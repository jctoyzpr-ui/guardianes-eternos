/**
 * @fileoverview Pool de Worker Threads para inspección DPI v5.3 (sin fail-open silencioso).
 *
 * Cambios respecto a v5.2 (que permitía evadir el WAF):
 *  - El tope de tiempo cuenta desde que un worker EMPIEZA a analizar la petición, no desde que entra a la cola.
 *    (v5.2: 8 peticiones pesadas en paralelo hacían que la cola superara 50 ms y TODO saliera "limpio").
 *  - Un timeout termina SOLO el worker de esa petición; las demás peticiones no se ven afectadas.
 *  - Ningún error devuelve "limpio": timeout / caída / sobrecarga devuelven `uninspectable: '<motivo>'` y la
 *    política (bloquear o alertar) la decide el Centinela según el modo configurado.
 *  - Pool de N workers (por defecto min(4, CPUs-1)), cola con tope global, tope de peticiones simultáneas por
 *    cliente (una sola IP no puede acaparar el pool) y espera máxima en cola.
 */

import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import { inspectRequest } from './requestInspector.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WORKER_FILE = path.resolve(__dirname, 'dpiWorker.js');

const defaultPoolSize = () => {
  const cpus = typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length;
  return Math.max(1, Math.min(4, cpus - 1));
};

export class DpiWorkerRunner {
  /**
   * @param {object} [options]
   * @param {number} [options.timeoutMs=1000]      Tope de CÓMPUTO por petición (desde que el worker la toma)
   * @param {number} [options.poolSize]          Número de workers
   * @param {number} [options.maxQueue=1024]      Peticiones en espera antes de declarar sobrecarga
   * @param {number} [options.maxPerClient]      Peticiones simultáneas (en cola + en análisis) por cliente
   * @param {number} [options.queueTimeoutMs=3000] Espera máxima en cola
   * @param {boolean} [options.useWorker=true]
   */
  constructor({
    timeoutMs = 1000,
    poolSize = defaultPoolSize(),
    maxQueue = 1024,
    maxPerClient = null,
    queueTimeoutMs = 3000,
    useWorker = true
  } = {}) {
    this.timeoutMs = timeoutMs;
    this.poolSize = Math.max(1, poolSize);
    this.maxQueue = maxQueue;
    // Peticiones pendientes por cliente (cola + análisis). Generoso: un navegador abre ~6 conexiones y una oficina
    // con CGNAT comparte IP. Lo que protege el pool es `maxHeavyRunningPerClient`.
    this.maxPerClient = maxPerClient ?? 256;
    // Cuerpos pesados (> 16 KB) de un mismo cliente analizándose a la vez: como máximo la mitad del pool.
    this.maxHeavyRunningPerClient = Math.max(1, Math.floor(this.poolSize / 2));
    this.heavyRunning = new Map();
    this.queueTimeoutMs = queueTimeoutMs;
    this.useWorker = useWorker;
    this.closed = false;
    this.nextId = 1;
    this.slots = [];
    this.queue = [];
    this.perClient = new Map();
    this.stats = { timeouts: 0, overloaded: 0, crashes: 0, inspected: 0 };
    if (this.useWorker) {
      for (let i = 0; i < this.poolSize; i += 1) this.slots.push(this._spawnSlot());
    }
  }

  /** Compatibilidad con v5.2 (tests/PoCs leían timeoutsCount). */
  get timeoutsCount() {
    return this.stats.timeouts;
  }

  _spawnSlot() {
    const slot = { worker: null, ready: false, job: null, timer: null };
    const w = new Worker(WORKER_FILE);
    w.unref();
    slot.worker = w;
    w.on('online', () => {
      slot.ready = true;
      this._pump();
    });
    w.on('message', (msg) => {
      const job = slot.job;
      if (!job || msg?.id !== job.id) return;
      clearTimeout(slot.timer);
      slot.timer = null;
      slot.job = null;
      this.stats.inspected += 1;
      this._finish(job, msg.result || { malicious: false, vectors: [], riskScore: 0, uninspectable: 'worker_empty_result' });
      this._pump();
    });
    w.on('error', () => {
      this._replaceSlot(slot, 'worker_crash');
    });
    w.on('exit', () => {
      if (slot.worker === w && !this.closed) this._replaceSlot(slot, 'worker_crash');
    });
    return slot;
  }

  _replaceSlot(slot, reason) {
    const job = slot.job;
    slot.job = null;
    clearTimeout(slot.timer);
    slot.timer = null;
    const old = slot.worker;
    slot.worker = null;
    slot.ready = false;
    if (old) old.removeAllListeners('exit');
    if (old) old.terminate().catch(() => {});
    if (job) {
      if (reason === 'timeout') this.stats.timeouts += 1;
      else this.stats.crashes += 1;
      this._finish(job, { malicious: false, vectors: [], riskScore: 0, uninspectable: reason });
    }
    if (this.closed) return;
    const idx = this.slots.indexOf(slot);
    const fresh = this._spawnSlot();
    if (idx !== -1) this.slots[idx] = fresh;
  }

  _finish(job, result) {
    if (job.done) return;
    job.done = true;
    clearTimeout(job.queueTimer);
    if (job.heavy && job.running) {
      const h = (this.heavyRunning.get(job.clientKey) || 1) - 1;
      if (h <= 0) this.heavyRunning.delete(job.clientKey);
      else this.heavyRunning.set(job.clientKey, h);
    }
    const count = (this.perClient.get(job.clientKey) || 1) - 1;
    if (count <= 0) this.perClient.delete(job.clientKey);
    else this.perClient.set(job.clientKey, count);
    job.resolve(result);
  }

  _takeNextJob() {
    // Primer trabajo de la cola cuyo cliente no tenga ya su cupo de cuerpos pesados en análisis (planificación justa)
    for (let i = 0; i < this.queue.length; i += 1) {
      const job = this.queue[i];
      if (job.done) {
        this.queue.splice(i, 1);
        i -= 1;
        continue;
      }
      if (job.heavy && (this.heavyRunning.get(job.clientKey) || 0) >= this.maxHeavyRunningPerClient) continue;
      this.queue.splice(i, 1);
      return job;
    }
    return null;
  }

  _pump() {
    if (this.closed) return;
    for (const slot of this.slots) {
      if (this.queue.length === 0) return;
      if (!slot.ready || slot.job || !slot.worker) continue;
      const job = this._takeNextJob();
      if (!job) return;
      if (job.heavy) this.heavyRunning.set(job.clientKey, (this.heavyRunning.get(job.clientKey) || 0) + 1);
      job.running = true;
      slot.job = job;
      clearTimeout(job.queueTimer);
      // El reloj empieza AQUÍ: cuando el worker toma la petición.
      slot.timer = setTimeout(() => {
        if (slot.job === job) this._replaceSlot(slot, 'timeout');
      }, this.timeoutMs);
      if (typeof slot.timer.unref === 'function') slot.timer.unref();
      try {
        slot.worker.postMessage({ id: job.id, payload: job.payload });
      } catch {
        slot.job = null;
        clearTimeout(slot.timer);
        this._finish(job, { malicious: false, vectors: [], riskScore: 0, uninspectable: 'worker_post_failed' });
      }
    }
  }

  /**
   * Inspecciona una petición fuera del hilo principal.
   * @param {object} payload  ver requestInspector.inspectRequest
   * @param {{ clientKey?: string }} [opts]
   * @returns {Promise<{malicious:boolean, vectors:string[], riskScore:number, uninspectable?:string|null, bodyStatus?:string}>}
   */
  inspectAsync(payload, { clientKey = 'anon' } = {}) {
    if (!this.useWorker || this.closed) {
      return Promise.resolve(inspectRequest(payload));
    }

    const inFlight = this.perClient.get(clientKey) || 0;
    if (inFlight >= this.maxPerClient || this.queue.length >= this.maxQueue) {
      this.stats.overloaded += 1;
      return Promise.resolve({ malicious: false, vectors: [], riskScore: 0, uninspectable: 'overloaded' });
    }
    this.perClient.set(clientKey, inFlight + 1);

    return new Promise((resolve) => {
      const bodyLen = payload?.rawBody ? payload.rawBody.length || payload.rawBody.byteLength || 0 : String(payload?.bodyText || '').length;
      const job = { id: this.nextId++, payload, clientKey, resolve, done: false, running: false, heavy: bodyLen > 16 * 1024, queueTimer: null };
      job.queueTimer = setTimeout(() => {
        if (job.done) return;
        this.stats.overloaded += 1;
        this._finish(job, { malicious: false, vectors: [], riskScore: 0, uninspectable: 'overloaded' });
      }, this.queueTimeoutMs);
      if (typeof job.queueTimer.unref === 'function') job.queueTimer.unref();
      this.queue.push(job);
      this._pump();
    });
  }

  async close() {
    this.closed = true;
    for (const job of this.queue) this._finish(job, { malicious: false, vectors: [], riskScore: 0, uninspectable: 'closed' });
    this.queue = [];
    await Promise.all(
      this.slots.map(async (slot) => {
        clearTimeout(slot.timer);
        if (slot.job) this._finish(slot.job, { malicious: false, vectors: [], riskScore: 0, uninspectable: 'closed' });
        slot.job = null;
        const w = slot.worker;
        slot.worker = null;
        if (w) {
          w.removeAllListeners('exit');
          await w.terminate().catch(() => {});
        }
      })
    );
  }
}
