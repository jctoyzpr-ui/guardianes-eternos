/**
 * @fileoverview Ejecutor Asíncrono con Worker Thread + Tope Estricto de Tiempo (Fase 0 #2).
 * Corre `inspectPayloadDPI` fuera del hilo principal de Node.js. Si una petición excede `timeoutMs`,
 * termina y reinicia el worker (fail-open en modo detección) para garantizar que el event loop jamás se congele.
 */

import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { inspectPayloadDPI } from './sentinelWaf.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WORKER_FILE = path.resolve(__dirname, 'dpiWorker.js');

export class DpiWorkerRunner {
  /**
   * @param {object} [options]
   * @param {number} [options.timeoutMs=50] Tope máximo de CPU/tiempo por petición antes de abortar
   * @param {boolean} [options.useWorker=true]
   */
  constructor({ timeoutMs = 50, useWorker = true } = {}) {
    this.timeoutMs = timeoutMs;
    this.useWorker = useWorker;
    this.worker = null;
    this.nextId = 1;
    this.pending = new Map();
    this.closed = false;
    this.timeoutsCount = 0;
  }

  _ensureWorker() {
    if (this.closed || !this.useWorker) return null;
    if (this.worker) return this.worker;

    const w = new Worker(WORKER_FILE);
    w.unref();
    w.on('message', (msg) => {
      const entry = this.pending.get(msg?.id);
      if (!entry) return;
      this.pending.delete(msg.id);
      clearTimeout(entry.timer);
      entry.resolve(msg.result || { malicious: false, vectors: [], riskScore: 0 });
    });
    w.on('error', () => {
      this._resetWorker('worker_error');
    });
    w.on('exit', () => {
      if (this.worker === w) {
        this.worker = null;
        this._flushPendingFailOpen('worker_exit');
      }
    });
    this.worker = w;
    return w;
  }

  _flushPendingFailOpen(reason) {
    for (const [id, entry] of this.pending.entries()) {
      clearTimeout(entry.timer);
      entry.resolve({ malicious: false, vectors: [], riskScore: 0, timedOut: reason === 'timeout' });
      this.pending.delete(id);
    }
  }

  _resetWorker(reason) {
    const old = this.worker;
    this.worker = null;
    if (old) {
      old.terminate().catch(() => {});
    }
    this._flushPendingFailOpen(reason);
  }

  /**
   * Ejecuta inspección DPI fuera del hilo principal con tope de tiempo estricto.
   */
  inspectAsync(payload) {
    if (this.closed || !this.useWorker) {
      return Promise.resolve(inspectPayloadDPI(payload));
    }

    const w = this._ensureWorker();
    if (!w) {
      return Promise.resolve(inspectPayloadDPI(payload));
    }

    const id = this.nextId;
    this.nextId += 1;

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (!this.pending.has(id)) return;
        this.timeoutsCount += 1;
        this._resetWorker('timeout');
      }, this.timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();

      this.pending.set(id, { resolve, timer });
      try {
        w.postMessage({ id, payload });
      } catch {
        clearTimeout(timer);
        this.pending.delete(id);
        resolve({ malicious: false, vectors: [], riskScore: 0 });
      }
    });
  }

  async close() {
    this.closed = true;
    const old = this.worker;
    this.worker = null;
    this._flushPendingFailOpen('closed');
    if (old) {
      await old.terminate().catch(() => {});
    }
  }
}
