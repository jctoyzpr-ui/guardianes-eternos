/**
 * @fileoverview Worker Thread dedicado para inspección estructural fuera del Event Loop principal (Fase 0 #2).
 * Evita que cualquier carga patológica o repetitiva congele el servidor HTTP para otros visitantes.
 */

import { parentPort } from 'node:worker_threads';
import { inspectPayloadDPI } from './sentinelWaf.js';

if (parentPort) {
  parentPort.on('message', (msg) => {
    const { id, payload } = msg || {};
    try {
      const result = inspectPayloadDPI(payload || {});
      parentPort.postMessage({ id, result });
    } catch {
      parentPort.postMessage({ id, result: { malicious: false, vectors: [], riskScore: 0 } });
    }
  });
}
