/**
 * @fileoverview Worker Thread de inspección v5.3: descompresión, decodificación, multipart y DPI completos
 * fuera del Event Loop principal. Un error nunca devuelve "limpio": devuelve `uninspectable`.
 */

import { parentPort } from 'node:worker_threads';
import { inspectRequest } from './requestInspector.js';

if (parentPort) {
  parentPort.on('message', (msg) => {
    const { id, payload } = msg || {};
    let result;
    try {
      result = inspectRequest(payload || {});
    } catch (err) {
      result = { malicious: false, vectors: [], riskScore: 0, uninspectable: 'inspector_error', error: String(err?.message || err).slice(0, 200) };
    }
    parentPort.postMessage({ id, result });
  });
}
