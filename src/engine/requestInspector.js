/**
 * @fileoverview Inspector de Peticiones v5.3 — convierte el cuerpo crudo en texto inspeccionable SIN puntos ciegos.
 *
 * Principio: todo lo que el backend va a interpretar se inspecciona, o se declara explícitamente
 * "no inspeccionable" con un motivo. Nunca se reenvía en silencio algo que no se miró.
 *
 *  - Content-Encoding gzip / x-gzip / deflate (zlib y raw) / br, también encadenados ("gzip, gzip"),
 *    descomprimidos con tope de salida (una gzip-bomb se corta al llegar al tope: costo acotado).
 *  - Charset: solo los que el detector entiende (UTF-8/ASCII/Latin-1/Windows-1252/UTF-16). Otros (IBM037/EBCDIC,
 *    UTF-7, UTF-32...) son una técnica conocida de evasión de WAF -> no inspeccionable.
 *  - multipart/form-data a nivel de bytes: campos de formulario SIEMPRE se inspeccionan (aunque traigan bytes
 *    nulos); archivos binarios reales no se pasan al detector de texto, pero se buscan marcas de webshell.
 *  - Cuerpos de texto mayores al tope (1 MB por defecto) -> no inspeccionable ('too_large').
 *
 * Se ejecuta dentro del Worker (dpiWorker.js), nunca en el hilo principal.
 */

import zlib from 'node:zlib';
import { inspectPayloadDPI } from './sentinelWaf.js';
import { decodeBufferToInspectableText } from './structuralDetector.js';

export const DEFAULT_MAX_INSPECT_BODY_BYTES = 1024 * 1024;

const SUPPORTED_CHARSETS = new Set([
  'utf-8', 'utf8', 'us-ascii', 'ascii', 'iso-8859-1', 'latin1', 'iso8859-1', 'windows-1252', 'cp1252',
  'utf-16', 'utf-16le', 'utf-16be', 'utf16', 'utf16le', 'utf16be'
]);

const TEXTUAL_CT_REGEX = /(?:^|\/|\+)(?:json|x-www-form-urlencoded|xml|text|javascript|graphql|csv|yaml|x-yaml|html|plain)(?:$|;|\s)/i;

const WEBSHELL_MARKERS = ['<?php', '__HALT_COMPILER', '<%@ page', '<%= Runtime', 'eval(base64_decode', 'system($_'];

function toBuffer(raw) {
  if (!raw) return Buffer.alloc(0);
  if (Buffer.isBuffer(raw)) return raw;
  if (raw instanceof Uint8Array) return Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
  if (raw instanceof ArrayBuffer) return Buffer.from(raw);
  return Buffer.from(String(raw), 'utf8');
}

export function parseContentEncodings(contentEncoding) {
  return String(contentEncoding || '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter((e) => e && e !== 'identity');
}

function decompressLayer(buf, encoding, maxOut) {
  const opts = { maxOutputLength: maxOut };
  if (encoding === 'gzip' || encoding === 'x-gzip') return zlib.gunzipSync(buf, opts);
  if (encoding === 'br') return zlib.brotliDecompressSync(buf, opts);
  if (encoding === 'deflate') {
    try {
      return zlib.inflateSync(buf, opts);
    } catch (err) {
      if (err?.code === 'ERR_BUFFER_TOO_LARGE' || err instanceof RangeError) throw err;
      return zlib.inflateRawSync(buf, opts); // deflate "raw" que algunos clientes envían
    }
  }
  const e = new Error(`unsupported_encoding:${encoding}`);
  e.code = 'UNSUPPORTED_ENCODING';
  throw e;
}

/**
 * Deshace todas las capas de Content-Encoding (en orden inverso, como manda RFC 9110).
 * @returns {{ buf: Buffer|null, reason: string|null }}
 */
export function decodeContentEncoding(rawBuf, contentEncoding, maxOut) {
  const layers = parseContentEncodings(contentEncoding);
  if (layers.length === 0) return { buf: rawBuf, reason: null };
  if (layers.length > 3) return { buf: null, reason: 'encoding_too_many_layers' };
  let buf = rawBuf;
  for (let i = layers.length - 1; i >= 0; i -= 1) {
    try {
      buf = decompressLayer(buf, layers[i], maxOut);
    } catch (err) {
      if (err?.code === 'UNSUPPORTED_ENCODING') return { buf: null, reason: 'encoding_unsupported' };
      if (err?.code === 'ERR_BUFFER_TOO_LARGE' || err instanceof RangeError || /maxOutputLength|too large/i.test(String(err?.message))) {
        return { buf: null, reason: 'too_large' };
      }
      return { buf: null, reason: 'encoding_malformed' };
    }
  }
  return { buf, reason: null };
}

export function extractCharset(contentType) {
  const m = String(contentType || '').match(/charset\s*=\s*"?([^";\s]+)"?/i);
  return m ? m[1].toLowerCase() : null;
}

/** Binario real: firma conocida, o bytes de control/NUL en los primeros 2 KB (UTF-8 con acentos NO cuenta). */
export function looksBinary(buf) {
  if (!buf || buf.length === 0) return false;
  const b = buf;
  if (b.length >= 4) {
    if (
      (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) || // PNG
      (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) || // JPEG
      (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) || // GIF
      (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46) || // RIFF (WEBP/WAV/AVI)
      (b[0] === 0x00 && b[1] === 0x00 && b[2] === 0x00 && (b[3] === 0x18 || b[3] === 0x1c || b[3] === 0x20)) || // MP4/HEIC
      (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) || // ZIP/DOCX/XLSX
      (b[0] === 0x1f && b[1] === 0x8b) || // GZIP
      (b[0] === 0x77 && b[1] === 0x4f && b[2] === 0x46) // WOFF
    ) {
      return true;
    }
  }
  const probe = Math.min(b.length, 2048);
  let control = 0;
  for (let i = 0; i < probe; i += 1) {
    const c = b[i];
    if (c === 0 || (c < 0x09) || (c > 0x0d && c < 0x20)) control += 1;
  }
  return control > probe * 0.05;
}

function scanWebshellMarkers(buf) {
  for (const marker of WEBSHELL_MARKERS) {
    if (buf.indexOf(marker, 0, 'latin1') !== -1) return true;
  }
  return false;
}

function decodeTextBuffer(buf, contentType) {
  // UTF-16 por charset/BOM/heurística se maneja en decodeBufferToInspectableText; aquí nunca se descarta por
  // "magic bytes": si el Content-Type o el contexto dicen texto, se inspecciona (los NUL se eliminan al normalizar).
  const decoded = decodeBufferToInspectableText(buf, contentType, buf.length + 1);
  if (decoded) return decoded;
  return buf.toString('latin1');
}

/**
 * multipart/form-data a nivel de bytes, lineal (Buffer.indexOf).
 * Reconstruye un multipart textual equivalente donde los archivos binarios quedan vacíos.
 */
function rebuildMultipartForInspection(buf, contentType) {
  const bMatch = String(contentType || '').match(/boundary=(?:"([^"]+)"|([^\s;]+))/i);
  const boundary = bMatch ? bMatch[1] || bMatch[2] : null;
  if (!boundary) return { text: null, reason: 'multipart_no_boundary', webshell: false };

  const delim = Buffer.from(`--${boundary}`, 'latin1');
  const out = [];
  let webshell = false;
  let pos = buf.indexOf(delim);
  if (pos === -1) return { text: null, reason: 'multipart_malformed', webshell: false };

  while (pos !== -1) {
    const partStart = pos + delim.length;
    // "--" tras el delimitador = fin
    if (buf[partStart] === 0x2d && buf[partStart + 1] === 0x2d) break;
    const next = buf.indexOf(delim, partStart);
    const partEnd = next === -1 ? buf.length : next;
    const part = buf.subarray(partStart, partEnd);

    let headerEnd = part.indexOf('\r\n\r\n', 0, 'latin1');
    let sepLen = 4;
    if (headerEnd === -1) {
      headerEnd = part.indexOf('\n\n', 0, 'latin1');
      sepLen = 2;
    }
    if (headerEnd !== -1) {
      const headerText = part.subarray(0, headerEnd).toString('utf8');
      let content = part.subarray(headerEnd + sepLen);
      // quita el CRLF final que precede al siguiente delimitador
      if (content.length >= 2 && content[content.length - 2] === 0x0d && content[content.length - 1] === 0x0a) {
        content = content.subarray(0, content.length - 2);
      } else if (content.length >= 1 && content[content.length - 1] === 0x0a) {
        content = content.subarray(0, content.length - 1);
      }

      const isFilePart = /filename\*?\s*=/i.test(headerText);
      const partCtMatch = headerText.match(/content-type\s*:\s*([^\r\n]+)/i);
      const partCt = partCtMatch ? partCtMatch[1].trim() : '';

      let contentText = '';
      if (isFilePart && looksBinary(content)) {
        if (scanWebshellMarkers(content)) webshell = true;
      } else {
        contentText = decodeTextBuffer(content, partCt);
      }
      out.push(`--${boundary}\r\n${headerText}\r\n\r\n${contentText}\r\n`);
    }
    if (next === -1) break;
    pos = next;
  }
  out.push(`--${boundary}--\r\n`);
  return { text: out.join(''), reason: null, webshell };
}

/**
 * Convierte el cuerpo crudo en texto inspeccionable.
 * @returns {{ bodyText: string, bodyStatus: 'empty'|'inspected'|'binary', uninspectable: string|null, forcedVectors: string[] }}
 */
export function buildInspectableBody({
  rawBody,
  contentType = '',
  contentEncoding = '',
  maxInspectBytes = DEFAULT_MAX_INSPECT_BODY_BYTES
}) {
  const raw = toBuffer(rawBody);
  if (raw.length === 0) return { bodyText: '', bodyStatus: 'empty', uninspectable: null, forcedVectors: [] };

  const ct = String(contentType || '');
  const isMultipart = /multipart\/form-data/i.test(ct);
  // Para multipart el tope aplica al TEXTO extraído (los archivos binarios no cuentan); el crudo puede ser mayor.
  const decodeCap = isMultipart ? Math.max(maxInspectBytes, 64 * 1024 * 1024) : maxInspectBytes + 1;

  const { buf, reason } = decodeContentEncoding(raw, contentEncoding, decodeCap);
  if (!buf) return { bodyText: '', bodyStatus: 'inspected', uninspectable: reason, forcedVectors: [] };

  const charset = extractCharset(ct);
  if (charset && !SUPPORTED_CHARSETS.has(charset)) {
    return { bodyText: '', bodyStatus: 'inspected', uninspectable: 'charset_unsupported', forcedVectors: [] };
  }

  if (isMultipart) {
    const mp = rebuildMultipartForInspection(buf, ct);
    if (mp.text === null) {
      // Multipart inválido: el backend probablemente lo rechace, pero se inspecciona como texto plano igual
      if (buf.length > maxInspectBytes) return { bodyText: '', bodyStatus: 'inspected', uninspectable: 'too_large', forcedVectors: [] };
      return { bodyText: decodeTextBuffer(buf, ct), bodyStatus: 'inspected', uninspectable: null, forcedVectors: [] };
    }
    if (Buffer.byteLength(mp.text) > maxInspectBytes) {
      return { bodyText: '', bodyStatus: 'inspected', uninspectable: 'too_large', forcedVectors: mp.webshell ? ['MALICIOUS_FILE_UPLOAD'] : [] };
    }
    return { bodyText: mp.text, bodyStatus: 'inspected', uninspectable: null, forcedVectors: mp.webshell ? ['MALICIOUS_FILE_UPLOAD'] : [] };
  }

  if (buf.length > maxInspectBytes) {
    return { bodyText: '', bodyStatus: 'inspected', uninspectable: 'too_large', forcedVectors: [] };
  }

  const declaredTextual = !ct || TEXTUAL_CT_REGEX.test(ct);
  if (!declaredTextual && looksBinary(buf)) {
    // Subida binaria real (PUT de una imagen, etc.): no hay texto que el backend vaya a interpretar como datos
    return {
      bodyText: '',
      bodyStatus: 'binary',
      uninspectable: null,
      forcedVectors: scanWebshellMarkers(buf) ? ['MALICIOUS_FILE_UPLOAD'] : []
    };
  }

  return { bodyText: decodeTextBuffer(buf, ct), bodyStatus: 'inspected', uninspectable: null, forcedVectors: [] };
}

/**
 * Inspección completa de una petición (URL + cabeceras + cuerpo). Usada por el Worker y como fallback síncrono.
 */
export function inspectRequest(payload = {}) {
  const {
    rawUrl = '/',
    headers = {},
    rawBody = null,
    bodyText: providedBodyText = '',
    contentType = '',
    contentEncoding = '',
    wafRules,
    customKeywords = [],
    maxInspectBytes = DEFAULT_MAX_INSPECT_BODY_BYTES
  } = payload;

  let bodyText = providedBodyText || '';
  let bodyStatus = bodyText ? 'inspected' : 'empty';
  let uninspectable = null;
  let forcedVectors = [];

  if (rawBody && (rawBody.length || rawBody.byteLength)) {
    const built = buildInspectableBody({ rawBody, contentType, contentEncoding, maxInspectBytes });
    bodyText = built.bodyText;
    bodyStatus = built.bodyStatus;
    uninspectable = built.uninspectable;
    forcedVectors = built.forcedVectors;
  }

  const dpi = inspectPayloadDPI({ rawUrl, headers, bodyText, contentType, wafRules, customKeywords });
  const vectors = [...dpi.vectors];
  let riskScore = dpi.riskScore;
  for (const v of forcedVectors) {
    if (!vectors.includes(v)) vectors.push(v);
    riskScore = Math.max(riskScore, 97);
  }
  return {
    malicious: vectors.length > 0,
    vectors,
    riskScore,
    bodyStatus,
    uninspectable
  };
}
