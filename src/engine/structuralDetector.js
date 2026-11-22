/**
 * @fileoverview Analizador Estructural Lineal O(n) v5.2 (0 dependencias npm).
 * Diseñado específicamente para:
 *   1. Costo estrictamente lineal O(n) sin regex con backtracking cuadrático (inmune a DoS de CPU).
 *   2. Generalización estructural real por familia:
 *      - SQLi: tokenizador léxico por campo + segmentos REST + multipart + tautologías con/sin '=' (LIKE, IS NOT NULL, OR TRUE, IN, BETWEEN).
 *      - XSS: scanner lineal de etiquetas (cerradas Y sin cerrar), cualquier atributo on*=, esquemas URI y breakouts en contexto JS.
 *      - SSRF: esquemas + // + http:\\ + DNS-rebinding en parámetros/URLs (nunca en Referer/Origin ni prosa de soporte).
 *      - RCE: des-ofuscación shell genérica (comillas vacías, backslashes, $IFS, brace expansion), sustitución $(...)/backticks y comandos POSIX.
 *      - SSTI: motores con {{ }}, {% %}, <% %>, #{ }, ${ }, <#assign>, #set() (distinguiendo variables simples de email).
 *      - NoSQL / XXE / Prototype Pollution: walker JSON iterativo profundo (hasta 64 niveles / 10k nodos), \u0024, y DOCTYPE XHTML legítimo permitido.
 *   3. Decodificación de body independiente del Content-Type declarado (magic bytes) y soporte UTF-16LE/BE.
 */

import net from 'node:net';

const MAX_FIELD_SCAN_CHARS = 65_536;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 10_000;

const SSRF_BLOCKLIST = new net.BlockList();
SSRF_BLOCKLIST.addSubnet('0.0.0.0', 8, 'ipv4');
SSRF_BLOCKLIST.addSubnet('10.0.0.0', 8, 'ipv4');
SSRF_BLOCKLIST.addSubnet('100.64.0.0', 10, 'ipv4');
SSRF_BLOCKLIST.addSubnet('127.0.0.0', 8, 'ipv4');
SSRF_BLOCKLIST.addSubnet('169.254.0.0', 16, 'ipv4');
SSRF_BLOCKLIST.addSubnet('172.16.0.0', 12, 'ipv4');
SSRF_BLOCKLIST.addSubnet('192.168.0.0', 16, 'ipv4');
SSRF_BLOCKLIST.addAddress('::1', 'ipv6');
SSRF_BLOCKLIST.addAddress('::', 'ipv6');
SSRF_BLOCKLIST.addSubnet('fc00::', 7, 'ipv6');
SSRF_BLOCKLIST.addSubnet('fe80::', 10, 'ipv6');
SSRF_BLOCKLIST.addSubnet('fd00:ec2::', 32, 'ipv6');

const SSRF_BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data',
  '169.254.169.254',
  '100.100.100.200'
]);

const DNS_REBIND_SUFFIXES = [
  '.nip.io',
  '.sslip.io',
  '.xip.io',
  '.localtest.me',
  '.lvh.me',
  '.vcap.me'
];

const NOSQL_OPERATORS = new Set([
  '$ne', '$eq', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
  '$where', '$regex', '$exists', '$expr', '$function', '$accumulator',
  '$or', '$and', '$nor', '$not', '$elemMatch', '$lookup', '$options'
]);

/**
 * Fase 1 (#6): Detecta magic bytes de archivos binarios reales (no confía ciegamente en Content-Type)
 * y decodifica UTF-16LE / UTF-16BE / UTF-8 en texto inspeccionable acotado.
 */
export function decodeBufferToInspectableText(buf, contentType = '', maxBytes = MAX_FIELD_SCAN_CHARS) {
  if (!buf || buf.length === 0) return '';
  const slice = buf.length > maxBytes ? buf.subarray(0, maxBytes) : buf;
  const ct = String(contentType || '').toLowerCase();

  // 1. Detección UTF-16 explícita por charset o BOM
  if (
    ct.includes('utf-16le') ||
    ct.includes('utf16le') ||
    (slice.length >= 2 && slice[0] === 0xff && slice[1] === 0xfe)
  ) {
    const start = slice.length >= 2 && slice[0] === 0xff && slice[1] === 0xfe ? 2 : 0;
    return slice.subarray(start).toString('utf16le');
  }

  if (
    ct.includes('utf-16be') ||
    ct.includes('utf16be') ||
    (slice.length >= 2 && slice[0] === 0xfe && slice[1] === 0xff)
  ) {
    const start = slice.length >= 2 && slice[0] === 0xfe && slice[1] === 0xff ? 2 : 0;
    const swapped = Buffer.allocUnsafe(slice.length - start - ((slice.length - start) % 2));
    for (let i = 0; i < swapped.length; i += 2) {
      swapped[i] = slice[start + i + 1];
      swapped[i + 1] = slice[start + i];
    }
    return swapped.toString('utf16le');
  }

  // Heurística UTF-16 sin BOM cuando el cliente declara charset=utf-16 o intercala bytes 0x00 con ASCII
  if (slice.length >= 8) {
    const sampleLen = Math.min(slice.length, 64);
    let evenZeros = 0;
    let oddZeros = 0;
    let asciiCount = 0;
    for (let i = 0; i < sampleLen; i += 1) {
      const b = slice[i];
      if (b === 0) {
        if (i % 2 === 0) evenZeros += 1;
        else oddZeros += 1;
      } else if (b >= 0x20 && b <= 0x7e) {
        asciiCount += 1;
      }
    }
    const half = Math.floor(sampleLen / 2);
    if (oddZeros >= half * 0.7 && evenZeros === 0 && asciiCount >= half * 0.7) {
      return slice.toString('utf16le');
    }
    if (evenZeros >= half * 0.7 && oddZeros === 0 && asciiCount >= half * 0.7) {
      const swapped = Buffer.allocUnsafe(slice.length - (slice.length % 2));
      for (let i = 0; i < swapped.length; i += 2) {
        swapped[i] = slice[i + 1];
        swapped[i + 1] = slice[i];
      }
      return swapped.toString('utf16le');
    }
  }

  // 2. Comprobación de magic bytes binarios reales (ignora el Content-Type mentiroso si es texto)
  if (slice.length >= 4) {
    const b0 = slice[0];
    const b1 = slice[1];
    const b2 = slice[2];
    const b3 = slice[3];
    const isRealBinaryMagic =
      (b0 === 0x89 && b1 === 0x50 && b2 === 0x4e && b3 === 0x47) || // PNG
      (b0 === 0xff && b1 === 0xd8 && b2 === 0xff) || // JPEG
      (b0 === 0x47 && b1 === 0x49 && b2 === 0x46 && b3 === 0x38) || // GIF
      (b0 === 0x25 && b1 === 0x50 && b2 === 0x44 && b3 === 0x46) || // PDF
      (b0 === 0x50 && b1 === 0x4b && b2 === 0x03 && b3 === 0x04) || // ZIP/DOCX
      (b0 === 0x77 && b1 === 0x4f && b2 === 0x46 && (b3 === 0x46 || b3 === 0x32)); // WOFF/WOFF2

    if (isRealBinaryMagic) {
      // Verifica densidad de bytes no imprimibles en los primeros 128 bytes para evitar falsos "magic" con texto detrás
      const probeLen = Math.min(slice.length, 128);
      let nonPrintable = 0;
      for (let i = 4; i < probeLen; i += 1) {
        const b = slice[i];
        if (b < 0x09 || (b > 0x0d && b < 0x20) || b > 0x7e) nonPrintable += 1;
      }
      if (nonPrintable > (probeLen - 4) * 0.25) {
        return '';
      }
    }
  }

  return slice.toString('utf8');
}

/**
 * Elimina comentarios SQL inline /* ... * / y /*!50000 ... * / en tiempo estrictamente lineal O(n).
 */
export function stripSqlCommentsLinear(input, replacement = '') {
  const s = String(input || '');
  if (!s.includes('/*')) return s;
  let out = '';
  let i = 0;
  const len = s.length;
  while (i < len) {
    const open = s.indexOf('/*', i);
    if (open === -1) {
      out += s.slice(i);
      break;
    }
    out += s.slice(i, open);
    // Comentario condicional MySQL /*!50000 SELECT */ -> extrae el interior
    if (s[open + 2] === '!') {
      let j = open + 3;
      while (j < len && s[j] >= '0' && s[j] <= '9') j += 1;
      const close = s.indexOf('*/', j);
      if (close === -1) {
        out += replacement + s.slice(j);
        break;
      }
      out += replacement + s.slice(j, close) + replacement;
      i = close + 2;
    } else {
      const close = s.indexOf('*/', open + 2);
      if (close === -1) {
        out += replacement;
        break;
      }
      out += replacement;
      i = close + 2;
    }
  }
  return out;
}

/**
 * Decodifica entidades HTML y escapes Unicode/Hex JS en O(n) acotado.
 */
export function decodeEntitiesAndEscapes(str) {
  if (!str || typeof str !== 'string') return '';
  let out = str.length > MAX_FIELD_SCAN_CHARS ? str.slice(0, MAX_FIELD_SCAN_CHARS) : str;

  if (out.includes('&')) {
    const named = { lt: '<', gt: '>', quot: '"', apos: "'", amp: '&', tab: '\t', newline: '\n', colon: ':' };
    out = out
      .replace(/&#x([0-9a-fA-F]{1,6});?/g, (_, hex) => {
        const c = parseInt(hex, 16);
        return Number.isFinite(c) && c > 0 && c <= 0x10ffff ? String.fromCodePoint(c) : '';
      })
      .replace(/&#([0-9]{1,7});?/g, (_, dec) => {
        const c = parseInt(dec, 10);
        return Number.isFinite(c) && c > 0 && c <= 0x10ffff ? String.fromCodePoint(c) : '';
      })
      .replace(/&([a-zA-Z]{2,10});/g, (m, name) => named[name.toLowerCase()] ?? m);
  }

  if (out.includes('\\u') || out.includes('\\x')) {
    out = out
      .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
      .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }

  return out;
}

/**
 * Normaliza entradas hasta 3 capas URL + entidades HTML + comentarios SQL en O(n) estricto.
 */
export function normalizePayloadMultiLayer(input) {
  if (!input || typeof input !== 'string') {
    return {
      decoded: '',
      noNulls: '',
      htmlDecoded: '',
      compactControl: '',
      sqlEmptyComments: '',
      sqlSpaceComments: ''
    };
  }

  let decoded = input.length > MAX_FIELD_SCAN_CHARS ? input.slice(0, MAX_FIELD_SCAN_CHARS) : input;
  for (let i = 0; i < 3; i += 1) {
    if (!decoded.includes('%') && !decoded.includes('+')) break;
    try {
      const next = decodeURIComponent(decoded.replace(/\+/g, ' '));
      if (next === decoded) break;
      decoded = next;
    } catch {
      const partial = decoded.replace(/%([0-9a-fA-F]{2})/g, (_, h) =>
        String.fromCharCode(parseInt(h, 16))
      );
      if (partial === decoded) break;
      decoded = partial;
    }
  }

  const noNulls = decoded.includes('\0') ? decoded.replace(/\0/g, '') : decoded;
  const htmlDecoded = decodeEntitiesAndEscapes(noNulls);
  const compactControl = htmlDecoded.replace(/[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]+/g, '');
  const sqlEmptyComments = stripSqlCommentsLinear(htmlDecoded, '');
  const sqlSpaceComments = stripSqlCommentsLinear(htmlDecoded, ' ');

  return { decoded, noNulls, htmlDecoded, compactControl, sqlEmptyComments, sqlSpaceComments };
}

/**
 * Parsea partes de un cuerpo `multipart/form-data` en O(n) para extraer nombres de campo, filenames y valores.
 */
function parseMultipartFields(bodyText, contentType = '') {
  const bMatch = String(contentType || '').match(/boundary=(?:"([^"]+)"|([^\s;]+))/i);
  const boundary = bMatch ? (bMatch[1] || bMatch[2]) : null;
  if (!boundary) return [];

  const delim = `--${boundary}`;
  const parts = bodyText.split(delim);
  const fields = [];

  for (let i = 1; i < parts.length && fields.length < 120; i += 1) {
    const part = parts[i];
    if (!part || part.startsWith('--')) continue;
    const sepIdx = part.indexOf('\r\n\r\n') !== -1 ? part.indexOf('\r\n\r\n') : part.indexOf('\n\n');
    if (sepIdx === -1) continue;
    const headerBlock = part.slice(0, sepIdx);
    const rawVal = part.slice(sepIdx + (part[sepIdx] === '\r' ? 4 : 2)).replace(/\r?\n$/, '');
    const nameMatch = headerBlock.match(/name="([^"]{1,80})"/i);
    const fileMatch = headerBlock.match(/filename="([^"]{1,160})"/i);
    const key = nameMatch ? nameMatch[1] : '';
    if (fileMatch) {
      fields.push({ key: `${key}.filename`, value: decodeEntitiesAndEscapes(fileMatch[1]), source: 'multipart' });
    }
    if (rawVal) {
      fields.push({ key, value: normalizePayloadMultiLayer(rawVal).htmlDecoded, source: 'multipart' });
    }
  }
  return fields;
}

/**
 * Extrae parámetros clave/valor de ruta REST, query, JSON (walker iterativo profundo hasta 64 niveles / 10k nodos),
 * multipart/form-data y urlencoded.
 */
export function extractStructuredInputs({ rawUrl = '/', bodyText = '', contentType = '' }) {
  const params = [];
  const pathSegments = [];
  const jsonKeys = [];
  const jsonKeyPaths = [];
  let rawPath = '/';
  let rawQuery = '';

  const qIdx = String(rawUrl).indexOf('?');
  if (qIdx !== -1) {
    rawPath = String(rawUrl).slice(0, qIdx);
    rawQuery = String(rawUrl).slice(qIdx + 1);
  } else {
    rawPath = String(rawUrl);
  }

  // Segmentos de ruta REST (ej. /api/users/1' OR 1-- -> inspeccionados individualmente)
  for (const seg of rawPath.split('/')) {
    if (!seg) continue;
    const normSeg = normalizePayloadMultiLayer(seg).htmlDecoded;
    pathSegments.push(normSeg);
    params.push({ key: '_path_segment', value: normSeg, source: 'path' });
  }

  if (rawQuery) {
    for (const pair of rawQuery.split(/&(?!(?:#x?[0-9a-fA-F]{1,6}|[a-zA-Z]{2,10});)/)) {
      if (!pair) continue;
      const eq = pair.indexOf('=');
      const k = eq === -1 ? pair : pair.slice(0, eq);
      const v = eq === -1 ? '' : pair.slice(eq + 1);
      params.push({
        key: normalizePayloadMultiLayer(k).htmlDecoded,
        value: normalizePayloadMultiLayer(v).htmlDecoded,
        source: 'query'
      });
    }
  }

  const trimmedBody = String(bodyText || '').trim();
  if (trimmedBody) {
    const ctLower = String(contentType || '').toLowerCase();
    if (ctLower.includes('multipart/form-data')) {
      const mpFields = parseMultipartFields(bodyText, contentType);
      for (const f of mpFields) params.push(f);
    } else if (trimmedBody.startsWith('{') || trimmedBody.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmedBody);
        // Walker JSON iterativo (sin recursión, hasta 64 niveles y 10,000 nodos)
        const stack = [{ node: parsed, keyStack: [], depth: 0 }];
        let visited = 0;
        while (stack.length > 0 && visited < MAX_JSON_NODES) {
          const { node, keyStack, depth } = stack.pop();
          visited += 1;
          if (depth > MAX_JSON_DEPTH || node === null || node === undefined) continue;

          if (typeof node === 'string') {
            params.push({
              key: keyStack[keyStack.length - 1] || '',
              value: decodeEntitiesAndEscapes(node),
              source: 'json'
            });
          } else if (Array.isArray(node)) {
            for (let i = node.length - 1; i >= 0; i -= 1) {
              stack.push({ node: node[i], keyStack, depth: depth + 1 });
            }
          } else if (typeof node === 'object') {
            const keys = Object.getOwnPropertyNames(node);
            for (let i = keys.length - 1; i >= 0; i -= 1) {
              const k = keys[i];
              const nextStack = keyStack.length < 4 ? [...keyStack, k] : [keyStack[keyStack.length - 1], k];
              jsonKeys.push(k);
              jsonKeyPaths.push(nextStack);
              stack.push({ node: node[k], keyStack: nextStack, depth: depth + 1 });
            }
          }
        }
      } catch {
        params.push({ key: '', value: normalizePayloadMultiLayer(trimmedBody).htmlDecoded, source: 'body' });
      }
    } else if (
      ctLower.includes('application/x-www-form-urlencoded') ||
      (/^[^=<>\s\r\n]{1,60}=/.test(trimmedBody) && !trimmedBody.startsWith('<'))
    ) {
      for (const pair of trimmedBody.split(/&(?!(?:#x?[0-9a-fA-F]{1,6}|[a-zA-Z]{2,10});)/)) {
        if (!pair) continue;
        const eq = pair.indexOf('=');
        if (eq === -1) {
          params.push({ key: '', value: normalizePayloadMultiLayer(pair).htmlDecoded, source: 'form' });
        } else {
          params.push({
            key: normalizePayloadMultiLayer(pair.slice(0, eq)).htmlDecoded,
            value: normalizePayloadMultiLayer(pair.slice(eq + 1)).htmlDecoded,
            source: 'form'
          });
        }
      }
    } else {
      params.push({ key: '', value: normalizePayloadMultiLayer(trimmedBody).htmlDecoded, source: 'body' });
    }
  }

  return { rawPath, rawQuery, pathSegments, params, jsonKeys, jsonKeyPaths };
}

// ============================================================================
// 1. TOKENIZADOR LÉXICO SQL O(n) — Tautologías con/sin '=', UNION, stacked, blind, ORDER BY
// ============================================================================
const SQL_KEYWORDS = new Set([
  'SELECT', 'UNION', 'ALL', 'DISTINCT', 'FROM', 'WHERE', 'INSERT', 'INTO', 'VALUES',
  'UPDATE', 'SET', 'DELETE', 'DROP', 'ALTER', 'TRUNCATE', 'TABLE', 'DATABASE',
  'ORDER', 'GROUP', 'BY', 'HAVING', 'LIMIT', 'OFFSET', 'WAITFOR', 'DELAY',
  'EXEC', 'EXECUTE', 'DECLARE', 'CAST', 'CONVERT', 'CONCAT', 'NULL', 'CASE', 'WHEN', 'THEN',
  'INFORMATION_SCHEMA', 'PG_SLEEP', 'SLEEP', 'BENCHMARK', 'EXTRACTVALUE', 'UPDATEXML',
  'ASCII', 'ORD', 'SUBSTR', 'SUBSTRING', 'MID', 'CHAR', 'HEX', 'UNHEX', 'LOAD_FILE', 'OUTFILE',
  'XP_CMDSHELL', 'VERSION', 'USER', 'SCHEMA', 'LIKE', 'RLIKE', 'REGEXP', 'IN', 'BETWEEN', 'IS', 'NOT',
  'TRUE', 'FALSE', 'EXISTS', 'CHR', 'CONCAT_WS', 'GROUP_CONCAT'
]);

const SQL_BOOL_OPS = new Set(['OR', 'AND', 'XOR']);

function tokenizeSql(text, maxTokens = 400) {
  const tokens = [];
  const s = String(text || '');
  let i = 0;
  const len = Math.min(s.length, MAX_FIELD_SCAN_CHARS);

  while (i < len && tokens.length < maxTokens) {
    const ch = s[i];
    if (ch <= ' ') {
      i += 1;
      continue;
    }
    if (ch === '-' && s[i + 1] === '-' && (i + 2 >= len || s[i + 2] <= ' ' || s[i + 2] === '-')) {
      tokens.push({ type: 'COMMENT', val: '--' });
      break;
    }
    if (ch === '#') {
      tokens.push({ type: 'COMMENT', val: '#' });
      break;
    }
    if (ch === '/' && s[i + 1] === '*') {
      const end = s.indexOf('*/', i + 2);
      if (end === -1) {
        tokens.push({ type: 'COMMENT', val: '/*' });
        break;
      }
      i = end + 2;
      continue;
    }
    if (ch === '|' && s[i + 1] === '|') {
      tokens.push({ type: 'BOOL', val: '||' });
      i += 2;
      continue;
    }
    if (ch === '&' && s[i + 1] === '&') {
      tokens.push({ type: 'BOOL', val: '&&' });
      i += 2;
      continue;
    }
    if (ch === ';' || ch === '(' || ch === ')' || ch === ',') {
      const map = { ';': 'SEMI', '(': 'LPAREN', ')': 'RPAREN', ',': 'COMMA' };
      tokens.push({ type: map[ch], val: ch });
      i += 1;
      continue;
    }
    if (ch === '=' || ch === '<' || ch === '>' || (ch === '!' && s[i + 1] === '=')) {
      let op = ch;
      if (s[i + 1] === '=' || (ch === '<' && s[i + 1] === '>')) {
        op += s[i + 1];
        i += 2;
      } else {
        i += 1;
      }
      tokens.push({ type: 'CMP', val: op });
      continue;
    }
    if (ch === "'" || ch === '"') {
      const quote = ch;
      if (
        quote === "'" &&
        i > 0 &&
        i + 1 < len &&
        /[a-zA-Z]/.test(s[i - 1]) &&
        /[a-zA-Z]/.test(s[i + 1]) &&
        !/\s(?:or|and)\s/i.test(s.slice(i + 1, i + 12))
      ) {
        i += 1;
        continue;
      }
      let j = i + 1;
      while (j < len && s[j] !== quote) {
        if (s[j] === '\\') j += 2;
        else j += 1;
      }
      if (j < len && s[j] === quote) {
        const inner = s.slice(i + 1, j);
        if (/^\s*(?:or|and|union|select|order|group|having|;|\|\||&&)/i.test(inner)) {
          tokens.push({ type: 'QUOTE', val: quote });
          i += 1;
        } else {
          tokens.push({ type: 'STR', val: inner });
          i = j + 1;
        }
      } else {
        tokens.push({ type: 'QUOTE', val: quote });
        i += 1;
      }
      continue;
    }
    if (ch >= '0' && ch <= '9') {
      let j = i;
      while (j < len && ((s[j] >= '0' && s[j] <= '9') || s[j] === '.')) j += 1;
      tokens.push({ type: 'NUM', val: s.slice(i, j) });
      i = j;
      continue;
    }
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_' || ch === '@' || ch === '$') {
      let j = i;
      while (
        j < len &&
        ((s[j] >= 'a' && s[j] <= 'z') ||
          (s[j] >= 'A' && s[j] <= 'Z') ||
          (s[j] >= '0' && s[j] <= '9') ||
          s[j] === '_' ||
          s[j] === '@' ||
          s[j] === '$')
      ) {
        j += 1;
      }
      const word = s.slice(i, j);
      const upper = word.toUpperCase();
      if (SQL_BOOL_OPS.has(upper)) {
        tokens.push({ type: 'BOOL', val: upper });
      } else if (SQL_KEYWORDS.has(upper)) {
        tokens.push({ type: 'KW', val: upper });
      } else {
        tokens.push({ type: 'IDENT', val: word });
      }
      i = j;
      continue;
    }
    tokens.push({ type: 'OTHER', val: ch });
    i += 1;
  }
  return tokens;
}

export function analyzeSqlStructure(rawText) {
  if (!rawText || typeof rawText !== 'string' || rawText.length < 4) return false;
  const norm = normalizePayloadMultiLayer(rawText);

  const slices = [];
  for (const text of [norm.sqlEmptyComments, norm.sqlSpaceComments]) {
    slices.push(text);
    // Si un único campo es largo (> 1500 chars), también tokeniza la cola final completa en O(1)
    if (text.length > 1500) {
      slices.push(text.slice(-1500));
    }
  }

  for (const text of slices) {
    const toks = tokenizeSql(text, 800);
    const n = toks.length;
    if (n < 2) continue;

    for (let i = 0; i < n; i += 1) {
      const t = toks[i];

      // 1. Tautologías booleanas CON o SIN '=':
      //    - Comparaciones: ' OR 1=1, 1 OR 2>1, ' OR 'a' LIKE 'a, ' OR 1 IN (1), 1 OR 1 BETWEEN 0 AND 2
      //    - Verdad directa: ' OR TRUE, ' OR NOT FALSE, ' OR 1--, ' || 1--, ' OR 1 IS NOT NULL
      if (t.type === 'BOOL' && i > 0 && i + 1 < n) {
        const prev = toks[i - 1];
        const hasSqlPivot =
          prev.type === 'QUOTE' ||
          prev.type === 'NUM' ||
          prev.type === 'RPAREN' ||
          prev.type === 'STR';

        if (hasSqlPivot) {
          let k = i + 1;
          while (k < n && toks[k].type === 'LPAREN') k += 1;
          const lhs = toks[k];
          const op = toks[k + 1];
          const rhs = toks[k + 2];

          // 1a. `OR TRUE` / `OR NOT FALSE` / `OR EXISTS(...)`
          if (lhs?.type === 'KW' && lhs.val === 'TRUE') return true;
          if (lhs?.type === 'KW' && lhs.val === 'NOT' && op?.type === 'KW' && op.val === 'FALSE') return true;
          if (lhs?.type === 'KW' && lhs.val === 'EXISTS' && op?.type === 'LPAREN') return true;

          // 1b. `QUOTE OR NUM` seguido de comentario, fin de cadena o `)` (ej. `' OR 1--`, `' OR 1`, `' || 1#`)
          if (
            prev.type === 'QUOTE' &&
            lhs?.type === 'NUM' &&
            (!op || op.type === 'COMMENT' || op.type === 'RPAREN' || op.type === 'SEMI')
          ) {
            return true;
          }

          // 1c. Comparación clásica (=, <, >, !=, <>) o LIKE / RLIKE / REGEXP / IN / BETWEEN / IS [NOT] NULL
          if (lhs && op) {
            const isSqlCmp =
              op.type === 'CMP' ||
              (op.type === 'KW' && ['LIKE', 'RLIKE', 'REGEXP', 'IN', 'BETWEEN', 'IS'].includes(op.val));
            if (isSqlCmp && rhs) {
              if (
                ['NUM', 'STR', 'IDENT', 'QUOTE'].includes(lhs.type) &&
                (['NUM', 'STR', 'IDENT', 'QUOTE', 'LPAREN'].includes(rhs.type) ||
                  (rhs.type === 'KW' && ['NULL', 'NOT', 'TRUE', 'FALSE'].includes(rhs.val)))
              ) {
                return true;
              }
            }
            if (lhs.type === 'STR' && op.type === 'CMP') return true;
          }

          // 1d. Función blind/error tras pivote booleano (`1 AND ascii(substr(...))`, `1 AND sleep(5)`)
          if (
            lhs?.type === 'KW' &&
            ['ASCII', 'ORD', 'SUBSTR', 'SUBSTRING', 'MID', 'EXTRACTVALUE', 'UPDATEXML', 'SLEEP', 'PG_SLEEP', 'BENCHMARK', 'CASE'].includes(lhs.val) &&
            (lhs.val === 'CASE' || toks[k + 1]?.type === 'LPAREN')
          ) {
            return true;
          }
        }
      }

      // 2. UNION [ALL|DISTINCT] [(] SELECT con contexto SQL real (excluye prosa inglesa normal)
      if (t.type === 'KW' && t.val === 'UNION') {
        let j = i + 1;
        if (toks[j]?.type === 'KW' && (toks[j].val === 'ALL' || toks[j].val === 'DISTINCT')) j += 1;
        let hadParen = false;
        while (toks[j]?.type === 'LPAREN') {
          hadParen = true;
          j += 1;
        }
        if (toks[j]?.type === 'KW' && toks[j].val === 'SELECT') {
          const prev = i > 0 ? toks[i - 1] : null;
          const hasLeftPivot = !prev || ['NUM', 'QUOTE', 'RPAREN', 'STR', 'SEMI'].includes(prev.type);
          const rest = toks.slice(j + 1);
          const hasSqlClauseAfter =
            hadParen ||
            rest.some(
              (rt) =>
                rt.type === 'COMMA' ||
                rt.type === 'COMMENT' ||
                rt.type === 'LPAREN' ||
                rt.type === 'NUM' ||
                (rt.type === 'KW' && ['FROM', 'NULL', 'INFORMATION_SCHEMA', 'VERSION', 'USER', 'CONCAT', 'CHAR'].includes(rt.val))
            );
          if (hasLeftPivot || hasSqlClauseAfter) return true;
        }
      }

      // 3. Stacked SQL queries tras ';'
      if (t.type === 'SEMI' && i + 1 < n) {
        const next = toks[i + 1];
        const next2 = toks[i + 2];
        if (next.type === 'KW') {
          if (next.val === 'SELECT' && next2) return true;
          if (next.val === 'DELETE' && next2?.type === 'KW' && next2.val === 'FROM') return true;
          if (['DROP', 'TRUNCATE', 'ALTER'].includes(next.val) && next2?.type === 'KW' && ['TABLE', 'DATABASE'].includes(next2.val)) return true;
          if (next.val === 'INSERT' && next2?.type === 'KW' && next2.val === 'INTO') return true;
          if (next.val === 'UPDATE' && toks.slice(i + 2, i + 8).some((x) => x.type === 'KW' && x.val === 'SET')) return true;
          if (next.val === 'WAITFOR' && next2?.type === 'KW' && next2.val === 'DELAY') return true;
          if (['EXEC', 'EXECUTE', 'DECLARE'].includes(next.val)) return true;
        }
      }

      // 4. Funciones tiempo / error / blind SQL con argumentos estrictamente SQL (no prosa "sleep (8 hours)")
      if (t.type === 'KW' && ['SLEEP', 'PG_SLEEP'].includes(t.val)) {
        if (toks[i + 1]?.type === 'LPAREN' && toks[i + 2]?.type === 'NUM' && toks[i + 3]?.type === 'RPAREN') {
          return true;
        }
      }
      if (t.type === 'KW' && t.val === 'BENCHMARK' && toks[i + 1]?.type === 'LPAREN' && toks[i + 2]?.type === 'NUM' && toks[i + 3]?.type === 'COMMA') {
        return true;
      }
      if (t.type === 'KW' && ['EXTRACTVALUE', 'UPDATEXML', 'XP_CMDSHELL', 'LOAD_FILE', 'INFORMATION_SCHEMA'].includes(t.val)) {
        if (t.val === 'INFORMATION_SCHEMA' || t.val === 'XP_CMDSHELL' || toks[i + 1]?.type === 'LPAREN') return true;
      }
      if (t.type === 'KW' && ['ASCII', 'ORD'].includes(t.val) && toks[i + 1]?.type === 'LPAREN') {
        if (toks[i + 2]?.type === 'KW' && ['SUBSTR', 'SUBSTRING', 'MID', 'SELECT'].includes(toks[i + 2].val)) return true;
      }
      if (t.type === 'KW' && t.val === 'WAITFOR' && toks[i + 1]?.type === 'KW' && toks[i + 1].val === 'DELAY') {
        return true;
      }

      // 5. ORDER BY / GROUP BY N-- con comentario SQL o pivote
      if (
        t.type === 'KW' &&
        (t.val === 'ORDER' || t.val === 'GROUP') &&
        toks[i + 1]?.type === 'KW' &&
        toks[i + 1].val === 'BY' &&
        toks[i + 2]?.type === 'NUM'
      ) {
        const hasComment = toks.slice(i + 3).some((x) => x.type === 'COMMENT');
        const hasPivot = i > 0 && ['QUOTE', 'NUM', 'RPAREN'].includes(toks[i - 1].type);
        if (hasComment || hasPivot) return true;
      }

      // 6. Cierre de comilla seguido inmediatamente de comentario SQL válido (no notas de texto con "--" sin comilla)
      if (t.type === 'QUOTE' && toks[i + 1]?.type === 'COMMENT') {
        return true;
      }
    }
  }

  return false;
}

// ============================================================================
// 2. SCANNER LINEAL O(n) HTML / XSS (Etiquetas cerradas Y SIN CERRAR + contexto JS)
// ============================================================================
const DANGEROUS_HTML_TAGS = new Set(['script', 'iframe', 'object', 'embed', 'applet', 'base', 'math']);

export function analyzeXssStructure(rawText, { isDirectUriParam = false } = {}) {
  if (!rawText || typeof rawText !== 'string') return false;
  const norm = normalizePayloadMultiLayer(rawText);

  for (const text of [norm.htmlDecoded, norm.compactControl]) {
    const len = text.length;

    // 1. Scanner estrictamente lineal O(n) de etiquetas HTML (cerradas con '>' O sin cerrar hasta EOF!)
    let pos = 0;
    while (pos < len) {
      const lt = text.indexOf('<', pos);
      if (lt === -1) break;

      let j = lt + 1;
      while (j < len && text[j] <= ' ') j += 1;
      if (j < len && text[j] === '/') {
        // Cierre explícito </script> breakout en contexto JS
        const restClose = text.slice(j + 1, j + 10).toLowerCase();
        if (restClose.startsWith('script')) return true;
        pos = lt + 1;
        continue;
      }

      // Lee nombre de etiqueta
      const nameStart = j;
      while (j < len && ((text[j] >= 'a' && text[j] <= 'z') || (text[j] >= 'A' && text[j] <= 'Z') || (text[j] >= '0' && text[j] <= '9') || text[j] === ':' || text[j] === '-')) {
        j += 1;
      }
      const tagName = text.slice(nameStart, j).toLowerCase();
      if (!tagName) {
        pos = lt + 1;
        continue;
      }

      const nextLt = text.indexOf('<', j);
      const gt = text.indexOf('>', j);
      // Soporta etiquetas SIN CERRAR (`<svg/onload=alert(1)` hasta EOF o hasta el siguiente `<`)
      const end = gt !== -1 && (nextLt === -1 || gt < nextLt)
        ? gt
        : nextLt !== -1
          ? nextLt
          : Math.min(len, j + 512);
      const attrs = text.slice(j, Math.min(end, j + 512));

      if (DANGEROUS_HTML_TAGS.has(tagName) && (gt !== -1 || attrs.length > 0 || j === len)) {
        // Permite prosa inocua como "<base" solo si no tiene formato de etiqueta; <script siempre es malicioso
        if (tagName === 'script' || tagName === 'iframe' || tagName === 'object' || tagName === 'embed' || /[\s/=>]/.test(text[j] || '>')) {
          return true;
        }
      }

      // Cualquier manejador de eventos `on[a-z]+=` dentro de la etiqueta (cerrada o sin cerrar)
      if (/(?:^|[\s/"'`])on[a-z]{2,26}\s*=/i.test(attrs)) return true;

      // Esquemas peligrosos en atributos URI
      if (/(?:href|src|action|formaction|xlink:href|data|poster)\s*=\s*["'`]?\s*(?:javascript|vbscript|data\s*:\s*(?:text\/html|image\/svg\+xml))/i.test(attrs)) {
        return true;
      }

      pos = Math.max(lt + 1, end);
    }

    // 2. Esquema URI peligroso en valor directo (excluye títulos de libros como "JavaScript: The Good Parts")
    const compact = text.trim().replace(/[\x00-\x1f\t]+/g, '');
    if (/^data\s*:\s*(?:text\/html|image\/svg\+xml)/i.test(compact)) return true;
    if (/^(?:javascript|vbscript)\s*:/i.test(compact)) {
      const after = compact.replace(/^(?:javascript|vbscript)\s*:/i, '').trim();
      const looksLikeCode = /[();={}[\]`]|\/\/|\/\*|\b(?:alert|prompt|confirm|eval|void|document|window|location|fetch|import)\b/i.test(after);
      if (looksLikeCode || (isDirectUriParam && !/^[A-Z][a-z]+(?:\s+[A-Za-z]+){1,6}$/.test(after))) {
        return true;
      }
    }

    // 3. Breakouts en contexto JavaScript (`'-alert(1)-'`, `";alert(1);//`, `';confirm(1);//`, `eval(atob(...))`)
    if (
      /['"`]\s*(?:;|-|\+|\*|\/|\))\s*(?:alert|prompt|confirm|eval|Function|fetch|import|setTimeout|setInterval)\s*\(/i.test(text) ||
      /\b(?:document\.cookie|document\.write\s*\(|eval\s*\(\s*atob\s*\(|String\.fromCharCode\s*\(|crypto-clipper|wallet_swap_skimmer)/i.test(text)
    ) {
      return true;
    }

    // 4. AngularJS / Client-side Template sandbox escape
    if (text.includes('{{') && /\{\{[^}]{0,120}\bconstructor\b[^}]{0,120}\}\}/i.test(text)) {
      return true;
    }
  }

  return false;
}

// ============================================================================
// 3. EXTRACTOR CANÓNICO SSRF O(n) — Solo en parámetros/campos URL (NUNCA Referer/Origin ni prosa de soporte)
// ============================================================================
export function canonicalizeObfuscatedIp(rawHost) {
  if (!rawHost || typeof rawHost !== 'string') return null;
  let host = rawHost.trim().toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (!host) return null;

  if (net.isIPv6(host)) {
    const v4MappedDec = host.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
    if (v4MappedDec && net.isIPv4(v4MappedDec[1])) return { ip: v4MappedDec[1], family: 'ipv4' };
    const v4MappedHex = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
    if (v4MappedHex) {
      const hi = parseInt(v4MappedHex[1], 16);
      const lo = parseInt(v4MappedHex[2], 16);
      return {
        ip: `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`,
        family: 'ipv4'
      };
    }
    return { ip: host, family: 'ipv6' };
  }

  if (net.isIPv4(host)) return { ip: host, family: 'ipv4' };

  const parts = host.split('.');
  if (parts.length >= 1 && parts.length <= 4) {
    const nums = [];
    for (const part of parts) {
      if (!part) return null;
      let n;
      if (/^0x[0-9a-f]+$/i.test(part)) n = parseInt(part.slice(2), 16);
      else if (/^0[0-7]+$/.test(part)) n = parseInt(part, 8);
      else if (/^\d+$/.test(part)) n = parseInt(part, 10);
      else return null;
      if (!Number.isFinite(n) || n < 0 || n > 0xffffffff) return null;
      nums.push(n);
    }
    let ipv4Int = 0;
    if (nums.length === 1) ipv4Int = nums[0];
    else if (nums.length === 2) {
      if (nums[0] > 255 || nums[1] > 0xffffff) return null;
      ipv4Int = ((nums[0] << 24) >>> 0) + nums[1];
    } else if (nums.length === 3) {
      if (nums[0] > 255 || nums[1] > 255 || nums[2] > 0xffff) return null;
      ipv4Int = ((nums[0] << 24) >>> 0) + (nums[1] << 16) + nums[2];
    } else {
      if (nums.some((x) => x > 255)) return null;
      ipv4Int = ((nums[0] << 24) >>> 0) + (nums[1] << 16) + (nums[2] << 8) + nums[3];
    }
    return {
      ip: [
        (ipv4Int >>> 24) & 255,
        (ipv4Int >>> 16) & 255,
        (ipv4Int >>> 8) & 255,
        ipv4Int & 255
      ].join('.'),
      family: 'ipv4'
    };
  }
  return null;
}

function isBlockedSsrfHost(rawAuthority) {
  if (!rawAuthority || typeof rawAuthority !== 'string') return false;
  let authority = rawAuthority.trim();
  const atIdx = authority.lastIndexOf('@');
  if (atIdx !== -1) authority = authority.slice(atIdx + 1);

  let host = authority;
  if (host.startsWith('[')) {
    const end = host.indexOf(']');
    if (end !== -1) host = host.slice(0, end + 1);
  } else {
    const colon = host.indexOf(':');
    if (colon !== -1) host = host.slice(0, colon);
  }
  const lower = host.toLowerCase().replace(/\.$/, '');
  if (!lower) return false;

  if (
    SSRF_BLOCKED_HOSTNAMES.has(lower) ||
    lower.endsWith('.internal') ||
    lower.endsWith('.local') ||
    lower.endsWith('.localhost')
  ) {
    return true;
  }

  if (DNS_REBIND_SUFFIXES.some((sfx) => lower.endsWith(sfx) || lower === sfx.slice(1))) {
    if (lower.endsWith('.localtest.me') || lower === 'localtest.me' || lower.endsWith('.lvh.me') || lower === 'lvh.me') {
      return true;
    }
    const ipv4Match = lower.match(/(?:^|[.-])(\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3})\./);
    if (ipv4Match) {
      const candidateIp = ipv4Match[1].replace(/-/g, '.');
      if (net.isIPv4(candidateIp) && SSRF_BLOCKLIST.check(candidateIp, 'ipv4')) return true;
    }
    const hexMatch = lower.match(/(?:^|\.)([0-9a-f]{8})\.(?:nip|sslip|xip)\.io$/);
    if (hexMatch) {
      const parsedHex = canonicalizeObfuscatedIp(`0x${hexMatch[1]}`);
      if (parsedHex && SSRF_BLOCKLIST.check(parsedHex.ip, parsedHex.family)) return true;
    }
  }

  const parsedIp = canonicalizeObfuscatedIp(lower);
  if (parsedIp && SSRF_BLOCKLIST.check(parsedIp.ip, parsedIp.family)) return true;

  try {
    const u = new URL(`http://${authority}/`);
    const uHost = u.hostname.toLowerCase();
    if (SSRF_BLOCKED_HOSTNAMES.has(uHost)) return true;
    const uIp = canonicalizeObfuscatedIp(uHost);
    if (uIp && SSRF_BLOCKLIST.check(uIp.ip, uIp.family)) return true;
  } catch {
    // ignora
  }
  return false;
}

export function analyzeSsrfStructure(rawText, { isUrlParamValue = false, isFreeProse = false } = {}) {
  if (!rawText || typeof rawText !== 'string') return false;
  const text = normalizePayloadMultiLayer(rawText).htmlDecoded;

  // IMDS cloud explícitos siempre son sospechosos
  if (/169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200/i.test(text)) {
    return true;
  }

  // En prosa libre de soporte (ej. "mi router http://192.168.1.1 no conecta"), NO disparar SSRF
  // salvo que el campo sea un parámetro/clave URL explícito o contenga metadata cloud.
  if (isFreeProse && !isUrlParamValue) {
    return false;
  }

  const schemeRegex = /(?:https?|gopher|dict|ftp|ldap|file):[\/\\]{1,3}([^\s"'<>/?#\\]+)/gi;
  let m;
  while ((m = schemeRegex.exec(text)) !== null) {
    if (isBlockedSsrfHost(m[1])) return true;
  }

  if (isUrlParamValue) {
    const trimmed = text.trim();
    if (/^[\/\\]{2}([^\s"'<>/?#\\]+)/.test(trimmed)) {
      const host = trimmed.match(/^[\/\\]{2}([^\s"'<>/?#\\]+)/)[1];
      if (isBlockedSsrfHost(host)) return true;
    }
    const bareHost = trimmed.split(/[/?#]/)[0];
    if (bareHost && isBlockedSsrfHost(bareHost)) return true;
  }

  return false;
}

// ============================================================================
// 4. ANALIZADOR ESTRUCTURAL RCE / COMMAND INJECTION / LOG4SHELL / SPEL O(n)
// ============================================================================
const POSIX_COMMANDS = new Set([
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'cat', 'id', 'whoami', 'uname', 'sleep',
  'curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'python', 'python3', 'perl', 'ruby', 'php',
  'awk', 'sed', 'env', 'printenv', 'ping', 'nslookup', 'dig', 'chmod', 'chown', 'mkfifo',
  'telnet', 'certutil', 'powershell', 'cmd.exe', 'ls', 'dir', 'head', 'tail', 'grep', 'find',
  'xargs', 'base64', 'xxd', 'od', 'rev', 'dd', 'tee', 'tar', 'gzip', 'expr', 'eval', 'exec',
  'printf', 'echo', 'kill', 'ps', 'netstat', 'ss', 'ifconfig', 'ip', 'hostname', 'groups', 'passwd'
]);

function hasNestedDollarBraceLinear(str) {
  let pos = 0;
  while (pos < str.length) {
    const open = str.indexOf('${', pos);
    if (open === -1) return false;
    const close = str.indexOf('}', open + 2);
    const inner = str.indexOf('${', open + 2);
    if (inner !== -1 && (close === -1 || inner < close)) {
      return true;
    }
    pos = open + 2;
  }
  return false;
}

function deobfuscateShellLinear(str) {
  return str
    .replace(/\$\{IFS\}/g, ' ')
    .replace(/\$IFS\b/g, ' ')
    .replace(/\$[@*]/g, '')
    .replace(/(?<=[a-zA-Z0-9_/.-])['"\\]+(?=[a-zA-Z0-9_/.-])/g, '');
}

/**
 * Comprueba si un fragmento tras un delimitador shell (`;`, `|`, `&&`, `||`, `\n`, `$(`, `` ` ``)
 * constituye una invocación real de comando POSIX (evita FP en listas separadas por `|` y reseñas multilínea).
 */
function looksLikeShellInvocation(fragment, delimiter) {
  const trimmed = fragment.trim();
  if (!trimmed) return false;

  // Brace expansion estilo `{cat,/etc/passwd}`
  if (/^\{[a-zA-Z0-9_./-]+,[a-zA-Z0-9_./-]+\}/.test(trimmed)) return true;

  // Extrae el primer token (posible ruta `/bin/sh` o comando `curl`)
  const tokMatch = trimmed.match(/^((?:\/(?:usr\/)?s?bin\/)?[a-zA-Z0-9._-]+)(?:\s+(.*))?$/);
  if (!tokMatch) return false;

  const fullCmd = tokMatch[1].toLowerCase();
  const baseCmd = fullCmd.includes('/') ? fullCmd.slice(fullCmd.lastIndexOf('/') + 1) : fullCmd;
  const args = (tokMatch[2] || '').trim();
  const hasExplicitBinPath = fullCmd.startsWith('/bin/') || fullCmd.startsWith('/usr/bin/') || fullCmd.startsWith('/sbin/');

  if (hasExplicitBinPath && POSIX_COMMANDS.has(baseCmd)) return true;
  if (!POSIX_COMMANDS.has(baseCmd)) return false;

  // En sustitución explícita `$(...)` o backticks `` `...` ``, cualquier comando POSIX es alta confianza
  if (delimiter === '$(' || delimiter === '`') return true;

  // En salto de línea (`\n`), exigir que la línea sea un comando puro sin prosa natural alrededor
  // (evita falsos positivos en reseñas multilínea como "Great product\nid love to buy again" o "sleep well")
  if (delimiter === '\n') {
    if (baseCmd === 'id' || baseCmd === 'whoami' || baseCmd === 'uname' || baseCmd === 'env' || baseCmd === 'printenv') {
      return args === '' || /^-[a-zA-Z]{1,4}$/.test(args);
    }
    if (baseCmd === 'sleep') return /^\d+(?:\.\d+)?$/.test(args);
    if (baseCmd === 'cat' || baseCmd === 'head' || baseCmd === 'tail') return /^\/[a-zA-Z0-9._/-]+/.test(args);
    if (baseCmd === 'sh' || baseCmd === 'bash' || baseCmd === 'zsh') return args === '' || /^-c\b/.test(args);
    if (baseCmd === 'curl' || baseCmd === 'wget') return /^(?:-[a-zA-Z]+\s+)*(?:https?:\/\/|[a-z0-9.-]+\.[a-z]{2,})/i.test(args);
    if (baseCmd === 'nc' || baseCmd === 'ncat' || baseCmd === 'netcat') return /-e\b|-c\b/.test(args);
    return false;
  }

  // En pipe `|` (listas de productos como "Camisa | Pantalón | Envío rápido"), exigir comando + sintaxis shell real
  if (delimiter === '|') {
    if (['sh', 'bash', 'zsh', 'dash', 'ksh'].includes(baseCmd)) return args === '' || /^-/.test(args);
    if (['id', 'whoami', 'uname', 'env', 'printenv', 'rev'].includes(baseCmd)) return args === '' || /^-[a-zA-Z]{1,4}$/.test(args);
    if (['base64', 'xxd', 'od', 'xargs', 'awk', 'sed', 'tee'].includes(baseCmd)) return args.startsWith('-') || args.includes("'") || args.includes('/');
    if (['cat', 'head', 'tail', 'grep'].includes(baseCmd)) return /(?:^|\s)\/[a-zA-Z0-9._/-]+/.test(args);
    if (['curl', 'wget', 'nc', 'ncat', 'netcat', 'python', 'python3', 'perl', 'ruby', 'php'].includes(baseCmd)) return args.length > 0;
    return false;
  }

  // En `;`, `&&`, `||`
  if (baseCmd === 'id') return args === '' || /^-[a-zA-Z]{1,4}$/.test(args);
  if (['whoami', 'uname', 'env', 'printenv'].includes(baseCmd)) return args === '' || /^-[a-zA-Z]{1,4}$/.test(args);
  if (['sh', 'bash', 'zsh', 'dash'].includes(baseCmd)) return args === '' || /^-/.test(args);
  if (baseCmd === 'sleep') return /^\d+(?:\.\d+)?$/.test(args);
  if (['cat', 'head', 'tail', 'ls'].includes(baseCmd)) return args === '' || /^-|^\//.test(args);
  if (['curl', 'wget'].includes(baseCmd)) return /^\S+/.test(args);
  if (['nc', 'ncat', 'netcat'].includes(baseCmd)) return args.includes('-e') || args.includes('-c') || /\d{1,5}/.test(args);
  if (['python', 'python3', 'perl', 'php', 'ruby'].includes(baseCmd)) return /^-[ce]\s+/.test(args);
  if (['base64', 'xxd', 'find', 'xargs', 'awk', 'sed', 'chmod', 'mkfifo', 'eval', 'exec'].includes(baseCmd)) return args.length > 0;

  return false;
}

export function analyzeRceStructure(rawText) {
  if (!rawText || typeof rawText !== 'string') return false;
  const norm = normalizePayloadMultiLayer(rawText);

  for (const base of [rawText, norm.htmlDecoded]) {
    // 1. Log4Shell / JNDI / Expression Language (lineal O(n))
    if (base.includes('${')) {
      if (/\$\{(?:jndi|env|lower|upper|sys|java|date|ctx|base64|spring|k8s|docker|bundle|main|sd|log4j):/i.test(base)) {
        return true;
      }
      if (hasNestedDollarBraceLinear(base)) return true;
      if (/\$\{\s*T\s*\(\s*[a-zA-Z0-9_.$]+\s*\)/i.test(base)) return true;
    }
    if (base.includes('#{') && /#\{\s*T\s*\(\s*[a-zA-Z0-9_.$]+\s*\)/i.test(base)) return true;

    const deob = deobfuscateShellLinear(base);
    for (const cand of [base, deob]) {
      // 2. Sustitución de comandos `$(...)` lineal
      let p = 0;
      while ((p = cand.indexOf('$(', p)) !== -1) {
        const close = cand.indexOf(')', p + 2);
        if (close !== -1 && close - p <= 180) {
          if (looksLikeShellInvocation(cand.slice(p + 2, close), '$(')) return true;
        }
        p += 2;
      }

      // 3. Backticks `` `...` `` lineal
      p = 0;
      while ((p = cand.indexOf('`', p)) !== -1) {
        const close = cand.indexOf('`', p + 1);
        if (close === -1) break;
        if (close - p <= 180 && looksLikeShellInvocation(cand.slice(p + 1, close), '`')) return true;
        p = close + 1;
      }

      // 4. Encadenamiento con `;`, `||`, `&&`, `|`, `\n` escaneado linealmente
      const sepRegex = /(?:&&|\|\||;|\||\r?\n)/g;
      let m;
      while ((m = sepRegex.exec(cand)) !== null) {
        const delim = m[0].includes('\n') ? '\n' : m[0];
        const nextSep = cand.slice(m.index + m[0].length, m.index + m[0].length + 160);
        const cut = nextSep.search(/[;&|\r\n]/);
        const seg = cut === -1 ? nextSep : nextSep.slice(0, cut);
        if (looksLikeShellInvocation(seg, delim)) return true;
      }

      // 5. Binarios Windows / reverse shells explícitos / Java4Shell
      if (/\bcmd\.exe\s+\/c\b|\bpowershell(?:\.exe)?\s+-(?:enc|encodedcommand|nop)\b/i.test(cand)) return true;
      if (/java4shell|avx512_vbmi_overflow/i.test(cand)) return true;
      if (cand.includes('===') && /(?:^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={3,}/.test(cand)) return true;
    }
  }
  return false;
}

// ============================================================================
// 5. ANALIZADOR ESTRUCTURAL LFI / PATH TRAVERSAL O(n)
// ============================================================================
export function analyzeLfiStructure(rawText, { isFreeProseBody = false } = {}) {
  if (!rawText || typeof rawText !== 'string') return false;
  const text = normalizePayloadMultiLayer(rawText).htmlDecoded;

  if (text.includes('..')) {
    if (/(?:^|[\s="'/?&\\])(?:\.\.[/\\])+[a-zA-Z0-9._/-]/i.test(text) || /(?:\.\.[/\\]){2,}/.test(text)) {
      return true;
    }
  }

  if (/\b(?:php|expect|phar|zip):\/\/(?:filter|input|resource|fd)/i.test(text)) return true;
  if (/\bdata:\/\/[a-z0-9/+.-]*;base64,/i.test(text)) return true;
  if (/\bfile:\/\/\/(?:etc|proc|var|windows|boot)/i.test(text)) return true;

  if (/\/etc\/(?:passwd|shadow)\b|\/proc\/(?:self|\d+)\/(?:environ|cmdline|maps|fd)\b|\/var\/www\/[^\s"'<>]*\.(?:env|php|sql|bak|config)\b|c:\\windows\\win\.ini/i.test(text)) {
    return true;
  }
  if (!isFreeProseBody && /^\/etc\/hosts$/i.test(text.trim())) {
    return true;
  }

  return false;
}

// ============================================================================
// 6. ANALIZADOR SSTI (CON Y SIN {{ }}), NoSQL, XXE (PERMITIENDO XHTML DOCTYPE) & PROTOTYPE POLLUTION
// ============================================================================
function hasSstiInDelimitedBlock(inner) {
  const s = inner.trim();
  if (!s || s.length > 200) return false;
  // Variable simple de email (`nombre`, `user.first_name`, `order_id`) -> NO es SSTI
  if (/^[a-zA-Z_][a-zA-Z0-9_.-]{0,40}$/.test(s)) return false;
  // Aritmética de prueba (`7*7`, `7*'7'`), introspección Python/JS/Java, imports, llamadas a ejecución
  return /(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|constructor|lipsum|cycler|popen|system\s*\(|exec\s*\(|eval\s*\(|Runtime|ProcessBuilder|request\.application|config\.items|\bimport\s+os\b|\d+\s*[*+-/]\s*(?:'\d+'|\d+))/i.test(
    s
  );
}

function scanTemplateDelimitersLinear(text, openTok, closeTok) {
  if (!text.includes(openTok)) return false;
  let pos = 0;
  while ((pos = text.indexOf(openTok, pos)) !== -1) {
    const end = text.indexOf(closeTok, pos + openTok.length);
    if (end === -1) break;
    const inner = text.slice(pos + openTok.length, end);
    if (hasSstiInDelimitedBlock(inner)) return true;
    pos = end + closeTok.length;
  }
  return false;
}

export function analyzeExtrasStructure({ rawTexts = [], jsonKeys = [], jsonKeyPaths = [], params = [] }) {
  // 1. NoSQL & Prototype Pollution sobre claves reales JSON (profundo hasta 64 niveles / 10k nodos)
  for (const k of jsonKeys) {
    if (NOSQL_OPERATORS.has(k)) return true;
    if (k === '__proto__') return true;
  }
  for (const stack of jsonKeyPaths) {
    for (let i = 0; i < stack.length - 1; i += 1) {
      if (stack[i] === 'constructor' && stack[i + 1] === 'prototype') return true;
    }
  }

  for (const p of params) {
    const k = String(p.key || '');
    if (/\[\s*\$(?:ne|eq|gt|gte|lt|lte|in|nin|where|regex|exists|or|and)\s*\]/i.test(k)) return true;
    if (/(?:^|[\[.])__proto__(?:[\].]|$)|constructor(?:\.|\[)prototype/i.test(k)) return true;
  }

  // 2. SSTI (con y sin {{ }}), XXE real (sin FP en <!DOCTYPE html PUBLIC XHTML>) y Prototype Pollution
  for (const raw of rawTexts) {
    if (!raw || typeof raw !== 'string') continue;
    const text = normalizePayloadMultiLayer(raw).htmlDecoded;

    // SSTI: {{ }}, {% %}, <% %>, #{ }, ${ }, *{ }
    if (
      scanTemplateDelimitersLinear(text, '{{', '}}') ||
      scanTemplateDelimitersLinear(text, '{%', '%}') ||
      scanTemplateDelimitersLinear(text, '<%', '%>') ||
      scanTemplateDelimitersLinear(text, '#{', '}') ||
      scanTemplateDelimitersLinear(text, '${', '}') ||
      scanTemplateDelimitersLinear(text, '*{', '}')
    ) {
      return true;
    }
    // FreeMarker / Velocity / Smarty sin llaves dobles
    if (
      /<#assign\b[^>]{0,160}new\s*\(|#set\s*\(\s*\$[a-z0-9_]+\s*=|freemarker\.template\.utility\.Execute|\{php\}|\{system\s*\(/i.test(
        text
      )
    ) {
      return true;
    }

    // XXE real: exige `<!ENTITY` o `<!DOCTYPE ... SYSTEM ...` externo no-W3C (permite `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML..."`)
    if (text.includes('<!')) {
      if (/<!\s*ENTITY\b/i.test(text)) return true;
      if (/<!\s*DOCTYPE\b[^>\n]{0,120}\bSYSTEM\s+["'][^"']+["']/i.test(text) && !/w3\.org\/TR\//i.test(text)) {
        return true;
      }
    }

    // Prototype Pollution textual
    if (text.includes('__proto__') || text.includes('prototype')) {
      if (/(?:^|[.?&["'{\s])__proto__(?:[\]"'}=:\s.]|$)|constructor\s*(?:\.\s*prototype|\[\s*["']prototype["']\s*\])/i.test(text)) {
        return true;
      }
    }

    // NoSQL textual
    if (text.includes('$') && /(?:"|\[)\s*\$(?:ne|gt|gte|lt|lte|in|nin|where|regex|exists|expr|function)\s*(?:"|\])/i.test(text)) {
      return true;
    }
  }

  return false;
}
