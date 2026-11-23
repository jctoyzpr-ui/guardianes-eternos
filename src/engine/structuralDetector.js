/**
 * @fileoverview Analizador Estructural Lineal O(n) v5.3 (0 dependencias npm).
 * v5.3: sin recorte silencioso de campos, JSON léxico (claves duplicadas), ventanas SQL, operandos compuestos,
 * subconsultas/CASE, best-fit Unicode y overlong UTF-8, rotura de atributos, OGNL, deserialización, CRLF, LDAP,
 * Spring class-binding, wrappers de stream y rutas de sistema. Todos los bucles revisados para costo lineal real.
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

// v5.3: Sin recorte silencioso de campos. Todo lo que el backend recibe (hasta el tope de cuerpo inspeccionable,
// 1 MB por defecto) se analiza completo. La seguridad ante DoS viene de algoritmos lineales reales + Worker con
// tope de tiempo, no de "no mirar" el final del campo (eso era una evasión: relleno + ataque al final).
export const MAX_FIELD_SCAN_CHARS = 2 * 1024 * 1024;
const SQL_WINDOW_CHARS = 2_000;
const SQL_WINDOW_OVERLAP = 400;

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
    // v5.3: Codificaciones no estándar que IIS / Tomcat / parsers laxos sí decodifican:
    //   %uXXXX (IIS), UTF-8 "overlong" (%c0%ae = '.', %c0%af = '/', %e0%80%ae, %c1%9c = '\')
    if (decoded.includes('%')) {
      decoded = decoded
        .replace(/%u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/%c0%ae|%e0%80%ae|%c0%2e/gi, '.')
        .replace(/%c0%af|%e0%80%af|%c0%2f/gi, '/')
        .replace(/%c1%9c|%c1%1c|%c0%5c/gi, '\\');
    }
    try {
      // v5.3: '+' = espacio solo en la PRIMERA capa (form-encoding). En capas siguientes un '+' viene de %2B y es
      // literal (operador de concatenación MSSQL: `'+(SELECT ...)+'`); antes se convertía en espacio.
      const next = decodeURIComponent(i === 0 ? decoded.replace(/\+/g, ' ') : decoded);
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

  // v5.3: "best-fit" de Windows/IIS/ASP y formas de ancho completo: el backend las convierte a ASCII
  //   ∕ ⁄ ／ -> '/',  ∖ ＼ ﹨ -> '\',  ． ․ ﹒ -> '.',  ＜script＞ -> <script>  (U+FF01..U+FF5E -> ASCII)
  if (/[․⁄∕∖﹒﹨！-～]/.test(decoded)) {
    decoded = decoded
      .replace(/[∕⁄]/g, '/')
      .replace(/[∖﹨]/g, '\\')
      .replace(/[․﹒]/g, '.')
      .replace(/[！-～]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xfee0));
  }
  const noNulls = decoded.includes('\0') ? decoded.replace(/\0/g, '') : decoded;
  const htmlDecoded = decodeEntitiesAndEscapes(noNulls);
  // v5.3: los navegadores ignoran TAB/LF/CR dentro de esquemas URI ("java\nscript:") -> también se eliminan aquí
  const compactControl = htmlDecoded.replace(/[\x00-\x1f\x7f]+/g, '');
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

  // v5.3: sin tope de 120 campos (el campo 121 quedaba sin inspeccionar). El costo sigue siendo lineal.
  for (let i = 1; i < parts.length; i += 1) {
    const part = parts[i];
    if (!part || part.startsWith('--')) continue;
    const sepIdx = part.indexOf('\r\n\r\n') !== -1 ? part.indexOf('\r\n\r\n') : part.indexOf('\n\n');
    if (sepIdx === -1) continue;
    const headerBlock = part.slice(0, sepIdx);
    const rawVal = part.slice(sepIdx + (part[sepIdx] === '\r' ? 4 : 2)).replace(/\r?\n$/, '');
    const nameMatch = headerBlock.match(/\bname="([^"]{1,200})"/i);
    const fileMatch = headerBlock.match(/filename="([^"]{1,400})"/i);
    // RFC 5987 (filename*=UTF-8''..%2e%2e%2f..) — antes se ignoraba
    const fileStarMatch = headerBlock.match(/filename\*\s*=\s*(?:[a-z0-9-]+'[a-z-]*')?([^;\r\n]{1,600})/i);
    const key = nameMatch ? nameMatch[1] : '';
    if (fileMatch) {
      fields.push({ key: `${key}.filename`, value: decodeEntitiesAndEscapes(fileMatch[1]), source: 'multipart' });
    }
    if (fileStarMatch) {
      fields.push({ key: `${key}.filename`, value: normalizePayloadMultiLayer(fileStarMatch[1].trim()).htmlDecoded, source: 'multipart' });
    }
    // El nombre del campo también llega al backend (form[__proto__][x], campo con SQL, etc.)
    if (key) fields.push({ key: `${key}`, value: '', source: 'multipart-key' });
    if (rawVal) {
      fields.push({ key, value: normalizePayloadMultiLayer(rawVal).htmlDecoded, source: 'multipart' });
    }
  }
  return fields;
}

function unescapeJsonString(raw) {
  if (!raw.includes('\\')) return raw;
  try {
    return JSON.parse(`"${raw}"`);
  } catch {
    return raw;
  }
}

/**
 * v5.3: Escáner léxico JSON estrictamente lineal O(n).
 * Devuelve cada string (clave o valor) con su ruta de claves, sin depender de JSON.parse.
 * Si la estructura no es JSON válido devuelve ok=false (el caller lo inspecciona como texto plano).
 */
export function scanJsonLexical(text) {
  const params = [];
  const keys = [];
  const keyPaths = [];
  // Pila de contenedores: { type: '{' | '[', key: clave actual dentro del objeto }
  const stack = [];
  const len = text.length;
  let i = 0;
  let expectKey = false;

  const currentPath = () => {
    const path = [];
    for (let s = Math.max(0, stack.length - 4); s < stack.length; s += 1) {
      if (stack[s].type === '{' && stack[s].key !== null) path.push(stack[s].key);
    }
    return path;
  };

  while (i < len) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < len && text[j] !== '"') {
        j += text[j] === '\\' ? 2 : 1;
      }
      if (j >= len) return { ok: false, params, keys, keyPaths };
      const value = unescapeJsonString(text.slice(i + 1, j));
      i = j + 1;
      // ¿Es clave? (siguiente carácter no-espacio es ':')
      let k = i;
      while (k < len && (text[k] === ' ' || text[k] === '\n' || text[k] === '\r' || text[k] === '\t')) k += 1;
      const top = stack[stack.length - 1];
      if (text[k] === ':' && top?.type === '{' && expectKey) {
        top.key = value;
        keys.push(value);
        keyPaths.push(currentPath());
        expectKey = false;
        i = k + 1;
      } else {
        const path = currentPath();
        params.push({ key: path[path.length - 1] || '', value: decodeEntitiesAndEscapes(value), source: 'json' });
      }
      continue;
    }
    if (ch === '{') {
      stack.push({ type: '{', key: null });
      expectKey = true;
    } else if (ch === '[') {
      stack.push({ type: '[', key: null });
      expectKey = false;
    } else if (ch === '}' || ch === ']') {
      const top = stack.pop();
      if (!top || (ch === '}' && top.type !== '{') || (ch === ']' && top.type !== '[')) {
        return { ok: false, params, keys, keyPaths };
      }
      expectKey = false;
    } else if (ch === ',') {
      expectKey = stack[stack.length - 1]?.type === '{';
    }
    i += 1;
  }
  return { ok: stack.length === 0, params, keys, keyPaths };
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
      // v5.3: Escáner léxico lineal en vez de JSON.parse + walker:
      //   - ve TODAS las claves y valores, incluidas claves duplicadas ({"u":"ok","u":"' OR 1=1--"}): JSON.parse se
      //     queda con la última, pero muchos backends usan la primera -> antes era una evasión.
      //   - sin tope de 10,000 nodos ni de 64 niveles (antes el nodo 10,001 quedaba sin inspeccionar).
      const lex = scanJsonLexical(trimmedBody);
      if (lex.ok) {
        for (const p of lex.params) params.push(p);
        for (const k of lex.keys) jsonKeys.push(k);
        for (const kp of lex.keyPaths) jsonKeyPaths.push(kp);
      } else {
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
  // v5.3: si desde una comilla no existe cierre hasta el final, ninguna comilla posterior del mismo tipo lo tendrá
  // (la alineación de escapes coincide) -> evita re-escaneos O(n²) con `'\'\'\'...`
  const noCloseFrom = { "'": Infinity, '"': Infinity };

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
      let j = len;
      if (i < noCloseFrom[quote]) {
        j = i + 1;
        while (j < len && s[j] !== quote) {
          if (s[j] === '\\') j += 2;
          else j += 1;
        }
        if (j >= len) noCloseFrom[quote] = i;
      }
      if (j < len && s[j] === quote) {
        const inner = s.slice(i + 1, j);
        // v5.3: también breakouts con operador de concatenación/aritmético antes de la subconsulta:
        //   `'+(SELECT ...)+'` (MSSQL), `'||(SELECT ...)||'` (Oracle/PG), `'-(SELECT ...)-'`
        if (/^\s*(?:[+\-*/%^&|]+\s*)?\(*\s*(?:or|and|union|select|order|group|having|exec|waitfor|case|;|\|\||&&)\b/i.test(inner) || /^\s*;/.test(inner)) {
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
      // v5.3: literales hex/binarios SQL (0x31, 0b1) son un solo NUM (antes "0" + IDENT "x31" rompía la tautología)
      if (ch === '0' && (s[i + 1] === 'x' || s[i + 1] === 'X' || s[i + 1] === 'b' || s[i + 1] === 'B')) {
        j = i + 2;
        while (j < len && /[0-9a-fA-F]/.test(s[j])) j += 1;
        tokens.push({ type: 'NUM', val: s.slice(i, j) });
        i = j;
        continue;
      }
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

const SQL_FUNCTION_KWS = new Set([
  'CHAR', 'CHR', 'ASCII', 'ORD', 'SUBSTR', 'SUBSTRING', 'MID', 'HEX', 'UNHEX', 'CONCAT', 'CONCAT_WS', 'CAST',
  'CONVERT', 'VERSION', 'USER', 'SCHEMA', 'DATABASE', 'SLEEP', 'PG_SLEEP', 'BENCHMARK', 'EXTRACTVALUE',
  'UPDATEXML', 'GROUP_CONCAT', 'LOAD_FILE'
]);

/**
 * v5.3: Salta un "operando" SQL completo a partir de toks[k]:
 *   NUM | STR | IDENT | QUOTE | NULL/TRUE/FALSE | FUNC(...) | IDENT(...) | ( ... )
 * Devuelve el índice siguiente al operando o -1 si no hay operando válido. Lineal (avanza siempre).
 */
function skipSqlOperand(toks, k) {
  const n = toks.length;
  if (k >= n) return -1;
  const t = toks[k];
  if ((t.type === 'KW' && SQL_FUNCTION_KWS.has(t.val)) || t.type === 'IDENT') {
    if (toks[k + 1]?.type === 'LPAREN') {
      let depth = 0;
      for (let j = k + 1; j < n && j < k + 64; j += 1) {
        if (toks[j].type === 'LPAREN') depth += 1;
        else if (toks[j].type === 'RPAREN') {
          depth -= 1;
          if (depth === 0) return j + 1;
        }
      }
      return -1;
    }
    return t.type === 'IDENT' ? k + 1 : -1;
  }
  if (t.type === 'LPAREN') {
    let depth = 0;
    for (let j = k; j < n && j < k + 64; j += 1) {
      if (toks[j].type === 'LPAREN') depth += 1;
      else if (toks[j].type === 'RPAREN') {
        depth -= 1;
        if (depth === 0) return j + 1;
      }
    }
    return -1;
  }
  if (['NUM', 'STR', 'QUOTE'].includes(t.type)) return k + 1;
  if (t.type === 'KW' && ['NULL', 'TRUE', 'FALSE'].includes(t.val)) return k + 1;
  return -1;
}

function isSqlComparisonOp(op) {
  return Boolean(op) && (op.type === 'CMP' || (op.type === 'KW' && ['LIKE', 'RLIKE', 'REGEXP', 'IN', 'BETWEEN', 'IS'].includes(op.val)));
}

/**
 * v5.3: Ventanas solapadas de tamaño fijo -> cada parte de un campo largo se tokeniza (el ataque no puede
 * esconderse en medio de 100 KB de relleno) y el costo total sigue siendo lineal.
 */
function sqlWindows(text) {
  if (text.length <= SQL_WINDOW_CHARS) return [text];
  const out = [];
  const step = SQL_WINDOW_CHARS - SQL_WINDOW_OVERLAP;
  for (let start = 0; start < text.length; start += step) {
    out.push(text.slice(start, start + SQL_WINDOW_CHARS));
    if (start + SQL_WINDOW_CHARS >= text.length) break;
  }
  return out;
}

export function analyzeSqlStructure(rawText) {
  if (!rawText || typeof rawText !== 'string' || rawText.length < 4) return false;
  const norm = normalizePayloadMultiLayer(rawText);

  const variants = new Set([norm.sqlEmptyComments, norm.sqlSpaceComments]);
  // v5.3: variante con '+' literal (valores JSON / cabeceras / %2B ya decodificado): el '+' es operador SQL
  if (rawText.includes('+')) {
    let plain = rawText.length > MAX_FIELD_SCAN_CHARS ? rawText.slice(0, MAX_FIELD_SCAN_CHARS) : rawText;
    try {
      plain = decodeURIComponent(plain);
    } catch {
      // se usa tal cual
    }
    variants.add(stripSqlCommentsLinear(decodeEntitiesAndEscapes(plain.replace(/\0/g, '')), ' '));
  }
  const slices = [];
  for (const text of variants) {
    for (const w of sqlWindows(text)) slices.push(w);
  }

  for (const text of slices) {
    const toks = tokenizeSql(text, 1200);
    const n = toks.length;
    if (n < 2) continue;

    for (let i = 0; i < n; i += 1) {
      const t = toks[i];

      // v5.3 (0). Tautología/comparación con operandos compuestos tras pivote + booleano:
      //   ' OR CHAR(49)=CHAR(49)--, 1 AND ASCII(x)>64, ' OR (SELECT 1)=1, ' OR 0x31=0x31
      if (t.type === 'BOOL' && i > 0 && i + 1 < n) {
        const prev = toks[i - 1];
        if (['QUOTE', 'NUM', 'RPAREN', 'STR'].includes(prev.type)) {
          const afterLhs = skipSqlOperand(toks, i + 1);
          if (afterLhs !== -1 && isSqlComparisonOp(toks[afterLhs])) {
            const afterRhs = skipSqlOperand(toks, afterLhs + 1);
            const lhsIsCompound = toks[i + 1].type === 'LPAREN' || toks[i + 2]?.type === 'LPAREN';
            const rhsTok = toks[afterLhs + 1];
            const rhsIsCompound = rhsTok && (rhsTok.type === 'LPAREN' || toks[afterLhs + 2]?.type === 'LPAREN');
            if (afterRhs !== -1 && (lhsIsCompound || rhsIsCompound)) return true;
          }
        }
      }

      // v5.3 (0b). Ruptura de comilla (QUOTE o QUOTE + ')') + booleano [NOT] + comparación entre paréntesis, o
      //   cualquier expresión que TERMINA en comentario SQL: `x') OR NOT (2<1)-- `, `' AND (1)=(1)#`
      if (t.type === 'BOOL' && i > 0) {
        const p1 = toks[i - 1];
        const p2 = toks[i - 2];
        const quoteBreak = p1.type === 'QUOTE' || (p1.type === 'RPAREN' && p2?.type === 'QUOTE');
        if (quoteBreak) {
          let k = i + 1;
          if (toks[k]?.type === 'KW' && toks[k].val === 'NOT') k += 1;
          if (toks[k]?.type === 'LPAREN') {
            const after = skipSqlOperand(toks, k);
            const inner = toks.slice(k, after === -1 ? Math.min(n, k + 20) : after);
            if (inner.some((x) => x.type === 'CMP' || (x.type === 'KW' && ['SELECT', 'TRUE', 'FALSE', 'NULL'].includes(x.val)))) return true;
          }
          for (let j = i + 1; j < n && j < i + 30; j += 1) {
            if (toks[j].type === 'COMMENT') return true;
            if (toks[j].type === 'QUOTE') break;
          }
        }
      }

      // v5.3 (0c). Comilla de ruptura seguida DIRECTAMENTE de una cláusula SQL: `admin' HAVING 1=1--`,
      //   `x' GROUP BY 1--`, `x' ORDER BY 9--`, `x' LIMIT 1 INTO OUTFILE`, `x' PROCEDURE ANALYSE()`
      if (t.type === 'QUOTE' && i + 1 < n) {
        const nx = toks[i + 1];
        const nx2 = toks[i + 2];
        if (nx.type === 'KW' && nx2) {
          if (nx.val === 'HAVING' && ['NUM', 'IDENT', 'LPAREN', 'STR', 'QUOTE'].includes(nx2.type)) return true;
          if ((nx.val === 'GROUP' || nx.val === 'ORDER') && nx2.type === 'KW' && nx2.val === 'BY') return true;
          if (nx.val === 'LIMIT' && nx2.type === 'NUM') return true;
          if (nx.val === 'INTO' && nx2.type === 'KW' && nx2.val === 'OUTFILE') return true;
          if (['UNION', 'SELECT', 'EXEC', 'EXECUTE', 'WAITFOR', 'DECLARE'].includes(nx.val)) return true;
        }
        if (nx.type === 'IDENT' && /^procedure$/i.test(nx.val) && nx2?.type === 'IDENT') return true;
      }

      // v5.3 (7). CASE WHEN <comparación> THEN — inyección en expresiones de orden/filtro (sort, order, column)
      if (t.type === 'KW' && t.val === 'CASE' && toks[i + 1]?.type === 'KW' && toks[i + 1].val === 'WHEN') {
        for (let j = i + 2; j < n && j < i + 40; j += 1) {
          if (toks[j].type === 'KW' && toks[j].val === 'THEN') {
            const inner = toks.slice(i + 2, j);
            if (inner.some((x) => x.type === 'CMP' || x.type === 'LPAREN' || (x.type === 'KW' && SQL_FUNCTION_KWS.has(x.val)))) {
              return true;
            }
            break;
          }
        }
      }

      // v5.3 (8). Subconsulta en posición de expresión: ,(SELECT ...) / =(SELECT ...) / OR (SELECT ...)
      //   Exige contenido SQL real dentro (función, NUM, NULL, comparación, CASE, '*', @@var) para no confundir
      //   prosa como "(select one from the list)".
      if (t.type === 'LPAREN' && toks[i + 1]?.type === 'KW' && toks[i + 1].val === 'SELECT') {
        const prev = i > 0 ? toks[i - 1] : null;
        // posición de expresión: tras coma, comparación, booleano, comilla, paréntesis, palabra SQL u operador
        // aritmético/concatenación (MSSQL `'+(SELECT ...)+'`, Oracle `'||(SELECT ...)||'`)
        const exprPosition = prev && (
          ['COMMA', 'CMP', 'BOOL', 'QUOTE', 'LPAREN', 'STR'].includes(prev.type) ||
          (prev.type === 'OTHER' && ['+', '-', '*', '/', '%', '|', '&', '^'].includes(prev.val)) ||
          (prev.type === 'KW' && ['IN', 'EXISTS', 'BY', 'WHERE', 'AND', 'SELECT', 'THEN', 'WHEN'].includes(prev.val))
        );
        if (exprPosition) {
          let depth = 0;
          let sqlSignal = false;
          for (let j = i; j < n && j < i + 80; j += 1) {
            const x = toks[j];
            if (x.type === 'LPAREN') depth += 1;
            else if (x.type === 'RPAREN') {
              depth -= 1;
              if (depth === 0) break;
            }
            if (
              j > i + 1 &&
              (x.type === 'NUM' ||
                x.type === 'CMP' ||
                (x.type === 'OTHER' && x.val === '*') ||
                (x.type === 'IDENT' && x.val.startsWith('@@')) ||
                (x.type === 'KW' && (SQL_FUNCTION_KWS.has(x.val) || ['NULL', 'CASE', 'INFORMATION_SCHEMA', 'LIMIT'].includes(x.val))))
            ) {
              sqlSignal = true;
            }
          }
          if (sqlSignal) return true;
        }
      }

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
              // v5.3: con operador de PALABRA (LIKE/IN/IS/BETWEEN/REGEXP) entre dos palabras sueltas es prosa
              // ("...'es la mejor' or something like that"), no SQL: se exige al menos un literal/paréntesis/NULL.
              const wordOpBetweenIdents = op.type === 'KW' && lhs.type === 'IDENT' && rhs.type === 'IDENT';
              if (
                !wordOpBetweenIdents &&
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
    // v5.3: la posición del siguiente '>' se memoriza; antes cada '<' sin cierre re-escaneaba hasta el final (O(n²)).
    let pos = 0;
    let gtCache = text.indexOf('>');
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
      if (gtCache !== -1 && gtCache < j) gtCache = text.indexOf('>', j);
      const gt = gtCache;
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

    // v5.3 (3b). Rotura de atributo SIN etiqueta nueva: el valor se refleja dentro de value="..." y el atacante
    //   cierra la comilla para añadir un manejador: `" autofocus onfocus=alert(1) x="`, `' onmouseover='alert(1)`
    //   Exige comilla + espacio + (atributos opcionales) + on<evento>= + código JS, para no tocar prosa.
    if (
      /["'`][\s/]+(?:[a-z-]{1,24}(?:\s*=\s*(?:"[^"]{0,80}"|'[^']{0,80}'|[^\s>"']{0,80}))?[\s/]+){0,4}on[a-z]{3,24}\s*=\s*["'`]?\s*(?:[a-z_$][\w$.]{0,40}\s*[(`]|javascript:|eval|top\[|window\[|this\.|\[\]|\()/i.test(text) ||
      /["'`][\s/]+style\s*=\s*["']?[^"'>]{0,120}(?:expression\s*\(|javascript:|behavior\s*:|-moz-binding)/i.test(text)
    ) {
      return true;
    }

    // 4. AngularJS / Client-side Template sandbox escape
    // v5.3: se ancla en cada "constructor" (raro) en vez de en cada "{{" (con 1 MB de "{{" la regex anterior
    // retrocedía 120 caracteres por posición: ~1.4 s).
    // (JavaScript distingue mayúsculas: el gadget solo funciona con "constructor" en minúsculas)
    if (text.includes('{{')) {
      let cPos = 0;
      while ((cPos = text.indexOf('constructor', cPos)) !== -1) {
        const before = text.slice(Math.max(0, cPos - 122), cPos);
        const after = text.slice(cPos + 11, cPos + 133);
        const open = before.lastIndexOf('{{');
        const close = after.indexOf('}}');
        if (open !== -1 && !before.slice(open).includes('}') && close !== -1 && !after.slice(0, close).includes('}')) return true;
        cPos += 11;
      }
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

  // v5.3: camino rápido — hostname ASCII con TLD alfabético que no es interno ni de rebinding: nunca es una IP.
  if (
    /^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,63}$/.test(lower) &&
    !SSRF_BLOCKED_HOSTNAMES.has(lower) &&
    !/\.(?:internal|local|localhost|localdomain|intranet|corp|home|lan)$/.test(lower) &&
    !DNS_REBIND_SUFFIXES.some((sfx) => lower.endsWith(sfx)) &&
    !/(?:^|\.)(?:localtest\.me|lvh\.me|vcap\.me|nip\.io|sslip\.io|xip\.io)$/.test(lower) &&
    !lower.startsWith('metadata')
  ) {
    return false;
  }

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
    // El parser WHATWG normaliza lo que un backend Node/navegador también normalizará: IDNA (①②⑦ -> 127),
    // IPv6 completas (0:0:0:0:0:ffff:7f00:1 -> ::ffff:7f00:1), mayúsculas, puntos finales.
    const u = new URL(`http://${authority}/`);
    const uHost = u.hostname.toLowerCase().replace(/\.$/, '');
    if (SSRF_BLOCKED_HOSTNAMES.has(uHost) || uHost.endsWith('.internal') || uHost.endsWith('.localhost')) return true;
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

  const schemeRegex = /(?:https?|gopher|dict|ftp|ldaps?|file|sftp|tftp|jar|netdoc|ws|wss):[\/\\]{1,3}([^\s"'<>/?#\\]+)/gi;
  let m;
  // v5.3: TODAS las URLs del campo se revisan (un tope sería evasión: N URLs inocentes + la maliciosa).
  // Hosts repetidos se resuelven una sola vez y los dominios ASCII normales salen por un camino rápido.
  const seenHosts = new Set();
  while ((m = schemeRegex.exec(text)) !== null) {
    const authority = m[1];
    if (seenHosts.has(authority)) continue;
    seenHosts.add(authority);
    if (isBlockedSsrfHost(authority)) return true;
  }
  // v5.3: gopher:// y dict:// apuntando a cualquier host son herramientas de SSRF, no enlaces de usuario
  if (isUrlParamValue && /^\s*(?:gopher|dict|tftp|jar|netdoc):/i.test(text)) return true;

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
      // v5.3: si no queda ningún ')' no se re-escanea por cada '$(' (antes 63 KB de "$(" = 117 ms -> fail-open)
      let p = 0;
      while ((p = cand.indexOf('$(', p)) !== -1) {
        const close = cand.indexOf(')', p + 2);
        if (close === -1) break;
        if (close - p <= 180) {
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

      // 4. Encadenamiento con `;`, `||`, `&&`, `|`, `\n` — v5.3: un único split lineal (antes un slice de 160
      //    caracteres por separador: 1 MB de ';' eran ~1M copias).
      const pieces = cand.split(/(&&|\|\||[;|&]|\r?\n)/);
      for (let s = 1; s + 1 < pieces.length; s += 2) {
        const sep = pieces[s];
        if (sep === '&') continue; // un '&' suelto solo corta el segmento (igual que antes)
        const seg = pieces[s + 1];
        if (!seg || !seg.trim()) continue;
        const delim = sep.includes('\n') ? '\n' : sep;
        if (looksLikeShellInvocation(seg.length > 160 ? seg.slice(0, 160) : seg, delim)) return true;
      }

      // 5. Binarios Windows / reverse shells explícitos / Java4Shell
      if (/\bcmd\.exe\s+\/c\b|\bpowershell(?:\.exe)?\s+-(?:enc|encodedcommand|nop)\b/i.test(cand)) return true;
      if (/java4shell|avx512_vbmi_overflow/i.test(cand)) return true;
      // v5.3: OGNL / Struts2 y expresiones Java de ejecución
      if (/%\{\s*\(\s*#|\$\{\s*\(\s*#|#_memberAccess|#context\s*\[|@java\.lang\.(?:Runtime|ProcessBuilder|System)@|ognl\.OgnlContext|new\s+java\.lang\.ProcessBuilder|java\.lang\.Runtime\s*\.\s*getRuntime\s*\(/i.test(cand)) {
        return true;
      }
      // v5.3: Deserialización insegura (Java base64/hex, PHP serialize de objetos, .NET BinaryFormatter, node-serialize)
      if (/(?:^|[^A-Za-z0-9+/])rO0AB[A-Za-z0-9+/=]{12,}|\baced0005[0-9a-f]{8,}|(?:^|[;{"\s])O:\d{1,4}:"[A-Za-z_\\][\w\\]{0,120}":\d{1,4}:\{|_\$\$ND_FUNC\$\$_|\bAAEAAAD\/\/\/\/\/|\$type"\s*:\s*"System\.(?:Windows\.Data\.ObjectDataProvider|Diagnostics\.Process)/i.test(cand)) {
        return true;
      }
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
  // v5.3: wrappers de stream que ningún usuario legítimo escribe (en cualquier contexto)
  if (/\b(?:phar|expect|glob|compress\.(?:zlib|bzip2)|zlib|rar|ogg|ssh2\.(?:shell|exec|tunnel|sftp|scp)):\/\//i.test(text)) return true;
  if (/\bphp:\/\/[a-z]/i.test(text)) return true;

  if (/\/etc\/(?:passwd|shadow|group|sudoers|crontab|issue|master\.passwd)\b|\/proc\/(?:self|\d+)\/(?:environ|cmdline|maps|fd|cwd|root|status|mounts)\b|\/var\/www\/[^\s"'<>]*\.(?:env|php|sql|bak|config)\b|c:\\windows\\win\.ini/i.test(text)) {
    return true;
  }
  // v5.3: rutas de sistema Windows (con \ o /) — en cualquier contexto solo las inequívocamente de sistema
  if (/\b[a-z]:[\\/]+(?:windows|winnt)[\\/]+(?:system32|syswow64|system\.ini|win\.ini|repair|panther|debug)\b|[\\/]windows[\\/]+system32[\\/]+(?:config|drivers[\\/]+etc)\b|\bboot\.ini\b|[\\/]inetpub[\\/]+wwwroot[\\/][^\s"'<>]*web\.config/i.test(text)) {
    return true;
  }

  if (!isFreeProseBody) {
    const trimmed = text.trim();
    if (/^\/etc\/hosts$/i.test(trimmed)) return true;
    // Cuando el VALOR COMPLETO de un parámetro es una ruta absoluta de sistema / wrapper de archivo
    if (/^(?:file:|zip:\/\/|\/(?:etc|proc|root|sys|var\/log|var\/lib|home\/[^/\s]+\/\.(?:ssh|aws|bash_history|config))\/)/i.test(trimmed)) return true;
    if (/^[a-z]:[\\/]+(?:windows|winnt|programdata|inetpub|boot\.ini|users[\\/]+[^\\/\s]+[\\/]+(?:appdata|ntuser\.dat|\.ssh|\.aws))/i.test(trimmed)) return true;
    // Rutas UNC hacia otro host (fuga de hash NTLM / SMB relay): \\atacante\share
    if (/^(?:\\\\|\/\/\/?)[a-z0-9.-]+[\\/][^\s]*/i.test(trimmed) && trimmed.startsWith('\\\\')) return true;
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
  return /(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|__init__|__self|_self\.env|registerUndefinedFilterCallback|getFilter\s*\(|_TemplateReference__context|\|\s*attr\s*\(|\|\s*map\s*\(\s*["']system|constructor|lipsum|cycler|joiner|namespace\.__|popen|system\s*\(|exec\s*\(|eval\s*\(|Runtime|ProcessBuilder|request\.application|request\[|config\.items|self\.__|\bimport\s+os\b|\d+\s*[*+-/]\s*(?:'\d+'|"\d+"|\d+))/i.test(
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
    if (/\[\s*\$(?:ne|eq|gt|gte|lt|lte|in|nin|where|regex|exists|or|and|expr|function|elemMatch|not|nor)\s*\]/i.test(k)) return true;
    // v5.3: __proto__ seguido de '[' (query `__proto__[isAdmin]=true`) — antes solo ']' o '.'
    if (/(?:^|[\[.])__proto__(?:[\[\].]|$)|constructor\s*(?:\.|\[)\s*prototype/i.test(k)) return true;
    // v5.3: binding de objetos Java (Spring4Shell CVE-2022-22965 y familia): class.module.classLoader / class[classLoader]
    if (/(?:^|[.\[])class\s*(?:\.|\[)\s*(?:module|classloader|protectiondomain)\b|(?:^|[.\[])classloader\s*(?:\.|\[)/i.test(k)) return true;
    // v5.3: CRLF / división de cabeceras en valores de query/ruta/cabecera (no en prosa de body)
    if ((p.source === 'query' || p.source === 'path') && /[\r\n]\s*(?:set-cookie|location|content-(?:type|length|security-policy)|refresh|access-control-[a-z-]+|x-[a-z-]{2,40}|transfer-encoding|http\/1\.[01])\s*:?/i.test(String(p.value || ''))) {
      return true;
    }
    // v5.3: LDAP injection: cierre de filtro + nuevo filtro  `*)(uid=*))(|(uid=*`, `admin)(&)`
    if (/\)\s*\(\s*[|&!]\s*\(?\s*[a-z][\w-]{0,30}\s*[~<>]?=|\*\)\s*\(\s*[a-z][\w-]{0,30}\s*=\s*\*|\)\s*\(\s*&\s*\)|\)\s*\(\s*\|\s*\(/i.test(String(p.value || ''))) {
      return true;
    }
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
