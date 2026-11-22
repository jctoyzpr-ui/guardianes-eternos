/**
 * @fileoverview Analizador Estructural Multicapa v5.1 (0 dependencias npm).
 * Reemplaza el parcheo caso-por-caso con analizadores genéricos por familia:
 *   - Tokenizador léxico SQL (gramática de tautologías, UNION, stacked queries, blind/error functions, ORDER BY)
 *   - Parser estructural HTML/XSS (etiquetas reales, cualquier atributo on*=, esquemas URI en contexto)
 *   - Extractor SSRF canónico (http/https/gopher/dict/file, protocol-relative //, http:\\, DNS rebinding nip.io/sslip.io + net.BlockList)
 *   - Analizador RCE / Shell / EL (des-ofuscación de comillas shell, saltos de línea %0a, $(...), backticks, pipes, Log4Shell/SpEL)
 *   - Analizador estructural LFI, SSTI, NoSQL (con decodificación \u0024), XXE y Prototype Pollution.
 * Calibrado para distinguir gramática de explotación frente a prosa humana natural (N-01 & N-03).
 */

import net from 'node:net';

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
  '.vcap.me',
  '.127.0.0.1.nip.io'
];

const NOSQL_OPERATORS = new Set([
  '$ne', '$eq', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
  '$where', '$regex', '$exists', '$expr', '$function', '$accumulator',
  '$or', '$and', '$nor', '$not', '$elemMatch', '$lookup'
]);

/**
 * Decodifica entidades HTML y escapes Unicode/Hex JS (\u0024, \x3c) sin alterar texto normal.
 */
export function decodeEntitiesAndEscapes(str) {
  if (!str || typeof str !== 'string') return '';
  let out = str;

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
 * Normaliza hasta 3 capas de codificación URL, limpia bytes nulos, decodifica entidades HTML/Unicode
 * y genera vistas para inspección estructural.
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

  let decoded = input;
  for (let i = 0; i < 3; i += 1) {
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

  const noNulls = decoded.replace(/\0/g, '');
  const htmlDecoded = decodeEntitiesAndEscapes(noNulls);
  const compactControl = htmlDecoded.replace(/[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]+/g, '');
  const sqlEmptyComments = htmlDecoded.replace(/\/\*![0-9]*|\*\/|\/\*[\s\S]*?\*\//g, '');
  const sqlSpaceComments = htmlDecoded
    .replace(/\/\*![0-9]*|\*\//g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ');

  return { decoded, noNulls, htmlDecoded, compactControl, sqlEmptyComments, sqlSpaceComments };
}

/**
 * Extrae parámetros clave/valor de una query string y fragmentos estructurados de JSON.
 */
export function extractStructuredInputs({ rawUrl = '/', bodyText = '' }) {
  const params = []; // { key, value, source }
  const jsonKeys = []; // claves literales de objetos JSON (tras decodificar \u0024 por JSON.parse)
  const jsonKeyPaths = []; // ej. ['constructor', 'prototype']
  let rawPath = '/';
  let rawQuery = '';

  const qIdx = String(rawUrl).indexOf('?');
  if (qIdx !== -1) {
    rawPath = String(rawUrl).slice(0, qIdx);
    rawQuery = String(rawUrl).slice(qIdx + 1);
  } else {
    rawPath = String(rawUrl);
  }

  if (rawQuery) {
    // Divide por '&' respetando entidades HTML sin codificar (ej. &#x3C;script&#x3E;)
    for (const pair of rawQuery.split(/&(?!(?:#x?[0-9a-fA-F]{1,6}|[a-zA-Z]{2,10});)/)) {
      if (!pair) continue;
      const eq = pair.indexOf('=');
      const k = eq === -1 ? pair : pair.slice(0, eq);
      const v = eq === -1 ? '' : pair.slice(eq + 1);
      const nk = normalizePayloadMultiLayer(k).htmlDecoded;
      const nv = normalizePayloadMultiLayer(v).htmlDecoded;
      params.push({ key: nk, value: nv, rawValue: v, source: 'query' });
    }
  }

  const trimmedBody = String(bodyText || '').trim();
  if (trimmedBody) {
    if (trimmedBody.startsWith('{') || trimmedBody.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmedBody);
        const visit = (node, keyStack, depth) => {
          if (depth > 8 || node === null || node === undefined) return;
          if (typeof node === 'string') {
            params.push({
              key: keyStack[keyStack.length - 1] || '',
              value: decodeEntitiesAndEscapes(node),
              rawValue: node,
              source: 'json'
            });
          } else if (Array.isArray(node)) {
            for (const item of node.slice(0, 200)) visit(item, keyStack, depth + 1);
          } else if (typeof node === 'object') {
            // Object.getOwnPropertyNames captura también "__proto__" cuando viene en JSON.parse
            for (const k of Object.getOwnPropertyNames(node)) {
              const nextStack = [...keyStack, k];
              jsonKeys.push(k);
              jsonKeyPaths.push(nextStack);
              visit(node[k], nextStack, depth + 1);
            }
          }
        };
        visit(parsed, [], 0);
      } catch {
        params.push({ key: '', value: normalizePayloadMultiLayer(trimmedBody).htmlDecoded, rawValue: trimmedBody, source: 'body' });
      }
    } else if (/^[^=<>\s]+=.*/.test(trimmedBody) && !trimmedBody.startsWith('<')) {
      for (const pair of trimmedBody.split('&')) {
        if (!pair) continue;
        const eq = pair.indexOf('=');
        if (eq === -1) {
          params.push({ key: '', value: normalizePayloadMultiLayer(pair).htmlDecoded, rawValue: pair, source: 'form' });
        } else {
          const nk = normalizePayloadMultiLayer(pair.slice(0, eq)).htmlDecoded;
          const nv = normalizePayloadMultiLayer(pair.slice(eq + 1)).htmlDecoded;
          params.push({ key: nk, value: nv, rawValue: pair.slice(eq + 1), source: 'form' });
        }
      }
    } else {
      params.push({ key: '', value: normalizePayloadMultiLayer(trimmedBody).htmlDecoded, rawValue: trimmedBody, source: 'body' });
    }
  }

  return { rawPath, rawQuery, params, jsonKeys, jsonKeyPaths };
}

// ============================================================================
// 1. TOKENIZADOR LÉXICO SQL (Estructura gramatical, sin falsos positivos en prosa)
// ============================================================================
const SQL_KEYWORDS = new Set([
  'SELECT', 'UNION', 'ALL', 'DISTINCT', 'FROM', 'WHERE', 'INSERT', 'INTO', 'VALUES',
  'UPDATE', 'SET', 'DELETE', 'DROP', 'ALTER', 'TRUNCATE', 'TABLE', 'DATABASE',
  'ORDER', 'GROUP', 'BY', 'HAVING', 'LIMIT', 'OFFSET', 'WAITFOR', 'DELAY',
  'EXEC', 'EXECUTE', 'DECLARE', 'CAST', 'CONVERT', 'CONCAT', 'NULL', 'CASE', 'WHEN', 'THEN',
  'INFORMATION_SCHEMA', 'PG_SLEEP', 'SLEEP', 'BENCHMARK', 'EXTRACTVALUE', 'UPDATEXML',
  'ASCII', 'ORD', 'SUBSTR', 'SUBSTRING', 'MID', 'CHAR', 'HEX', 'UNHEX', 'LOAD_FILE', 'OUTFILE',
  'XP_CMDSHELL', 'VERSION', 'USER', 'DATABASE', 'SCHEMA'
]);

const SQL_BOOL_OPS = new Set(['OR', 'AND', 'XOR']);

function tokenizeSql(text) {
  const tokens = [];
  const s = String(text || '');
  let i = 0;
  const len = s.length;

  while (i < len && tokens.length < 300) {
    const ch = s[i];
    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }
    // Comentario SQL -- (requiere espacio, tab, fin de cadena o -- consecutivo para no confundir con --OFERTA)
    if (ch === '-' && s[i + 1] === '-' && (i + 2 >= len || /[\s\-]/.test(s[i + 2]))) {
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
      // Ignora apóstrofe inglés dentro de nombres tipo O'Neil / don't (letra antes Y letra después)
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
      // Leer literal si cierra antes de un operador booleano; si no, emitir QUOTE suelto
      let j = i + 1;
      while (j < len && s[j] !== quote) {
        if (s[j] === '\\') j += 2;
        else j += 1;
      }
      if (j < len && s[j] === quote) {
        const inner = s.slice(i + 1, j);
        // Si dentro de las comillas hay un pivote SQLi (ej. ' OR 'a'='a -> la cadena cerrada es " OR "),
        // emitir QUOTE para que el resto se tokenice como SQL!
        if (/^\s*(?:or|and|union|select|order|group|having|;)/i.test(inner)) {
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
    if (/[0-9]/.test(ch)) {
      let j = i;
      while (j < len && /[0-9.]/.test(s[j])) j += 1;
      tokens.push({ type: 'NUM', val: s.slice(i, j) });
      i = j;
      continue;
    }
    if (/[a-zA-Z_@$]/.test(ch)) {
      let j = i;
      while (j < len && /[a-zA-Z0-9_@$]/.test(s[j])) j += 1;
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
  const variants = [norm.sqlEmptyComments, norm.sqlSpaceComments];

  for (const text of variants) {
    const toks = tokenizeSql(text);
    const n = toks.length;
    if (n < 2) continue;

    for (let i = 0; i < n; i += 1) {
      const t = toks[i];

      // 1. Tautología booleana / comparación inyectada:
      //    (' | " | NUM | )) BOOL (NUM|STR|IDENT|QUOTE) CMP (NUM|STR|IDENT|QUOTE)
      //    Ej: ' OR 'a'='a, ' OR ''=', 1 OR 2=2, 1 AND 1=1, ) OR 1=1
      if (t.type === 'BOOL' && i > 0 && i + 2 < n) {
        const prev = toks[i - 1];
        const hasSqlPivot =
          prev.type === 'QUOTE' ||
          prev.type === 'NUM' ||
          prev.type === 'RPAREN' ||
          prev.type === 'STR';

        if (hasSqlPivot) {
          // Salta paréntesis de apertura opcionales tras OR/AND: OR (1=1)
          let k = i + 1;
          while (k < n && toks[k].type === 'LPAREN') k += 1;
          const lhs = toks[k];
          const cmp = toks[k + 1];
          const rhs = toks[k + 2];
          if (
            lhs &&
            cmp &&
            cmp.type === 'CMP' &&
            rhs &&
            ['NUM', 'STR', 'IDENT', 'QUOTE'].includes(lhs.type) &&
            ['NUM', 'STR', 'IDENT', 'QUOTE'].includes(rhs.type)
          ) {
            return true;
          }
          // Caso especial `' OR ''='` donde `''` se tokenizó como STR('') seguido de CMP('=') y QUOTE("'")
          if (lhs && lhs.type === 'STR' && cmp && cmp.type === 'CMP') {
            return true;
          }
          // Caso booleano + función blind/error: `1 AND ascii(substr(...))`, `1 AND extractvalue(...)`, `1 AND sleep(5)`
          if (
            lhs &&
            lhs.type === 'KW' &&
            ['ASCII', 'ORD', 'SUBSTR', 'SUBSTRING', 'MID', 'EXTRACTVALUE', 'UPDATEXML', 'SLEEP', 'PG_SLEEP', 'BENCHMARK'].includes(lhs.val) &&
            toks[k + 1]?.type === 'LPAREN'
          ) {
            return true;
          }
        }
      }

      // 2. UNION [ALL|DISTINCT] [(] SELECT con contexto SQL real (excluye prosa como "the union select committee met")
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
          const hasLeftPivot =
            !prev || ['NUM', 'QUOTE', 'RPAREN', 'STR', 'SEMI'].includes(prev.type);
          const rest = toks.slice(j + 1);
          const hasSqlClauseAfter =
            hadParen ||
            rest.some(
              (rt) =>
                rt.type === 'COMMA' ||
                rt.type === 'COMMENT' ||
                rt.type === 'LPAREN' ||
                rt.type === 'NUM' ||
                (rt.type === 'KW' && ['FROM', 'NULL', 'INFORMATION_SCHEMA', 'VERSION', 'USER', 'CONCAT'].includes(rt.val))
            );
          if (hasLeftPivot || hasSqlClauseAfter) {
            return true;
          }
        }
      }

      // 3. Stacked SQL queries tras punto y coma: `; SELECT ...`, `; DELETE FROM ...`, `; DROP TABLE ...`, `; INSERT INTO ...`, `; UPDATE ... SET`
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

      // 4. Funciones de tiempo / error / blind SQL con argumentos estrictamente SQL (NO "sleep (8 hours)")
      if (t.type === 'KW' && ['SLEEP', 'PG_SLEEP'].includes(t.val)) {
        if (
          toks[i + 1]?.type === 'LPAREN' &&
          toks[i + 2]?.type === 'NUM' &&
          toks[i + 3]?.type === 'RPAREN'
        ) {
          return true;
        }
      }
      if (t.type === 'KW' && t.val === 'BENCHMARK' && toks[i + 1]?.type === 'LPAREN' && toks[i + 2]?.type === 'NUM' && toks[i + 3]?.type === 'COMMA') {
        return true;
      }
      if (t.type === 'KW' && ['EXTRACTVALUE', 'UPDATEXML', 'XP_CMDSHELL', 'LOAD_FILE', 'INFORMATION_SCHEMA'].includes(t.val)) {
        if (t.val === 'INFORMATION_SCHEMA' || t.val === 'XP_CMDSHELL' || toks[i + 1]?.type === 'LPAREN') {
          return true;
        }
      }
      if (t.type === 'KW' && ['ASCII', 'ORD'].includes(t.val) && toks[i + 1]?.type === 'LPAREN') {
        if (toks[i + 2]?.type === 'KW' && ['SUBSTR', 'SUBSTRING', 'MID', 'SELECT'].includes(toks[i + 2].val)) {
          return true;
        }
      }
      if (t.type === 'KW' && t.val === 'WAITFOR' && toks[i + 1]?.type === 'KW' && toks[i + 1].val === 'DELAY') {
        return true;
      }

      // 5. Enumeración de columnas ORDER BY / GROUP BY N-- (con comentario SQL o pivote de inyección)
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

      // 6. Cierre de comilla seguido inmediatamente de comentario SQL válido (`admin'--`, `'#`, `admin'-- `)
      //    NOTA: `admin'--OFERTA` NO emite COMMENT porque `--` requiere espacio o fin de cadena.
      if (t.type === 'QUOTE' && toks[i + 1]?.type === 'COMMENT') {
        return true;
      }
    }
  }

  return false;
}

// ============================================================================
// 2. PARSER ESTRUCTURAL HTML / XSS (Cualquier evento on*= en etiqueta real; sin FP en libros)
// ============================================================================
const DANGEROUS_HTML_TAGS = new Set(['script', 'iframe', 'object', 'embed', 'applet', 'base']);

export function analyzeXssStructure(rawText, { isDirectUriParam = false } = {}) {
  if (!rawText || typeof rawText !== 'string') return false;
  const norm = normalizePayloadMultiLayer(rawText);
  const candidates = [norm.htmlDecoded, norm.compactControl];

  for (const text of candidates) {
    // 1. Escanea etiquetas HTML reales `<tagName ...>`
    const tagRegex = /<\s*([a-zA-Z][a-zA-Z0-9:-]{0,30})([\s\S]{0,600}?)>/g;
    let m;
    while ((m = tagRegex.exec(text)) !== null) {
      const tagName = m[1].toLowerCase();
      const attrs = m[2] || '';

      if (DANGEROUS_HTML_TAGS.has(tagName)) return true;

      // Cualquier atributo manejador de eventos HTML/SVG/Pointer/Focus/Animation (`on[a-z]+ =`)
      if (/(?:^|[\s/"'`])on[a-z]{2,26}\s*=/i.test(attrs)) return true;

      // Esquemas peligrosos dentro de atributos URI (`href`, `src`, `action`, `formaction`, `data`, `xlink:href`)
      if (
        /(?:href|src|action|formaction|xlink:href|data|poster)\s*=\s*["'`]?\s*(?:javascript|vbscript|data\s*:\s*(?:text\/html|image\/svg\+xml))/i.test(
          attrs.replace(/[\x00-\x20]+/g, (sp) => (sp.includes(' ') ? ' ' : ''))
        )
      ) {
        return true;
      }
    }

    // 2. Etiqueta <script sin cerrar (ej. `<script src=...`)
    if (/<\s*script\b/i.test(text)) return true;

    // 3. Esquema `javascript:` o `data:text/html` en valor de parámetro URI o con invocación JS real
    //    NO dispara sobre texto normal como "JavaScript: The Good Parts"
    const trimmed = text.trim();
    const compact = trimmed.replace(/[\x00-\x1f\t]+/g, '');
    if (/^data\s*:\s*(?:text\/html|image\/svg\+xml)/i.test(compact)) return true;
    if (/^(?:javascript|vbscript)\s*:/i.test(compact)) {
      const afterScheme = compact.replace(/^(?:javascript|vbscript)\s*:/i, '').trim();
      // Es XSS si contiene llamada JS/código (paréntesis, asignación, comentario JS, void, alert, eval, document, window, fetch, location)
      // o si viene en un parámetro URL explícito sin ser título de libro (palabras capitalizadas separadas por espacios)
      const looksLikeCode = /[();={}[\]`]|\/\/|\/\*|\b(?:alert|prompt|confirm|eval|void|document|window|location|fetch|import)\b/i.test(afterScheme);
      if (looksLikeCode || (isDirectUriParam && !/^[A-Z][a-z]+(?:\s+[A-Za-z]+){1,6}$/.test(afterScheme))) {
        return true;
      }
    }

    // 4. Skimming / exfiltración JS explícita
    if (/\bdocument\.cookie\b|\beval\s*\(\s*atob\s*\(|crypto-clipper|wallet_swap_skimmer/i.test(text)) {
      return true;
    }

    // 5. AngularJS / Client-side Template Injection (`{{constructor.constructor(...)}}`)
    if (/\{\{[\s\S]{0,120}\bconstructor\b[\s\S]{0,120}\}\}/i.test(text)) {
      return true;
    }
  }

  return false;
}

// ============================================================================
// 3. EXTRACTOR CANÓNICO SSRF (http/https/gopher/dict/file, //, http:\\, nip.io/sslip.io + BlockList)
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

  // Detecta servicios wildcard de DNS rebinding (nip.io, sslip.io, xip.io, localtest.me, lvh.me)
  if (DNS_REBIND_SUFFIXES.some((sfx) => lower.endsWith(sfx) || lower === sfx.slice(1))) {
    // Extrae cualquier IPv4 incrustada con puntos o guiones o bloquea directamente si es localtest.me/lvh.me
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

export function analyzeSsrfStructure(rawText, { isUrlParamValue = false } = {}) {
  if (!rawText || typeof rawText !== 'string') return false;
  const text = normalizePayloadMultiLayer(rawText).htmlDecoded;

  if (/169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200/i.test(text)) {
    return true;
  }

  // Esquemas estándar y con barras invertidas (`http:\\127.0.0.1`, `http:/\127.0.0.1`)
  const schemeRegex = /(?:https?|gopher|dict|ftp|ldap|file):[\/\\]{1,3}([^\s"'<>/?#\\]+)/gi;
  let m;
  while ((m = schemeRegex.exec(text)) !== null) {
    if (isBlockedSsrfHost(m[1])) return true;
  }

  // URL protocol-relative (`//127.0.0.1`, `//[::1]`, `//localhost/admin`) en valor de parámetro o tras `=`
  if (isUrlParamValue) {
    const trimmed = text.trim();
    if (/^[\/\\]{2}([^\s"'<>/?#\\]+)/.test(trimmed)) {
      const host = trimmed.match(/^[\/\\]{2}([^\s"'<>/?#\\]+)/)[1];
      if (isBlockedSsrfHost(host)) return true;
    }
    // También host directo en parámetro URL (ej. `url=127.0.0.1.nip.io/admin`)
    const bareHost = trimmed.split(/[/?#]/)[0];
    if (bareHost && isBlockedSsrfHost(bareHost)) return true;
  } else {
    const protoRelParam = /(?:=|:\s*["'])[\/\\]{2}([^\s"'<>/?#\\]+)/g;
    while ((m = protoRelParam.exec(text)) !== null) {
      if (isBlockedSsrfHost(m[1])) return true;
    }
  }

  return false;
}

// ============================================================================
// 4. ANALIZADOR ESTRUCTURAL RCE / COMMAND INJECTION / LOG4SHELL / SPEL
// ============================================================================
const SHELL_CMDS =
  '(?:sh|bash|zsh|dash|ksh|csh|cat|id|whoami|uname|sleep|curl|wget|nc|ncat|netcat|socat|python|python3|perl|ruby|php|awk|env|printenv|ping|nslookup|dig|chmod|chown|mkfifo|telnet|certutil|powershell|cmd\\.exe)';

export function analyzeRceStructure(rawText) {
  if (!rawText || typeof rawText !== 'string') return false;
  const norm = normalizePayloadMultiLayer(rawText);

  for (const base of [rawText, norm.htmlDecoded]) {
    // 1. Log4Shell / JNDI / Expression Language (cualquier lookup anidado o lookup conocido, incl. ${date:'j'} y SpEL ${T(...)})
    if (/\$\{(?:jndi|env|lower|upper|sys|java|date|ctx|base64|spring|k8s|docker|bundle|main|sd|log4j):/i.test(base)) {
      return true;
    }
    if (/\$\{[^}]{0,120}\$\{[^}]{1,120}\}/i.test(base)) {
      return true;
    }
    if (/[$#]\{\s*T\s*\(\s*[a-zA-Z0-9_.$]+\s*\)/i.test(base)) {
      return true;
    }

    // 2. Des-ofuscación de comillas vacías/partidas de shell (`c'u'rl` -> `curl`, `b"a"sh` -> `bash`, `w\get` -> `wget`)
    const deobfuscated = base
      .replace(/(?<=[a-zA-Z0-9_/.-])['"\\]+(?=[a-zA-Z0-9_/.-])/g, '')
      .replace(/\$\{IFS\}/g, ' ')
      .replace(/\$IFS\b/g, ' ');

    for (const candidate of [base, deobfuscated]) {
      // 3. Sustitución de comandos `$(cmd ...)` o backticks `` `cmd ...` ``
      const subCmdRx = new RegExp(`\\$\\(\\s*(?:\\/bin\\/|\\/usr\\/bin\\/)?${SHELL_CMDS}(?:\\s|\\)|$)`, 'i');
      const tickCmdRx = new RegExp('`\\s*(?:\\/bin\\/|\\/usr\\/bin\\/)?' + SHELL_CMDS + '(?:\\s|`)', 'i');
      if (subCmdRx.test(candidate) || tickCmdRx.test(candidate)) return true;

      // 4. Encadenamiento de comandos tras `;`, `|`, `||`, `&&`, o salto de línea (`\n`, `\r`)
      //    Cubre `;curl evil|sh`, `\nid`, `%0aid`, `| bash`, `&& whoami`, `; nc 1.2.3.4 4444 -e /bin/sh`
      //    Sin falsos positivos en `"; id del pedido 4432"` (para `id`, exige fin/delimitador/flag, NO palabras en prosa)
      const sepCmdRx = new RegExp(
        `(?:;|\\|\\||&&|\\||[\\r\\n]+)\\s*(?:\\/bin\\/|\\/usr\\/bin\\/)?(?:` +
          `(?:bash|zsh|sh)(?:\\s|$|;|\\||&)|` +
          `id(?:\\s*(?:$|[;|&\r\n>]|-[a-zA-Z]))|` +
          `(?:whoami|uname)(?:\\s|$|[;|&\r\n>])|` +
          `(?:curl|wget)\\s+\\S+|` +
          `cat\\s+\\/|sleep\\s+\\d+|` +
          `(?:nc|ncat|netcat)\\s+[^\\r\\n]{1,120}(?:-e|-c)\\s*\\S+|` +
          `(?:python3?|perl|php|ruby)\\s+-[ce]\\s+` +
        `)`,
        'i'
      );
      if (sepCmdRx.test(candidate)) return true;

      // 5. Reverse shell / binarios explícitos
      if (/(?:^|\s)(?:nc|ncat|netcat)\s+[^\r\n]{1,120}-e\s+\/bin\/(?:sh|bash)\b/i.test(candidate)) return true;
      if (/\bcmd\.exe\s+\/c\b|\bpowershell(?:\.exe)?\s+-(?:enc|encodedcommand|nop)\b/i.test(candidate)) return true;
      if (/java4shell|avx512_vbmi_overflow/i.test(candidate)) return true;
      if (candidate.includes('===') && /(?:^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={3,}/.test(candidate)) return true;
    }
  }
  return false;
}

// ============================================================================
// 5. ANALIZADOR ESTRUCTURAL LFI / TRAVERSAL (1 solo ../ incluido; sin FP en soporte "/etc/hosts")
// ============================================================================
export function analyzeLfiStructure(rawText, { isFreeProseBody = false } = {}) {
  if (!rawText || typeof rawText !== 'string') return false;
  const text = normalizePayloadMultiLayer(rawText).htmlDecoded;

  // Cualquier secuencia de path traversal (`../` o `..\`), incluso un solo nivel
  if (/(?:^|[\s="'/?&\\])(?:\.\.[/\\])+[a-zA-Z0-9._/-]/i.test(text) || /(?:\.\.[/\\]){2,}/.test(text)) {
    return true;
  }

  // Wrappers de flujo de archivos peligrosos
  if (/\b(?:php|expect|phar|zip):\/\/(?:filter|input|resource|fd)/i.test(text)) return true;
  if (/\bdata:\/\/[a-z0-9/+.-]*;base64,/i.test(text)) return true;
  if (/\bfile:\/\/\/(?:etc|proc|var|windows|boot)/i.test(text)) return true;

  // Rutas OS críticas: si viene en URL/parámetro o empieza con ruta absoluta, bloquear siempre;
  // en prosa libre de soporte, "/etc/hosts" solo NO debe bloquear al cliente ("Edite /etc/hosts y no funciona")
  if (/\/etc\/(?:passwd|shadow)\b|\/proc\/(?:self|\d+)\/(?:environ|cmdline|maps|fd)\b|\/var\/www\/[^\s"'<>]*\.(?:env|php|sql|bak|config)\b|c:\\windows\\win\.ini/i.test(text)) {
    return true;
  }
  if (!isFreeProseBody && /^\/etc\/hosts$/i.test(text.trim())) {
    return true;
  }

  return false;
}

// ============================================================================
// 6. ANALIZADOR SSTI / NoSQL / XXE / PROTOTYPE POLLUTION
// ============================================================================
export function analyzeExtrasStructure({ rawTexts = [], jsonKeys = [], jsonKeyPaths = [], params = [] }) {
  // 1. NoSQL & Prototype Pollution sobre claves reales de JSON (ya decodificadas de \u0024 por JSON.parse!)
  for (const k of jsonKeys) {
    if (NOSQL_OPERATORS.has(k)) return true;
    if (k === '__proto__') return true;
  }
  for (const stack of jsonKeyPaths) {
    for (let i = 0; i < stack.length - 1; i += 1) {
      if (stack[i] === 'constructor' && stack[i + 1] === 'prototype') return true;
    }
  }

  // 2. Parámetros de query para NoSQL (`pass[$ne]=`, `id[$in][]=`) y Prototype Pollution (`__proto__[x]`, `constructor[prototype][x]`)
  for (const p of params) {
    const k = String(p.key || '');
    if (/\[\s*\$(?:ne|eq|gt|gte|lt|lte|in|nin|where|regex|exists)\s*\]/i.test(k)) return true;
    if (/(?:^|[\[.])__proto__(?:[\].]|$)|constructor(?:\.|\[)prototype/i.test(k)) return true;
  }

  // 3. SSTI, XXE, Prototype Pollution y NoSQL textual en cadenas
  for (const raw of rawTexts) {
    if (!raw || typeof raw !== 'string') continue;
    const text = normalizePayloadMultiLayer(raw).htmlDecoded;

    // SSTI (Jinja2, Twig, ERB, Freemarker, SpEL, Angular)
    if (
      /\{\{[\s\S]{0,160}(?:\d+\s*[*+-/]\s*\d+|__class__|__mro__|__subclasses__|__globals__|__builtins__|config\.|self\.|request\.|cycler\.|lipsum\.|constructor)/i.test(text) ||
      /<%=\s*[^%]{1,80}%>/.test(text) ||
      /[$#]\{\s*T\s*\(/i.test(text)
    ) {
      return true;
    }

    // XXE
    if (/<!\s*(?:ENTITY\b|DOCTYPE[^>]+(?:SYSTEM|PUBLIC|ENTITY)\b)/i.test(text)) return true;

    // Prototype Pollution textual
    if (/(?:^|[.?&["'{\s])__proto__(?:[\]"'}=:\s.]|$)|constructor\s*(?:\.\s*prototype|\[\s*["']prototype["']\s*\])/i.test(text)) {
      return true;
    }

    // NoSQL en texto plano / query / JSON crudo (tras decodificar \u0024)
    if (/(?:"|\[)\s*\$(?:ne|gt|gte|lt|lte|in|nin|where|regex|exists)\s*(?:"|\])/i.test(text)) {
      return true;
    }
  }

  return false;
}
