/**
 * @fileoverview Motor WAF v5.0 de Inspección Profunda de Paquetes (DPI),
 * Normalización Multicapa Anti-Evasión (URL + HTML Entities + JSON recursivo + SQL Comments),
 * Bloqueador SSRF Canónico con net.BlockList, Canarios No-Anclados y Rate-Limiter Comportamental.
 * Sin estado global a nivel de módulo (L-05) y calibrado contra falsos positivos (H-05).
 */

import net from 'node:net';

export const CANARY_PATHS = [
  '/.env',
  '/.env.prod',
  '/.env.local',
  '/.env.backup',
  '/.env.staging',
  '/.git/config',
  '/.git/HEAD',
  '/.aws/credentials',
  '/.ssh/id_rsa',
  '/.ssh/id_rsa.pub',
  '/.kube/config',
  '/.htaccess',
  '/.DS_Store',
  '/wp-config.php.bak',
  '/wp-config.php~',
  '/config.php.bak',
  '/web.config.bak',
  '/sftp-config.json',
  '/docker-compose.yml',
  '/backup/db_master_2026.sql',
  '/dump.sql',
  '/wp-admin/setup-config.php',
  '/xmlrpc.php',
  '/phpmyadmin/',
  '/pma/',
  '/admin-legacy-portal',
  '/actuator/env',
  '/actuator/heapdump',
  '/api/v1/internal/admin-keys',
  '/api/v2/debug/token-vault',
  '/api/v1/cloud-credentials',
  '/api/v1/users/export',
  '/graphql/schema-dump.json',
  '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
  '/debug/pprof/',
  '/server-status',
  '/solr/admin/info/system',
  '/cgi-bin/luci',
  '/boaform/admin/formLogin',
  '/telescope/requests',
  '/_ignition/execute-solution',
  '/swagger-ui.html',
  '/elmah.axd'
];

export const DEFAULT_WAF_RULES = {
  sqlInjection: true,
  xssSkimming: true,
  pathTraversal: true,
  ssrfMetadata: true,
  rceJava4Shell: true,
  sstiNosqlXxeProto: true,
  behavioralRateLimit: true,
  rateLimitMaxPer10s: 25,
  autoQuarantineThreshold: 85
};

/**
 * Patrones de rutas sensibles NO anclados al inicio (H-01):
 * detectan /app/.env, /repo/.git/config, /.env/, /.env;.css, /wp-config.php~, etc.
 */
const SENSITIVE_FAMILY_PATTERNS = [
  /(?:^|\/)\.env(?:[._;/-].*)?$/i,
  /(?:^|\/)\.git(?:\/|;|$)/i,
  /(?:^|\/)\.aws(?:\/|;|$)/i,
  /(?:^|\/)\.ssh(?:\/|;|$)/i,
  /(?:^|\/)\.kube(?:\/|;|$)/i,
  /(?:^|\/)\.htaccess(?:;|\/|$)/i,
  /\.(?:bak|old|swp|swo|sql|dump|orig|save)(?:;|\/|$)/i,
  /(?:wp-config|config|settings|database|secrets)\.(?:php|yml|yaml|json|ini|xml)~(?:;|\/|$)/i,
  /(?:^|\/)(?:wp-admin\/setup-config|xmlrpc\.php|phpmyadmin|pma(?:\/|$)|actuator\/|debug\/pprof|vendor\/phpunit)/i
];

const RESERVED_CONTROL_PATHS = new Set([
  '/',
  '/soc',
  '/index.html',
  '/robots.txt',
  '/guardianes-sensor.js',
  '/guardianes/check',
  '/telemetry-beacon',
  '/events'
]);

/**
 * BlockList canónica de red para SSRF (RFC1918, loopback, link-local, IMDS AWS/GCP/Alibaba, IPv6 ULA/link-local).
 */
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

/**
 * Decodifica entidades HTML numéricas (hex/dec) y con nombre comunes para neutralizar XSS ofuscado.
 */
function decodeHtmlEntities(str) {
  if (!str || !str.includes('&')) return str;
  const named = {
    lt: '<',
    gt: '>',
    quot: '"',
    apos: "'",
    amp: '&',
    tab: '\t',
    newline: '\n',
    colon: ':'
  };
  return str
    .replace(/&#x([0-9a-fA-F]{1,6});?/g, (_, hex) => {
      const code = parseInt(hex, 16);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    })
    .replace(/&#([0-9]{1,7});?/g, (_, dec) => {
      const code = parseInt(dec, 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    })
    .replace(/&([a-zA-Z]{2,10});/g, (m, name) => named[name.toLowerCase()] ?? m);
}

/**
 * Normaliza entradas hasta 3 capas de URL-decoding, decodifica entidades HTML,
 * limpia bytes nulos y genera variantes sin comentarios SQL inline y sin tabs/controles para XSS.
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
      // Decodificación parcial segura si hay secuencias % malformadas mezcladas con válidas
      const partial = decoded.replace(/%([0-9a-fA-F]{2})/g, (_, h) =>
        String.fromCharCode(parseInt(h, 16))
      );
      if (partial === decoded) break;
      decoded = partial;
    }
  }

  const noNulls = decoded.replace(/\0/g, '');
  const htmlDecoded = decodeHtmlEntities(noNulls);
  const compactControl = htmlDecoded.replace(/[\x00-\x1f\x7f]+/g, '');
  const sqlEmptyComments = htmlDecoded.replace(/\/\*![0-9]*|\*\/|\/\*[\s\S]*?\*\//g, '');
  const sqlSpaceComments = htmlDecoded
    .replace(/\/\*![0-9]*|\*\//g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ');

  return { decoded, noNulls, htmlDecoded, compactControl, sqlEmptyComments, sqlSpaceComments };
}

/**
 * Extrae recursivamente claves y valores de strings en un cuerpo JSON (depth-limited).
 */
function extractJsonFragments(rawText, maxDepth = 6) {
  if (!rawText || typeof rawText !== 'string') return [];
  const trimmed = rawText.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return [];
  try {
    const parsed = JSON.parse(trimmed);
    const fragments = [];
    const visit = (node, depth) => {
      if (depth > maxDepth || fragments.length > 200 || node === null || node === undefined) return;
      if (typeof node === 'string') {
        fragments.push(node);
      } else if (Array.isArray(node)) {
        for (const item of node) visit(item, depth + 1);
      } else if (typeof node === 'object') {
        for (const [k, v] of Object.entries(node)) {
          fragments.push(k);
          if (typeof v === 'string') fragments.push(`${k}=${v}`);
          visit(v, depth + 1);
        }
      }
    };
    visit(parsed, 0);
    return fragments;
  } catch {
    return [];
  }
}

/**
 * Convierte representaciones ofuscadas de IPv4 (decimal 2852039166, hex 0xA9FEA9FE,
 * octal 0251.0376.0251.0376, o abreviadas 127.1 / 10.1) a su forma canónica IPv4.
 */
export function canonicalizeObfuscatedIp(rawHost) {
  if (!rawHost || typeof rawHost !== 'string') return null;
  let host = rawHost.trim().toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }
  if (!host) return null;

  // IPv6 directo o IPv4-mapped (ej. ::ffff:169.254.169.254 o ::ffff:a9fe:a9fe)
  if (net.isIPv6(host)) {
    const v4MappedDec = host.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
    if (v4MappedDec && net.isIPv4(v4MappedDec[1])) {
      return { ip: v4MappedDec[1], family: 'ipv4' };
    }
    const v4MappedHex = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
    if (v4MappedHex) {
      const hi = parseInt(v4MappedHex[1], 16);
      const lo = parseInt(v4MappedHex[2], 16);
      const ip = `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
      return { ip, family: 'ipv4' };
    }
    return { ip: host, family: 'ipv6' };
  }

  // IPv4 estándar
  if (net.isIPv4(host)) {
    return { ip: host, family: 'ipv4' };
  }

  // IPv4 abreviado / decimal / hexadecimal / octal (1 a 4 partes separadas por punto)
  const parts = host.split('.');
  if (parts.length >= 1 && parts.length <= 4) {
    const nums = [];
    for (const part of parts) {
      if (!part) return null;
      let n;
      if (/^0x[0-9a-f]+$/i.test(part)) {
        n = parseInt(part.slice(2), 16);
      } else if (/^0[0-7]+$/.test(part)) {
        n = parseInt(part, 8);
      } else if (/^\d+$/.test(part)) {
        n = parseInt(part, 10);
      } else {
        return null;
      }
      if (!Number.isFinite(n) || n < 0 || n > 0xffffffff) return null;
      nums.push(n);
    }

    let ipv4Int = 0;
    if (nums.length === 1) {
      ipv4Int = nums[0];
    } else if (nums.length === 2) {
      if (nums[0] > 255 || nums[1] > 0xffffff) return null;
      ipv4Int = ((nums[0] << 24) >>> 0) + nums[1];
    } else if (nums.length === 3) {
      if (nums[0] > 255 || nums[1] > 255 || nums[2] > 0xffff) return null;
      ipv4Int = ((nums[0] << 24) >>> 0) + (nums[1] << 16) + nums[2];
    } else {
      if (nums.some((x) => x > 255)) return null;
      ipv4Int = ((nums[0] << 24) >>> 0) + (nums[1] << 16) + (nums[2] << 8) + nums[3];
    }

    const ip = [
      (ipv4Int >>> 24) & 255,
      (ipv4Int >>> 16) & 255,
      (ipv4Int >>> 8) & 255,
      ipv4Int & 255
    ].join('.');
    return { ip, family: 'ipv4' };
  }

  return null;
}

/**
 * Evalúa si alguna URL incrustada en el texto apunta a un destino SSRF interno o de metadatos cloud.
 */
export function hasSsrfTargetInText(text) {
  if (!text || typeof text !== 'string') return false;
  if (/169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200/i.test(text)) {
    return true;
  }

  const urlRegex = /(?:https?|gopher|dict|ftp):\/\/([^\s"'<>/?#]+)/gi;
  let match;
  while ((match = urlRegex.exec(text)) !== null) {
    let authority = match[1];
    // Elimina userinfo@ si existe
    const atIdx = authority.lastIndexOf('@');
    if (atIdx !== -1) authority = authority.slice(atIdx + 1);

    // Extrae hostname manejando [IPv6]:port y host:port
    let host = authority;
    if (host.startsWith('[')) {
      const endBracket = host.indexOf(']');
      if (endBracket !== -1) host = host.slice(0, endBracket + 1);
    } else {
      const colonIdx = host.indexOf(':');
      if (colonIdx !== -1) host = host.slice(0, colonIdx);
    }

    const lowerHost = host.toLowerCase().replace(/\.$/, '');
    if (!lowerHost) continue;

    if (SSRF_BLOCKED_HOSTNAMES.has(lowerHost) || lowerHost.endsWith('.internal') || lowerHost.endsWith('.local')) {
      return true;
    }

    // Intenta parsear a través de WHATWG URL y nuestro decodificador canónico de IP ofuscada
    const parsedIp = canonicalizeObfuscatedIp(lowerHost);
    if (parsedIp && SSRF_BLOCKLIST.check(parsedIp.ip, parsedIp.family)) {
      return true;
    }
    try {
      const u = new URL(`http://${authority}/`);
      const uHost = u.hostname.toLowerCase();
      if (SSRF_BLOCKED_HOSTNAMES.has(uHost)) return true;
      const uIp = canonicalizeObfuscatedIp(uHost);
      if (uIp && SSRF_BLOCKLIST.check(uIp.ip, uIp.family)) {
        return true;
      }
    } catch {
      // ignora URL malformada
    }
  }
  return false;
}

export function validateCustomCanaryPath(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') return null;
  const cleaned = rawPath.trim().split('?')[0].replace(/\/+/g, '/');
  const prefixed = cleaned.startsWith('/') ? cleaned : `/${cleaned}`;
  const lower = prefixed.toLowerCase();
  if (!/^\/[a-zA-Z0-9._/-]{2,80}$/.test(prefixed)) return null;
  if (prefixed.includes('..')) return null;
  if (RESERVED_CONTROL_PATHS.has(lower) || lower.startsWith('/api/guardianes')) return null;
  return lower;
}

export function validateCustomWafKeyword(rawKeyword) {
  if (!rawKeyword || typeof rawKeyword !== 'string') return null;
  const cleaned = rawKeyword.trim().toLowerCase();
  if (cleaned.length < 3 || cleaned.length > 80) return null;
  if (/^[\s.*+?^${}()|[\]\\/-]+$/.test(cleaned)) return null;
  return cleaned;
}

/**
 * Normaliza rutas (dobles barras, parámetros matrix ';.css', barra final, URL-encoding)
 * y detecta los 43+ canarios, rutas personalizadas y familias sensibles en cualquier subruta.
 */
export function isCanaryOrSensitivePath(rawPath = '/', extraCanaries = []) {
  const pathOnly = String(rawPath).split('?')[0];
  const { noNulls } = normalizePayloadMultiLayer(pathOnly);
  // Elimina matrix params tipo /.env;.css antes de comparar
  const withoutMatrix = noNulls.replace(/;[^/]*/g, '');
  const collapsed = withoutMatrix.replace(/\\+/g, '/').replace(/\/+/g, '/').trim();
  const normalized = collapsed.startsWith('/') ? collapsed : `/${collapsed}`;
  const trimmedTrailing = normalized.length > 1 ? normalized.replace(/\/+$/, '') : normalized;
  const lower = normalized.toLowerCase();
  const lowerTrimmed = trimmedTrailing.toLowerCase();

  if (
    CANARY_PATHS.some((c) => {
      const cl = c.toLowerCase();
      const clTrim = cl.length > 1 ? cl.replace(/\/+$/, '') : cl;
      return cl === lower || clTrim === lowerTrimmed;
    })
  ) {
    return true;
  }

  if (
    Array.isArray(extraCanaries) &&
    extraCanaries.some((c) => {
      const cl = String(c).toLowerCase().replace(/\/+$/, '');
      return cl === lowerTrimmed;
    })
  ) {
    return true;
  }

  return (
    SENSITIVE_FAMILY_PATTERNS.some((rx) => rx.test(normalized)) ||
    SENSITIVE_FAMILY_PATTERNS.some((rx) => rx.test(trimmedTrailing))
  );
}

const DPI_SIGNATURES = {
  SQL_INJECTION: {
    ruleKey: 'sqlInjection',
    score: 94,
    patterns: [
      /\bunion\s*(?:(?:all|distinct)\s*)?(?:\(\s*)?select\b/i,
      /\bun(?:\/\*[\s\S]*?\*\/)*ion(?:\s+|\/\*[\s\S]*?\*\/|\()+(?:(?:all|distinct)(?:\s+|\/\*[\s\S]*?\*\/)+)?sel(?:\/\*[\s\S]*?\*\/)*ect\b/i,
      /(?:'|")\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|'[^']{1,32}'\s*=\s*'[^']{1,32}'?|"[^"]{1,32}"\s*=\s*"[^"]{1,32}"?)/i,
      /\b(?:or|and)\s+1\s*=\s*1\b/i,
      /(?:^|[=:\s(])(?:admin|root|user|test)'\s*(?:--|#)/i,
      /'\s*(?:--|#|;)\s*(?:$|select|drop|union|delete|update|insert)/i,
      /\binformation_schema\b/i,
      /\b(?:sleep|pg_sleep|benchmark)\s*\(\s*\d+/i,
      /\b(?:extractvalue|updatexml)\s*\(/i,
      /\bwaitfor\s+delay\b/i,
      /\bxp_cmdshell\b/i,
      /;\s*(?:drop|truncate|alter)\s+table\b/i
    ]
  },
  XSS_AND_SCRIPT_SKIMMING: {
    ruleKey: 'xssSkimming',
    score: 90,
    patterns: [
      /<\s*script\b/i,
      /\bjavascript\s*:/i,
      /<\s*(?:svg|img|iframe|object|embed|details|animate|body|marquee|video|audio)\b[^>]*\bon[a-z]{3,20}\s*=/i,
      /\bon(?:error|load|mouseover|focus|toggle|begin|click|animationstart|pointerenter)\s*=/i,
      /\bdocument\.cookie\b/i,
      /\beval\s*\(\s*atob\s*\(/i,
      /crypto-clipper|wallet_swap_skimmer/i
    ]
  },
  PATH_TRAVERSAL_LFI: {
    ruleKey: 'pathTraversal',
    score: 92,
    patterns: [
      /(?:\.\.[/\\]){1,}(?:\.env|\.git|etc\/|proc\/|var\/www|windows\/|boot\.ini|web\.config|wp-config)/i,
      /(?:\.\.[/\\]){2,}/,
      /%2e%2e(?:%2f|%5c|\/|\\)/i,
      /\/etc\/(?:passwd|shadow|hosts|issue)\b/i,
      /\/proc\/(?:self|\d+)\/(?:environ|cmdline|maps|fd)\b/i,
      /\/var\/www\/[^\s"'<>]*\.(?:env|php|sql|bak|config)\b/i,
      /c:\\windows\\win\.ini/i,
      /\b(?:php|expect):\/\/(?:filter|input|resource)/i,
      /\bdata:\/\/[a-z0-9/+.-]*;base64,/i
    ]
  },
  RCE_AND_JAVA4SHELL_LOG4SHELL: {
    ruleKey: 'rceJava4Shell',
    score: 99,
    patterns: [
      /\$\{(?:jndi|env|lower|upper|sys|base64):/i,
      /\$\{[^}]*\$\{[^}]*::-?[a-z]/i,
      /\$\(\s*(?:whoami|id\b|cat\s+\/|uname\b|ls\s+-|curl\s+|wget\s+|bash\b|sh\b)/i,
      /`\s*(?:whoami|id|uname|cat\s+\/etc\/passwd)\s*`/i,
      /(?:;|\|\||&&|\|)\s*(?:cat\s+\/|bash\b|sh\s+-c\b|whoami\b|id(?:\s*(?:$|;|\||&|>|-u|-g|-a))|curl\s+http|wget\s+http|nc\s+-e|python3?\s+-c\b)/i,
      /\bcmd\.exe\s+\/c\b/i,
      /\bpowershell(?:\.exe)?\s+-(?:enc|encodedcommand|nop)/i,
      /java4shell|avx512_vbmi_overflow/i
    ]
  },
  SSTI_NOSQL_XXE_PROTO: {
    ruleKey: 'sstiNosqlXxeProto',
    score: 93,
    patterns: [
      /\{\{\s*(?:\d+\s*[*+-/]\s*\d+|config\.|self\.|request\.|cycler\.|lipsum\.|__class__|__mro__|__subclasses__)/i,
      /(?:"|\[\s*)\$(?:ne|gt|gte|lt|lte|where|regex|nin|exists)\b(?:"|\s*\])/i,
      /<!\s*(?:ENTITY|DOCTYPE[^>]+(?:SYSTEM|PUBLIC|ENTITY))\b/i,
      /(?:^|[.?&["'{\s])__proto__(?:[\]"'}=:\s.]|$)|constructor\s*\.\s*prototype\b/i
    ]
  }
};

// Cabeceras estándar de navegador que rara vez necesitan inspección cuando contienen valores largos inocuos,
// pero TODAS las cabeceras relevantes (incluyendo User-Agent, Cookie, X-Forwarded-For, Referer, etc.) SÍ se inspeccionan.
const IGNORED_HEADER_NAMES = new Set([
  'host',
  'connection',
  'content-length',
  'accept-encoding',
  'accept-language',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
  'sec-fetch-site',
  'sec-fetch-mode',
  'sec-fetch-dest',
  'upgrade-insecure-requests'
]);

/**
 * Inspecciona URL, query, TODAS las cabeceras relevantes (incluyendo User-Agent, Cookie, X-Forwarded-For)
 * y cuerpo (incluyendo extracción recursiva JSON) con normalización multicapa.
 */
export function inspectPayloadDPI({
  rawUrl = '/',
  headers = {},
  bodyText = '',
  wafRules = DEFAULT_WAF_RULES,
  customKeywords = []
}) {
  const rules = { ...DEFAULT_WAF_RULES, ...(wafRules || {}) };

  const headerValues = [];
  if (headers && typeof headers === 'object') {
    for (const [name, value] of Object.entries(headers)) {
      if (IGNORED_HEADER_NAMES.has(name.toLowerCase())) continue;
      if (value === undefined || value === null) continue;
      const str = Array.isArray(value) ? value.join(' ') : String(value);
      if (str) headerValues.push(str);
    }
  }

  const jsonFragments = extractJsonFragments(bodyText);
  const rawTargets = [rawUrl, bodyText, ...headerValues, ...jsonFragments].filter(Boolean);
  const targets = [];

  for (const item of rawTargets) {
    const norm = normalizePayloadMultiLayer(String(item));
    targets.push(
      String(item),
      norm.noNulls,
      norm.htmlDecoded,
      norm.compactControl,
      norm.sqlEmptyComments,
      norm.sqlSpaceComments
    );
  }

  const vectors = [];
  let maxScore = 0;

  for (const [vectorName, def] of Object.entries(DPI_SIGNATURES)) {
    if (!rules[def.ruleKey]) continue;
    const matched = targets.some((txt) => def.patterns.some((rx) => rx.test(txt)));
    if (matched) {
      vectors.push(vectorName);
      if (def.score > maxScore) maxScore = def.score;
    }
  }

  // SSRF con parser canónico + net.BlockList (cubre decimal, hex, octal, IPv6-mapped, IMDS, RFC1918)
  if (rules.ssrfMetadata) {
    const ssrfFound = targets.some((txt) => hasSsrfTargetInText(txt));
    if (ssrfFound) {
      vectors.push('SSRF_AND_CLOUD_METADATA');
      maxScore = Math.max(maxScore, 96);
    }
  }

  // Reglas dinámicas por instancia creadas por el operador mediante Comandante Hermes
  const allCustomKeywords = Array.isArray(customKeywords) ? customKeywords.filter(Boolean) : [];
  if (allCustomKeywords.length > 0) {
    const lowerTargets = targets.map((t) => String(t).toLowerCase());
    const customMatched = allCustomKeywords.some((kw) =>
      lowerTargets.some((txt) => txt.includes(String(kw).toLowerCase()))
    );
    if (customMatched) {
      vectors.push('CUSTOM_HERMES_RULE');
      maxScore = Math.max(maxScore, 93);
    }
  }

  // Detección heurística acotada de Base64 sobredimensionado malformado (sin falsos positivos en "=====" - H-05)
  if (rules.rceJava4Shell) {
    const hasMalformedBase64 = targets.some((txt) => /(?:[A-Za-z0-9+/]{120,}={3,})/.test(txt));
    if (hasMalformedBase64) {
      if (!vectors.includes('RCE_AND_JAVA4SHELL_LOG4SHELL')) {
        vectors.push('RCE_AND_JAVA4SHELL_LOG4SHELL');
      }
      maxScore = Math.max(maxScore, 95);
    }
  }

  return {
    malicious: vectors.length > 0,
    vectors,
    riskScore: maxScore
  };
}

/**
 * Rate Limiter Comportamental por ventana deslizante (10 segundos).
 */
export class BehavioralRateLimiter {
  constructor() {
    this.buckets = new Map();
  }

  recordRequest(ip, { windowMs = 10_000, threshold = 25 } = {}) {
    const now = Date.now();
    const key = String(ip || '127.0.0.1');
    let timestamps = this.buckets.get(key) || [];
    timestamps = timestamps.filter((ts) => now - ts <= windowMs);
    timestamps.push(now);

    if (this.buckets.size > 4000) {
      const oldestKey = this.buckets.keys().next().value;
      if (oldestKey) this.buckets.delete(oldestKey);
    }

    this.buckets.set(key, timestamps);
    return {
      countInWindow: timestamps.length,
      isBurst: timestamps.length > threshold
    };
  }

  reset() {
    this.buckets.clear();
  }
}
