/**
 * @fileoverview Motor WAF v3.1 de Inspección Profunda de Paquetes (DPI),
 * Normalización Multicapa Anti-Evasión, 42+ Rutas Canario por Familia
 * y Rate-Limiter Comportamental.
 */

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
  behavioralRateLimit: true,
  rateLimitMaxPer10s: 25,
  autoQuarantineThreshold: 85
};

const SENSITIVE_FAMILY_PATTERNS = [
  /^\/\.env(?:[._-].*)?$/i,
  /^\/\.git(?:\/|$)/i,
  /^\/\.aws(?:\/|$)/i,
  /^\/\.ssh(?:\/|$)/i,
  /^\/\.kube(?:\/|$)/i,
  /\.(?:bak|old|swp|swo|sql|dump|orig|save)$/i,
  /^\/(?:wp-admin\/setup-config|xmlrpc\.php|phpmyadmin|pma|actuator\/|debug\/pprof|vendor\/phpunit)/i
];

/**
 * Normaliza entradas hasta 3 capas de codificación URL, limpia bytes nulos
 * y genera variantes sin comentarios SQL inline para derrotar técnicas de evasión.
 */
export function normalizePayloadMultiLayer(input) {
  if (!input || typeof input !== 'string') {
    return { decoded: '', noNulls: '', sqlEmptyComments: '', sqlSpaceComments: '' };
  }

  let decoded = input;
  for (let i = 0; i < 3; i += 1) {
    try {
      const next = decodeURIComponent(decoded.replace(/\+/g, ' '));
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }

  // Elimina bytes nulos (%00)
  const noNulls = decoded.replace(/\0/g, '');
  // Limpia comentarios MySQL condicionales /*!50000...*/ y comentarios inline /*...*/
  const sqlEmptyComments = noNulls.replace(/\/\*![0-9]*|\*\/|\/\*[\s\S]*?\*\//g, '');
  const sqlSpaceComments = noNulls.replace(/\/\*![0-9]*|\*\//g, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');

  return { decoded, noNulls, sqlEmptyComments, sqlSpaceComments };
}

const customCanaryPaths = new Set();
const customWafKeywords = new Set();

const RESERVED_CONTROL_PATHS = new Set([
  '/',
  '/soc',
  '/index.html',
  '/robots.txt',
  '/guardianes-sensor.js'
]);

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

export function registerCustomCanary(rawPath) {
  const valid = validateCustomCanaryPath(rawPath);
  if (!valid) return null;
  customCanaryPaths.add(valid);
  return valid;
}

export function getCustomCanaries() {
  return Array.from(customCanaryPaths);
}

export function registerCustomWafKeyword(rawKeyword) {
  const valid = validateCustomWafKeyword(rawKeyword);
  if (!valid) return null;
  customWafKeywords.add(valid);
  return valid;
}

export function getCustomWafKeywords() {
  return Array.from(customWafKeywords);
}

/**
 * Normaliza rutas (dobles barras, mayúsculas, URL-encoding) y detecta los 42+ canarios,
 * rutas personalizadas de Hermes y familias sensibles.
 */
export function isCanaryOrSensitivePath(rawPath = '/', extraCanaries = []) {
  const pathOnly = String(rawPath).split('?')[0];
  const { noNulls } = normalizePayloadMultiLayer(pathOnly);
  const collapsed = noNulls.replace(/\\+/g, '/').replace(/\/+/g, '/').trim();
  const normalized = collapsed.startsWith('/') ? collapsed : `/${collapsed}`;
  const lower = normalized.toLowerCase();

  if (CANARY_PATHS.some((c) => c.toLowerCase() === lower)) {
    return true;
  }
  if (customCanaryPaths.has(lower)) {
    return true;
  }
  if (Array.isArray(extraCanaries) && extraCanaries.some((c) => String(c).toLowerCase() === lower)) {
    return true;
  }
  return SENSITIVE_FAMILY_PATTERNS.some((rx) => rx.test(normalized));
}

const DPI_SIGNATURES = {
  SQL_INJECTION: {
    ruleKey: 'sqlInjection',
    score: 94,
    patterns: [
      /\bunion\s*(?:all\s*)?select\b/i,
      /\bun(?:\/\*[\s\S]*?\*\/)*ion(?:\s+|\/\*[\s\S]*?\*\/)+(?:all(?:\s+|\/\*[\s\S]*?\*\/)+)?sel(?:\/\*[\s\S]*?\*\/)*ect\b/i,
      /(?:'|"|%27|%22)\s*(?:or|and)\s+\d+\s*=\s*\d+/i,
      /\b(?:or|and)\s+1\s*=\s*1\b/i,
      /\binformation_schema\b/i,
      /\b(?:sleep|benchmark)\s*\(\s*\d+/i,
      /\bwaitfor\s+delay\b/i,
      /\bxp_cmdshell\b/i,
      /;\s*drop\s+table\b/i
    ]
  },
  XSS_AND_SCRIPT_SKIMMING: {
    ruleKey: 'xssSkimming',
    score: 90,
    patterns: [
      /<\s*script\b/i,
      /\bjavascript\s*:/i,
      /\bon(?:error|load|mouseover|focus)\s*=/i,
      /\bdocument\.cookie\b/i,
      /\beval\s*\(\s*atob\s*\(/i,
      /crypto-clipper|wallet_swap_skimmer/i
    ]
  },
  PATH_TRAVERSAL_LFI: {
    ruleKey: 'pathTraversal',
    score: 92,
    patterns: [
      /(?:\.\.[/\\]){2,}/,
      /%2e%2e(?:%2f|%5c|\/|\\)/i,
      /\/etc\/(?:passwd|shadow|hosts)\b/i,
      /c:\\windows\\win\.ini/i,
      /\bphp:\/\/(?:filter|input)\b/i
    ]
  },
  SSRF_AND_CLOUD_METADATA: {
    ruleKey: 'ssrfMetadata',
    score: 96,
    patterns: [
      /169\.254\.169\.254/,
      /metadata\.google\.internal/i,
      /100\.100\.100\.200/,
      /(?:url|redirect|callback|target|next)=https?:\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+)/i
    ]
  },
  RCE_AND_JAVA4SHELL_LOG4SHELL: {
    ruleKey: 'rceJava4Shell',
    score: 99,
    patterns: [
      /\$\{(?:jndi|env|lower|upper|sys):/i,
      /(?:;|\|\||&&|\|)\s*(?:cat\s+\/|bash\b|sh\b|whoami\b|id\b|curl\s+http|wget\s+http|nc\s+-e)/i,
      /\bcmd\.exe\s+\/c\b/i,
      /\bpowershell(?:\.exe)?\s+-(?:enc|encodedcommand|nop)/i,
      /java4shell|avx512_vbmi_overflow/i
    ]
  }
};

/**
 * Inspecciona URL, query, cabeceras no estándar y cuerpo POST aplicando normalización multicapa.
 */
export function inspectPayloadDPI({
  rawUrl = '/',
  headers = {},
  bodyText = '',
  wafRules = DEFAULT_WAF_RULES,
  customKeywords = []
}) {
  const rules = { ...DEFAULT_WAF_RULES, ...(wafRules || {}) };

  const inspectedHeaderValues = [
    headers['x-forwarded-host'],
    headers['x-original-url'],
    headers['x-rewrite-url'],
    headers['referer'],
    headers['x-api-version'],
    headers['x-artex-payload']
  ]
    .filter(Boolean)
    .map((v) => String(v))
    .join(' ');

  const rawTargets = [rawUrl, bodyText, inspectedHeaderValues].filter(Boolean);
  const targets = [];

  for (const item of rawTargets) {
    const norm = normalizePayloadMultiLayer(item);
    targets.push(item, norm.noNulls, norm.sqlEmptyComments, norm.sqlSpaceComments);
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

  // Reglas dinámicas creadas por el operador mediante Comandante Hermes
  const allCustomKeywords = Array.from(new Set([...customWafKeywords, ...(customKeywords || [])]));
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

  // Detección heurística adicional de CVE-2026-114938 (Java4Shell Base64 malformado sobredimensionado)
  if (rules.rceJava4Shell) {
    const combined = targets.join(' ');
    if (/(?:[A-Za-z0-9+/]{120,}={3,})/.test(combined) || /={4,}/.test(combined)) {
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

    if (this.buckets.size > 2000) {
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
