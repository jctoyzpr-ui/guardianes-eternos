/**
 * @fileoverview Motor de Detección Estructural & Rutas Canario v5.1 (0 dependencias npm).
 * Complementa firewalls de borde (Cloudflare / OWASP CRS) con:
 *   - 43+ Rutas Canario no-ancladas (0% dependencia de firmas para trampas de decepción)
 *   - Inspección estructural por familia (SQL tokenizer, HTML/XSS parser, SSRF canonical + BlockList,
 *     RCE/Shell/Log4Shell/SpEL, LFI, SSTI/NoSQL/XXE/Prototype Pollution)
 *   - Inspección de TODAS las cabeceras HTTP (incl. Accept-Language, Cookie, User-Agent, Referer)
 *   - Rate Limiter Comportamental por ventana deslizante.
 */

import {
  analyzeExtrasStructure,
  analyzeLfiStructure,
  analyzeRceStructure,
  analyzeSqlStructure,
  analyzeSsrfStructure,
  analyzeXssStructure,
  canonicalizeObfuscatedIp,
  extractStructuredInputs,
  normalizePayloadMultiLayer
} from './structuralDetector.js';

export { canonicalizeObfuscatedIp, normalizePayloadMultiLayer };

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

// Solo se ignoran cabeceras puras de transporte HTTP; TODAS las demás (incl. Accept-Language, Cookie, UA, Referer) SE INSPECCIONAN (N-01)
const TRANSPORT_ONLY_HEADERS = new Set([
  'host',
  'connection',
  'content-length',
  'content-encoding',
  'transfer-encoding',
  'upgrade'
]);

const URL_PARAM_KEY_REGEX = /(?:url|uri|redirect|callback|target|next|dest|destination|image|img|src|href|link|endpoint|webhook|fetch|proxy|feed|avatar|site|return|continue)/i;

export function hasSsrfTargetInText(text) {
  return analyzeSsrfStructure(text, { isUrlParamValue: false });
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
 * Normaliza rutas (dobles barras, matrix params ';.css', barra final, URL-encoding)
 * y detecta los 43+ canarios, rutas personalizadas y familias sensibles en cualquier subruta.
 */
export function isCanaryOrSensitivePath(rawPath = '/', extraCanaries = []) {
  const pathOnly = String(rawPath).split('?')[0];
  const { noNulls } = normalizePayloadMultiLayer(pathOnly);
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

/**
 * Inspección Estructural Multicapa en URL, parámetros, cuerpo completo y TODAS las cabeceras HTTP.
 */
export function inspectPayloadDPI({
  rawUrl = '/',
  headers = {},
  bodyText = '',
  wafRules = DEFAULT_WAF_RULES,
  customKeywords = []
}) {
  const rules = { ...DEFAULT_WAF_RULES, ...(wafRules || {}) };
  const structured = extractStructuredInputs({ rawUrl, bodyText });

  const headerPairs = [];
  if (headers && typeof headers === 'object') {
    for (const [name, value] of Object.entries(headers)) {
      const lowerName = name.toLowerCase();
      if (TRANSPORT_ONLY_HEADERS.has(lowerName)) continue;
      if (value === undefined || value === null) continue;
      const str = Array.isArray(value) ? value.join(' ') : String(value);
      if (str) headerPairs.push({ name: lowerName, value: str });
    }
  }

  const headerValues = headerPairs.map((h) => h.value);
  const cookieValues = [];
  for (const h of headerPairs) {
    if (h.name === 'cookie') {
      for (const part of h.value.split(';')) {
        const eq = part.indexOf('=');
        cookieValues.push(eq === -1 ? part.trim() : part.slice(eq + 1).trim());
      }
    }
  }

  const paramValues = structured.params.map((p) => p.value).filter(Boolean);
  const allTexts = [
    structured.rawPath,
    structured.rawQuery,
    bodyText,
    ...paramValues,
    ...headerValues,
    ...cookieValues
  ].filter(Boolean);

  const vectors = [];
  let maxScore = 0;

  // 1. SQL Injection (Tokenizador léxico estructural)
  if (rules.sqlInjection) {
    const sqlCandidates = [
      ...paramValues,
      ...cookieValues,
      ...headerPairs.filter((h) => !['user-agent', 'accept', 'accept-language', 'accept-encoding'].includes(h.name)).map((h) => h.value)
    ];
    if (sqlCandidates.length === 0 && structured.rawQuery) sqlCandidates.push(structured.rawQuery);
    if (sqlCandidates.length === 0 && bodyText) sqlCandidates.push(bodyText);

    if (sqlCandidates.some((txt) => analyzeSqlStructure(txt))) {
      vectors.push('SQL_INJECTION');
      maxScore = Math.max(maxScore, 94);
    }
  }

  // 2. XSS / HTML Injection (Parser estructural de etiquetas reales + esquemas URI en contexto)
  if (rules.xssSkimming) {
    const xssHit =
      structured.params.some((p) =>
        analyzeXssStructure(p.value, { isDirectUriParam: URL_PARAM_KEY_REGEX.test(p.key) })
      ) ||
      [structured.rawPath, ...headerValues].some((txt) => analyzeXssStructure(txt, { isDirectUriParam: false }));
    if (xssHit) {
      vectors.push('XSS_AND_SCRIPT_SKIMMING');
      maxScore = Math.max(maxScore, 90);
    }
  }

  // 3. Path Traversal / LFI (1 solo ../ incluido, sin FP en prosa libre "/etc/hosts")
  if (rules.pathTraversal) {
    const lfiHit =
      analyzeLfiStructure(structured.rawPath, { isFreeProseBody: false }) ||
      structured.params.some((p) =>
        analyzeLfiStructure(p.value, { isFreeProseBody: p.source === 'body' || p.source === 'json' || p.source === 'form' })
      ) ||
      headerValues.some((txt) => analyzeLfiStructure(txt, { isFreeProseBody: true }));
    if (lfiHit) {
      vectors.push('PATH_TRAVERSAL_LFI');
      maxScore = Math.max(maxScore, 92);
    }
  }

  // 4. SSRF & Cloud Metadata (esquemas, //, http:\\, nip.io/sslip.io + net.BlockList)
  if (rules.ssrfMetadata) {
    const ssrfHit =
      structured.params.some((p) =>
        analyzeSsrfStructure(p.value, { isUrlParamValue: URL_PARAM_KEY_REGEX.test(p.key) })
      ) ||
      [structured.rawQuery, bodyText, ...headerValues].some((txt) =>
        analyzeSsrfStructure(txt, { isUrlParamValue: false })
      );
    if (ssrfHit) {
      vectors.push('SSRF_AND_CLOUD_METADATA');
      maxScore = Math.max(maxScore, 96);
    }
  }

  // 5. RCE / Command Injection / Log4Shell / SpEL (incluyendo Accept-Language y saltos de línea %0a)
  if (rules.rceJava4Shell) {
    const rceTargets = [structured.rawPath, ...paramValues, ...headerValues, ...cookieValues];
    if (rceTargets.some((txt) => analyzeRceStructure(txt))) {
      vectors.push('RCE_AND_JAVA4SHELL_LOG4SHELL');
      maxScore = Math.max(maxScore, 99);
    }
  }

  // 6. SSTI / NoSQL (\u0024) / XXE / Prototype Pollution (claves JSON + query + texto)
  if (rules.sstiNosqlXxeProto) {
    const extrasHit = analyzeExtrasStructure({
      rawTexts: allTexts,
      jsonKeys: structured.jsonKeys,
      jsonKeyPaths: structured.jsonKeyPaths,
      params: structured.params
    });
    if (extrasHit) {
      vectors.push('SSTI_NOSQL_XXE_PROTO');
      maxScore = Math.max(maxScore, 93);
    }
  }

  // 7. Reglas dinámicas por instancia creadas por el operador mediante Comandante Hermes
  const allCustomKeywords = Array.isArray(customKeywords) ? customKeywords.filter(Boolean) : [];
  if (allCustomKeywords.length > 0) {
    const lowerTargets = allTexts.map((t) => normalizePayloadMultiLayer(String(t)).htmlDecoded.toLowerCase());
    const customMatched = allCustomKeywords.some((kw) =>
      lowerTargets.some((txt) => txt.includes(String(kw).toLowerCase()))
    );
    if (customMatched) {
      vectors.push('CUSTOM_HERMES_RULE');
      maxScore = Math.max(maxScore, 93);
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
