/**
 * @fileoverview Motor de Detección Estructural, Rutas Canario y Rate Limiter v5.2 (0 dependencias npm).
 * - Exención de activos estáticos para tiendas reales (50–100 archivos por página - Fase 0 #1).
 * - Exclusión de Referer/Origin en análisis SSRF (Fase 1 #5).
 * - Decodificación de body independiente del Content-Type declarado + UTF-16 (Fase 1 #6).
 * - Modo por defecto `wafActionMode: 'detect'` (heurísticas solo registran y avisan; cuarentena reservada a engaño).
 */

import {
  analyzeExtrasStructure,
  analyzeLfiStructure,
  analyzeRceStructure,
  analyzeSqlStructure,
  analyzeSsrfStructure,
  analyzeXssStructure,
  canonicalizeObfuscatedIp,
  decodeBufferToInspectableText,
  extractStructuredInputs,
  normalizePayloadMultiLayer
} from './structuralDetector.js';

export { canonicalizeObfuscatedIp, decodeBufferToInspectableText, normalizePayloadMultiLayer };

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
  // Fase 0 (#3): Por defecto las reglas heurísticas operan en modo detección (registran y avisan sin bloquear clientes).
  // El operador puede cambiar opcionalmente a 'block-request' (403 puntual, jamás cuarentena 24h).
  wafActionMode: 'detect',
  sqlInjection: true,
  xssSkimming: true,
  pathTraversal: true,
  ssrfMetadata: true,
  rceJava4Shell: true,
  sstiNosqlXxeProto: true,
  behavioralRateLimit: true,
  // Fase 0 (#1): Límite sobre navegaciones/API (excluye estáticos), apto para CGNAT/oficinas; solo devuelve 429 temporal.
  rateLimitMaxPer10s: 120,
  autoQuarantineThreshold: 85,
  // v5.3: tope de TEXTO de cuerpo inspeccionable (KB). Los archivos binarios de multipart no cuentan.
  maxInspectBodyKb: 1024,
  // v5.3: qué hacer con lo no inspeccionable (demasiado grande, encoding/charset no soportado, timeout, sobrecarga):
  //   'auto' = bloquear en block-request y alertar en detect; 'block'; 'allow-with-alert'
  uninspectablePolicy: 'auto'
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

const STATIC_ASSET_EXT_REGEX =
  /\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|eot|otf|mp4|webm|ogg|mp3|wav|pdf)$/i;

const TRANSPORT_ONLY_HEADERS = new Set([
  'host',
  'connection',
  'content-length',
  'content-encoding',
  'transfer-encoding',
  'upgrade'
]);

// Fase 1 (#5): Referer y Origin jamás deben evaluarse como SSRF (una web abierta por IP privada los envía siempre)
const SSRF_EXCLUDED_HEADERS = new Set(['referer', 'origin', 'host']);

const URL_PARAM_KEY_REGEX =
  /(?:url|uri|redirect|callback|target|next|dest|destination|image|img|src|href|link|endpoint|webhook|fetch|proxy|feed|avatar|site|return|continue|import|load|file)/i;

/**
 * Fase 0 (#1): Determina si una petición GET/HEAD corresponde a un archivo estático legítimo
 * (imágenes, CSS, JS, fuentes) que NO debe contarse en el límite de ráfagas por página.
 */
export function isStaticAssetRequest(cleanPath = '/', method = 'GET', extraCanaries = []) {
  const m = String(method || 'GET').toUpperCase();
  if (m !== 'GET' && m !== 'HEAD') return false;
  const pathOnly = String(cleanPath || '/').split('?')[0];
  if (isCanaryOrSensitivePath(pathOnly, extraCanaries)) return false;
  if (pathOnly.includes('..') || pathOnly.includes(';')) return false;
  return STATIC_ASSET_EXT_REGEX.test(pathOnly);
}

export function hasSsrfTargetInText(text) {
  return analyzeSsrfStructure(text, { isUrlParamValue: false, isFreeProse: false });
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
 * Inspección Estructural Lineal O(n) sobre ruta REST, parámetros, cuerpo (JSON/multipart/form/texto)
 * y cabeceras HTTP.
 */
export function inspectPayloadDPI({
  rawUrl = '/',
  headers = {},
  bodyText = '',
  contentType = '',
  wafRules = DEFAULT_WAF_RULES,
  customKeywords = []
}) {
  const rules = { ...DEFAULT_WAF_RULES, ...(wafRules || {}) };
  const effectiveCt = contentType || headers['content-type'] || headers['Content-Type'] || '';
  const structured = extractStructuredInputs({ rawUrl, bodyText, contentType: effectiveCt });

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
  // v5.3: los NOMBRES de parámetro también llegan al backend (ORMs que ordenan/filtran por clave, frameworks que
  // reflejan claves): `?x' UNION SELECT 1-- -=1` antes pasaba porque solo se miraban valores.
  const paramKeys = Array.from(
    new Set(
      [...structured.params.map((p) => p.key), ...structured.jsonKeys].filter(
        (k) => k && k !== '_path_segment' && !k.endsWith('.filename') && k.length >= 3
      )
    )
  );
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

  // 1. SQL Injection (tokenizador léxico por parámetro, segmento REST, multipart y cookies)
  if (rules.sqlInjection) {
    // v5.3: User-Agent y Accept-Language también se inspeccionan (se registran en BD: analytics, logs, auditoría).
    // Referer/Origin siguen excluidos (traen búsquedas de otros sitios con texto libre).
    const sqlCandidates = [
      ...paramValues,
      ...paramKeys,
      ...cookieValues,
      ...headerPairs
        .filter((h) => !['accept', 'accept-encoding', 'referer', 'origin', 'cookie'].includes(h.name))
        .map((h) => h.value)
    ];
    if (sqlCandidates.length === 0 && structured.rawQuery) sqlCandidates.push(structured.rawQuery);
    if (sqlCandidates.length === 0 && bodyText) sqlCandidates.push(bodyText);

    if (sqlCandidates.some((txt) => analyzeSqlStructure(txt))) {
      vectors.push('SQL_INJECTION');
      maxScore = Math.max(maxScore, 94);
    }
  }

  // 2. XSS / HTML Injection (etiquetas cerradas y sin cerrar + contexto JS)
  if (rules.xssSkimming) {
    const xssHit =
      structured.params.some((p) =>
        analyzeXssStructure(p.value, { isDirectUriParam: URL_PARAM_KEY_REGEX.test(p.key) })
      ) ||
      [
        structured.rawPath,
        ...paramKeys,
        ...cookieValues,
        ...headerPairs.filter((h) => h.name !== 'referer' && h.name !== 'origin').map((h) => h.value)
      ].some((txt) => analyzeXssStructure(txt, { isDirectUriParam: false }));
    if (xssHit) {
      vectors.push('XSS_AND_SCRIPT_SKIMMING');
      maxScore = Math.max(maxScore, 90);
    }
  }

  // 3. Path Traversal / LFI
  if (rules.pathTraversal) {
    const lfiHit =
      analyzeLfiStructure(structured.rawPath, { isFreeProseBody: false }) ||
      structured.params.some((p) =>
        analyzeLfiStructure(p.value, { isFreeProseBody: p.source === 'body' || p.source === 'json' || p.source === 'form' || p.source === 'multipart' })
      ) ||
      headerPairs
        .filter((h) => h.name !== 'referer' && h.name !== 'origin')
        .some((h) => analyzeLfiStructure(h.value, { isFreeProseBody: true }));
    if (lfiHit) {
      vectors.push('PATH_TRAVERSAL_LFI');
      maxScore = Math.max(maxScore, 92);
    }
  }

  // 4. SSRF & Cloud Metadata (Fase 1 #5: NUNCA en Referer ni Origin; Fase 0 #3: sin FP en prosa libre)
  if (rules.ssrfMetadata) {
    const ssrfParamHit = structured.params.some((p) => {
      const isUrlKey = URL_PARAM_KEY_REGEX.test(p.key);
      const isFreeProse = !isUrlKey && (p.source === 'body' || p.source === 'json' || p.source === 'form' || p.source === 'multipart');
      return analyzeSsrfStructure(p.value, { isUrlParamValue: isUrlKey, isFreeProse });
    });
    const ssrfHeaderHit = headerPairs
      .filter((h) => !SSRF_EXCLUDED_HEADERS.has(h.name) && h.name !== 'user-agent')
      .some((h) => analyzeSsrfStructure(h.value, { isUrlParamValue: URL_PARAM_KEY_REGEX.test(h.name), isFreeProse: false }));

    if (ssrfParamHit || ssrfHeaderHit) {
      vectors.push('SSRF_AND_CLOUD_METADATA');
      maxScore = Math.max(maxScore, 96);
    }
  }

  // 5. RCE / Command Injection / Log4Shell / SpEL
  if (rules.rceJava4Shell) {
    const rceTargets = [
      structured.rawPath,
      ...paramValues,
      ...headerPairs.filter((h) => h.name !== 'referer' && h.name !== 'origin').map((h) => h.value),
      ...cookieValues
    ];
    if (rceTargets.some((txt) => analyzeRceStructure(txt))) {
      vectors.push('RCE_AND_JAVA4SHELL_LOG4SHELL');
      maxScore = Math.max(maxScore, 99);
    }
  }

  // 6. SSTI (con y sin {{ }}), NoSQL, XXE (sin FP en XHTML DOCTYPE) y Prototype Pollution
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

  // 7. Reglas personalizadas del operador
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
 * Fase 0 (#1): Solo cuenta navegaciones/API no estáticas y nunca dispara cuarentena de 24h.
 */
export class BehavioralRateLimiter {
  constructor() {
    this.buckets = new Map();
  }

  recordRequest(ip, { windowMs = 10_000, threshold = 120 } = {}) {
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
