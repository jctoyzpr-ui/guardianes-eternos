/**
 * @fileoverview Servidor HTTP Nativo de Guardianes Eternos v5.0 (Arquitectura Enterprise Dual-Plane).
 * - Data Plane (puerto 4040): WAF DPI multicapa, Byte-Drip Tarpit con presupuesto de sockets (H-07),
 *   Streaming Reverse Proxy sin corrupción binaria (H-06), sidecar /guardianes/check (nginx auth_request),
 *   robots.txt completo (H-04) y /telemetry-beacon con nonce HMAC firmado (H-03, M-03).
 * - Control Plane (puerto 4041, loopback): Autenticación obligatoria por token/sesión firmada (C-01),
 *   anti-CSRF + anti-DNS-Rebinding (C-02), SSE en vivo GET /events para el SOC Holográfico 3D y Comandante Hermes v5.0.
 */

import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AIRouter } from './engine/aiRouter.js';
import { SwarmMemory } from './engine/swarmMemory.js';
import { SQLiteStore } from './engine/sqliteStore.js';
import { CANARY_PATHS, DEFAULT_WAF_RULES } from './engine/sentinelWaf.js';
import { SwarmCoordinator } from './engine/guardians.js';
import {
  buildDeployKit,
  buildSensorScript,
  exportCloudflareWaf,
  exportIptablesScript,
  exportNginxDenyConf,
  isValidIpAddress
} from './engine/firewallExporter.js';
import { runLiveCyberRangeComparison } from './sandbox/cyberRange.js';
import { HermesCommander } from './engine/hermesCommander.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const DEFAULT_PUBLIC_DIR = path.resolve(ROOT_DIR, 'public');
const DEFAULT_MEMORY_FILE = path.resolve(ROOT_DIR, 'MEMORIA_PROYECTO.md');
const DEFAULT_DB_FILE = path.resolve(ROOT_DIR, 'data/guardianes.sqlite');

const MAX_JSON_BODY_BYTES = 1024 * 1024;
const MAX_DPI_INSPECT_BYTES = 64 * 1024;
const MAX_PROXY_BODY_BYTES = 20 * 1024 * 1024;
const DEFAULT_TRUSTED_PROXIES = ['127.0.0.1', '::1'];

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'transfer-encoding',
  'upgrade'
]);

function sha256Hex(val) {
  return crypto.createHash('sha256').update(String(val)).digest('hex');
}

function timingSafeHexEquals(aHex, bHex) {
  if (!aHex || !bHex || typeof aHex !== 'string' || typeof bHex !== 'string') return false;
  const a = Buffer.from(aHex);
  const b = Buffer.from(bHex);
  if (a.length !== b.length || a.length === 0) return false;
  return crypto.timingSafeEqual(a, b);
}

function maskSecret(val) {
  if (!val || typeof val !== 'string') return '';
  const t = val.trim();
  if (t.length <= 8) return '••••••••';
  return `${t.slice(0, 4)}••••${t.slice(-4)}`;
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  if (res.writableEnded || res.destroyed) return;
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  res.end(body);
}

function parseCookies(cookieHeader = '') {
  const out = {};
  if (!cookieHeader || typeof cookieHeader !== 'string') return out;
  for (const pair of cookieHeader.split(';')) {
    const idx = pair.indexOf('=');
    if (idx <= 0) continue;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(val);
  }
  return out;
}

/**
 * Lee el cuerpo como Buffer crudo (sin corrupción UTF-8 de uploads binarios - H-06)
 * y extrae hasta 64 KB como vista de texto para inspección DPI.
 */
function readBodyBuffer(req, maxBytes = MAX_JSON_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    let totalBytes = 0;
    const chunks = [];

    req.on('data', (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      resolve(chunks.length === 0 ? Buffer.alloc(0) : Buffer.concat(chunks));
    });

    req.on('error', reject);
  });
}

async function readJsonBody(req) {
  const buf = await readBodyBuffer(req, MAX_JSON_BODY_BYTES);
  const raw = buf.toString('utf8');
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('Invalid JSON body');
  }
}

/**
 * H-03: Resolución segura de IP cliente recorriendo X-Forwarded-For de DERECHA a IZQUIERDA
 * y confiando únicamente cuando el socket TCP proviene de un proxy en trustedProxies.
 */
export function resolveClientIdentity(req, trustProxyHeaders = false, trustedProxies = DEFAULT_TRUSTED_PROXIES) {
  const remoteRaw = String(req.socket?.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '');
  const socketIp = isValidIpAddress(remoteRaw) ? remoteRaw : '127.0.0.1';
  const trustedSet = new Set(
    (Array.isArray(trustedProxies) && trustedProxies.length > 0 ? trustedProxies : DEFAULT_TRUSTED_PROXIES).map((p) =>
      String(p).replace(/^::ffff:/, '').trim()
    )
  );

  if (trustProxyHeaders && trustedSet.has(socketIp)) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
      const hops = forwarded
        .split(',')
        .map((h) => h.replace(/^::ffff:/, '').trim())
        .filter((h) => isValidIpAddress(h));

      // Recorre de derecha a izquierda saltando proxies de confianza para evitar spoofing del extremo izquierdo
      for (let i = hops.length - 1; i >= 0; i -= 1) {
        if (!trustedSet.has(hops[i])) {
          return { clientIp: hops[i], socketIp };
        }
      }
      if (hops.length > 0) {
        return { clientIp: hops[0], socketIp };
      }
    }
  }

  return { clientIp: socketIp, socketIp };
}

/**
 * Verifica que el Host header del Control Plane pertenezca a la lista blanca (anti-DNS Rebinding - C-02).
 */
function isAllowedControlHost(hostHeader, allowedHostsSet) {
  if (!hostHeader || typeof hostHeader !== 'string') return false;
  const trimmed = hostHeader.trim().toLowerCase();
  if (!trimmed) return false;
  let hostname = trimmed;
  if (hostname.startsWith('[')) {
    const end = hostname.indexOf(']');
    if (end === -1) return false;
    hostname = hostname.slice(0, end + 1);
  } else {
    const colon = hostname.indexOf(':');
    if (colon !== -1) hostname = hostname.slice(0, colon);
  }
  return allowedHostsSet.has(hostname);
}

/**
 * Verifica Origin y Sec-Fetch-Site en peticiones mutantes del Control Plane (anti-CSRF - C-02).
 */
function isSafeControlOrigin(req, allowedHostsSet) {
  const secFetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
  if (secFetchSite && !['same-origin', 'none'].includes(secFetchSite)) {
    return false;
  }
  const origin = req.headers['origin'];
  if (origin) {
    try {
      const parsed = new URL(String(origin));
      const host = parsed.hostname.toLowerCase();
      const bracketed = host.includes(':') ? `[${host}]` : host;
      if (!allowedHostsSet.has(host) && !allowedHostsSet.has(bracketed)) {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

/**
 * H-06: Reverse Proxy streaming nativo con http.request / https.request.
 * Conserva Buffer binario sin corrupción, reenvía Cookie/Authorization/Set-Cookie/Cache-Control,
 * NO sigue redirecciones 301/302 automáticamente, y la inyección DOM canario es opt-in (H-04).
 */
function proxyToProtectedTarget({
  req,
  res,
  targetBaseUrl,
  reqUrl,
  rawBodyBuffer,
  injectDomCanary = false
}) {
  return new Promise((resolve) => {
    let destination;
    try {
      destination = new URL(reqUrl.pathname + reqUrl.search, targetBaseUrl);
    } catch {
      sendJson(res, 502, { error: 'Upstream target configuration invalid.' });
      resolve();
      return;
    }

    const isHttps = destination.protocol === 'https:';
    const transport = isHttps ? https : http;

    const forwardHeaders = {};
    for (const [k, v] of Object.entries(req.headers || {})) {
      const lower = k.toLowerCase();
      if (HOP_BY_HOP_HEADERS.has(lower) || lower === 'host') continue;
      if (v !== undefined) forwardHeaders[k] = v;
    }
    forwardHeaders.host = destination.host;
    if (rawBodyBuffer && rawBodyBuffer.length > 0) {
      forwardHeaders['content-length'] = String(rawBodyBuffer.length);
    }

    const upstreamReq = transport.request(
      {
        protocol: destination.protocol,
        hostname: destination.hostname,
        port: destination.port || (isHttps ? 443 : 80),
        path: destination.pathname + destination.search,
        method: req.method,
        headers: forwardHeaders,
        timeout: 10_000
      },
      (upstreamRes) => {
        const resHeaders = {};
        for (const [k, v] of Object.entries(upstreamRes.headers || {})) {
          const lower = k.toLowerCase();
          if (HOP_BY_HOP_HEADERS.has(lower)) continue;
          if (v !== undefined) resHeaders[k] = v;
        }

        // Cabeceras de blindaje defensivo sin sobrescribir Cache-Control ni Set-Cookie del upstream
        resHeaders['X-Protected-By'] = 'Guardianes-Eternos-Swarm-WAF/5.0';
        resHeaders['X-Content-Type-Options'] = resHeaders['x-content-type-options'] || 'nosniff';
        resHeaders['X-Frame-Options'] = resHeaders['x-frame-options'] || 'SAMEORIGIN';
        resHeaders['Referrer-Policy'] = resHeaders['referrer-policy'] || 'strict-origin-when-cross-origin';
        resHeaders['Permissions-Policy'] =
          resHeaders['permissions-policy'] || 'geolocation=(), microphone=(), camera=()';

        const contentType = String(upstreamRes.headers['content-type'] || '');
        const contentEncoding = String(upstreamRes.headers['content-encoding'] || '');
        const shouldInjectHtml =
          injectDomCanary &&
          contentType.toLowerCase().includes('text/html') &&
          !contentEncoding &&
          upstreamRes.statusCode >= 200 &&
          upstreamRes.statusCode < 300;

        if (shouldInjectHtml) {
          const chunks = [];
          upstreamRes.on('data', (c) => chunks.push(c));
          upstreamRes.on('end', () => {
            let html = Buffer.concat(chunks).toString('utf8');
            const stealthCanary =
              '<a href="/api/v1/internal/admin-keys" rel="nofollow noopener" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;opacity:0" tabindex="-1" aria-hidden="true">Internal Admin Vault</a>' +
              '<script src="/guardianes-sensor.js" defer></script>';
            if (html.includes('</body>')) {
              html = html.replace('</body>', `${stealthCanary}</body>`);
            } else {
              html += stealthCanary;
            }
            const outBuf = Buffer.from(html, 'utf8');
            delete resHeaders['content-length'];
            resHeaders['Content-Length'] = String(outBuf.length);
            if (!res.writableEnded && !res.destroyed) {
              res.writeHead(upstreamRes.statusCode || 200, resHeaders);
              res.end(outBuf);
            }
            resolve();
          });
          upstreamRes.on('error', () => {
            sendJson(res, 502, { error: 'Upstream response failed.' });
            resolve();
          });
          return;
        }

        // Streaming directo sin tocar bytes (preserva binarios, imágenes, 302 redirects, Set-Cookie, etc.)
        if (!res.writableEnded && !res.destroyed) {
          res.writeHead(upstreamRes.statusCode || 200, resHeaders);
          upstreamRes.pipe(res);
          res.on('finish', resolve);
          res.on('close', resolve);
        } else {
          upstreamRes.resume();
          resolve();
        }
      }
    );

    upstreamReq.on('timeout', () => {
      upstreamReq.destroy(new Error('Upstream timeout'));
    });

    upstreamReq.on('error', () => {
      // L-01: Error genérico al cliente sin filtrar stack ni err.message
      sendJson(res, 502, { error: 'No se pudo conectar con el servidor protegido aguas arriba.' });
      resolve();
    });

    if (rawBodyBuffer && rawBodyBuffer.length > 0 && !['GET', 'HEAD'].includes((req.method || 'GET').toUpperCase())) {
      upstreamReq.write(rawBodyBuffer);
    }
    upstreamReq.end();
  });
}

export function createGuardianesServer(options = {}) {
  const memoryFilePath = options.memoryFilePath !== undefined ? options.memoryFilePath : DEFAULT_MEMORY_FILE;
  const publicDir = options.publicDir || DEFAULT_PUBLIC_DIR;
  const dbPath = options.dbPath !== undefined ? options.dbPath : DEFAULT_DB_FILE;

  const store = new SQLiteStore(dbPath);
  const aiRouter = new AIRouter(options.aiConfig || {});
  if (!options.aiConfig) {
    aiRouter.loadFromStore(store);
  } else if (options.aiConfig.tarpitDelayMs !== undefined) {
    aiRouter.updateConfig({ tarpitDelayMs: options.aiConfig.tarpitDelayMs });
  }

  // C-01: Token administrativo obligatorio (nunca bypass por 127.0.0.1)
  let adminTokenHash = '';
  let generatedAdminToken = null;
  const configuredToken = options.adminToken || process.env.GUARDIANES_ADMIN_TOKEN || '';
  if (configuredToken) {
    adminTokenHash = sha256Hex(configuredToken);
  } else {
    const savedHash = store.loadSetting('admin_token_hash', null);
    if (typeof savedHash === 'string' && savedHash.length === 64) {
      adminTokenHash = savedHash;
    } else {
      generatedAdminToken = crypto.randomBytes(24).toString('hex');
      adminTokenHash = sha256Hex(generatedAdminToken);
      store.saveSetting('admin_token_hash', adminTokenHash);
    }
  }

  const sessionHmacSecret = crypto.randomBytes(32);
  const beaconHmacSecret = crypto.randomBytes(32);
  const activeSessions = new Map(); // sessionId -> { csrfToken, expiresAt }

  function signSessionId(sessionId) {
    const mac = crypto.createHmac('sha256', sessionHmacSecret).update(sessionId).digest('hex');
    return `${sessionId}.${mac}`;
  }

  function verifySignedSessionCookie(cookieVal) {
    if (!cookieVal || typeof cookieVal !== 'string') return null;
    const dot = cookieVal.indexOf('.');
    if (dot <= 0) return null;
    const sessionId = cookieVal.slice(0, dot);
    const mac = cookieVal.slice(dot + 1);
    const expected = crypto.createHmac('sha256', sessionHmacSecret).update(sessionId).digest('hex');
    if (!timingSafeHexEquals(mac, expected)) return null;
    const sess = activeSessions.get(sessionId);
    if (!sess) return null;
    if (Date.now() > sess.expiresAt) {
      activeSessions.delete(sessionId);
      return null;
    }
    return { sessionId, ...sess };
  }

  function verifyBearerOrHeaderToken(req) {
    const authHeader = String(req.headers['authorization'] || '');
    const customToken = String(req.headers['x-guardianes-admin-token'] || '');
    const provided = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : customToken.trim();
    if (!provided) return false;
    return timingSafeHexEquals(sha256Hex(provided), adminTokenHash);
  }

  function issueBeaconNonce() {
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = crypto.createHmac('sha256', beaconHmacSecret).update(`beacon:${ts}`).digest('hex').slice(0, 24);
    return `${ts}.${sig}`;
  }

  function verifyBeaconNonce(nonce) {
    if (!nonce || typeof nonce !== 'string') return false;
    const dot = nonce.indexOf('.');
    if (dot <= 0) return false;
    const tsStr = nonce.slice(0, dot);
    const sig = nonce.slice(dot + 1);
    const ts = Number(tsStr);
    if (!Number.isFinite(ts)) return false;
    const ageSec = Math.abs(Math.floor(Date.now() / 1000) - ts);
    if (ageSec > 600) return false;
    const expected = crypto
      .createHmac('sha256', beaconHmacSecret)
      .update(`beacon:${tsStr}`)
      .digest('hex')
      .slice(0, 24);
    return timingSafeHexEquals(sig, expected);
  }

  const extraHosts = String(process.env.GUARDIANES_ALLOWED_HOSTS || '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  const allowedControlHosts = new Set([
    'localhost',
    '127.0.0.1',
    '[::1]',
    '::1',
    ...extraHosts,
    ...(options.allowedControlHosts || []).map((h) => String(h).toLowerCase())
  ]);

  // Configuración del Escudo WAF y Reverse Proxy
  const savedShield = store.loadSetting('shield_config_public', null);
  const savedShieldSecrets = store.decryptSecretObject(store.loadSetting('shield_secrets_vault', null));
  const override = options.shieldConfigOverride || {};

  const shieldConfig = {
    protectedTargetUrl: override.protectedTargetUrl || savedShield?.protectedTargetUrl || 'https://www.365collaboration.net',
    shieldMode:
      override.shieldMode || (savedShield?.shieldMode === 'reverse-proxy' ? 'reverse-proxy' : 'standalone'),
    trustProxyHeaders:
      override.trustProxyHeaders !== undefined
        ? Boolean(override.trustProxyHeaders)
        : Boolean(savedShield?.trustProxyHeaders),
    trustedProxies:
      Array.isArray(override.trustedProxies)
        ? override.trustedProxies
        : Array.isArray(savedShield?.trustedProxies)
          ? savedShield.trustedProxies
          : [...DEFAULT_TRUSTED_PROXIES],
    injectDomCanary:
      override.injectDomCanary !== undefined
        ? Boolean(override.injectDomCanary)
        : Boolean(savedShield?.injectDomCanary ?? false),
    wafRules: { ...DEFAULT_WAF_RULES, ...(savedShield?.wafRules || {}), ...(override.wafRules || {}) },
    webhookUrl: savedShield?.webhookUrl || '',
    webhookSecret: savedShieldSecrets?.webhookSecret || '',
    cloudflareApiToken: savedShieldSecrets?.cloudflareApiToken || '',
    cloudflareZoneId: savedShield?.cloudflareZoneId || ''
  };

  function getPublicShieldConfig() {
    return {
      protectedTargetUrl: shieldConfig.protectedTargetUrl,
      shieldMode: shieldConfig.shieldMode,
      trustProxyHeaders: shieldConfig.trustProxyHeaders,
      trustedProxies: [...shieldConfig.trustedProxies],
      injectDomCanary: shieldConfig.injectDomCanary,
      wafRules: { ...shieldConfig.wafRules },
      webhookUrl: shieldConfig.webhookUrl,
      webhookSecretConfigured: Boolean(shieldConfig.webhookSecret),
      webhookSecretMasked: maskSecret(shieldConfig.webhookSecret),
      cloudflareZoneId: shieldConfig.cloudflareZoneId,
      cloudflareTokenConfigured: Boolean(shieldConfig.cloudflareApiToken),
      cloudflareTokenMasked: maskSecret(shieldConfig.cloudflareApiToken),
      adminTokenEnabled: true,
      dualPlaneArchitecture: true
    };
  }

  function updateShieldConfig(patch = {}) {
    if (typeof patch.protectedTargetUrl === 'string' && patch.protectedTargetUrl.trim()) {
      const url = patch.protectedTargetUrl.trim().replace(/\/+$/, '');
      if (url.startsWith('https://') || url.startsWith('http://')) {
        shieldConfig.protectedTargetUrl = url;
      }
    }
    if (patch.shieldMode === 'standalone' || patch.shieldMode === 'reverse-proxy') {
      shieldConfig.shieldMode = patch.shieldMode;
    }
    if (patch.trustProxyHeaders !== undefined) {
      shieldConfig.trustProxyHeaders = Boolean(patch.trustProxyHeaders);
    }
    if (patch.injectDomCanary !== undefined) {
      shieldConfig.injectDomCanary = Boolean(patch.injectDomCanary);
    }
    if (Array.isArray(patch.trustedProxies)) {
      const validProxies = patch.trustedProxies.map((p) => String(p).trim()).filter(isValidIpAddress);
      if (validProxies.length > 0) shieldConfig.trustedProxies = validProxies;
    }
    if (patch.wafRules && typeof patch.wafRules === 'object') {
      for (const key of Object.keys(DEFAULT_WAF_RULES)) {
        if (Object.hasOwn(patch.wafRules, key)) {
          if (typeof DEFAULT_WAF_RULES[key] === 'boolean') {
            shieldConfig.wafRules[key] = Boolean(patch.wafRules[key]);
          } else {
            const num = Number(patch.wafRules[key]);
            if (Number.isFinite(num) && num >= 1 && num <= 10000) {
              shieldConfig.wafRules[key] = Math.floor(num);
            }
          }
        }
      }
    }
    if (typeof patch.webhookUrl === 'string') {
      const w = patch.webhookUrl.trim();
      if (w === '' || w.startsWith('https://') || w.startsWith('http://')) {
        shieldConfig.webhookUrl = w;
      }
    }
    if (typeof patch.webhookSecret === 'string' && !patch.webhookSecret.includes('••••')) {
      if (patch.webhookSecret.trim()) shieldConfig.webhookSecret = patch.webhookSecret.trim();
      else if (patch.webhookSecret === '__CLEAR__') shieldConfig.webhookSecret = '';
    }
    if (typeof patch.cloudflareApiToken === 'string' && !patch.cloudflareApiToken.includes('••••')) {
      if (patch.cloudflareApiToken.trim()) shieldConfig.cloudflareApiToken = patch.cloudflareApiToken.trim();
      else if (patch.cloudflareApiToken === '__CLEAR__') shieldConfig.cloudflareApiToken = '';
    }
    if (typeof patch.cloudflareZoneId === 'string') {
      shieldConfig.cloudflareZoneId = patch.cloudflareZoneId.trim();
    }

    store.saveSetting('shield_config_public', {
      protectedTargetUrl: shieldConfig.protectedTargetUrl,
      shieldMode: shieldConfig.shieldMode,
      trustProxyHeaders: shieldConfig.trustProxyHeaders,
      trustedProxies: shieldConfig.trustedProxies,
      injectDomCanary: shieldConfig.injectDomCanary,
      wafRules: shieldConfig.wafRules,
      webhookUrl: shieldConfig.webhookUrl,
      cloudflareZoneId: shieldConfig.cloudflareZoneId
    });
    store.saveSetting(
      'shield_secrets_vault',
      store.encryptSecretObject({
        webhookSecret: shieldConfig.webhookSecret,
        cloudflareApiToken: shieldConfig.cloudflareApiToken
      })
    );

    return getPublicShieldConfig();
  }

  const memory = new SwarmMemory(memoryFilePath, store);
  const swarm = new SwarmCoordinator(aiRouter, memory, () => shieldConfig);

  // H-07: Presupuesto adaptativo de sockets Tarpit para impedir DoS sobre tráfico legítimo
  const maxTarpitSockets = Number.isFinite(Number(options.maxTarpitSockets))
    ? Number(options.maxTarpitSockets)
    : 1000;
  const maxTarpitPerIp = Number.isFinite(Number(options.maxTarpitPerIp))
    ? Number(options.maxTarpitPerIp)
    : 2;
  let activeTarpitSockets = 0;
  const activeTarpitByIp = new Map();

  async function streamTarpitWithBudget(req, res, ip, { trapPayload, labyrinthResponse }) {
    const ipCount = activeTarpitByIp.get(ip) || 0;
    const budgetExhausted = activeTarpitSockets >= maxTarpitSockets || ipCount >= maxTarpitPerIp;

    const commonHeaders = {
      'X-Kernel-Verification-Directive': trapPayload.headerDirective,
      'X-Canary-Watermark': labyrinthResponse.canaryToken,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store'
    };

    if (budgetExhausted) {
      res.writeHead(403, {
        'Content-Type': 'application/json; charset=utf-8',
        ...commonHeaders
      });
      res.end(
        JSON.stringify({
          error: 'Access denied by perimeter shield.',
          canary_watermark: labyrinthResponse.canaryToken
        })
      );
      return;
    }

    activeTarpitSockets += 1;
    activeTarpitByIp.set(ip, ipCount + 1);
    memory.metrics.tarpitSocketsInUse = activeTarpitSockets;

    let released = false;
    const releaseSlot = () => {
      if (released) return;
      released = true;
      activeTarpitSockets = Math.max(0, activeTarpitSockets - 1);
      const cur = (activeTarpitByIp.get(ip) || 1) - 1;
      if (cur <= 0) activeTarpitByIp.delete(ip);
      else activeTarpitByIp.set(ip, cur);
      memory.metrics.tarpitSocketsInUse = activeTarpitSockets;
    };

    res.on('close', releaseSlot);
    res.on('finish', releaseSlot);

    try {
      res.writeHead(200, {
        'Content-Type': labyrinthResponse.contentType,
        ...commonHeaders
      });

      const totalDelay = Math.min(Math.max(0, labyrinthResponse.delayMs || 0), 60_000);
      const chunks = labyrinthResponse.chunks || [labyrinthResponse.body];

      if (totalDelay === 0 || chunks.length <= 1) {
        res.end(labyrinthResponse.body);
        return;
      }

      const stepDelay = Math.max(25, Math.floor(totalDelay / chunks.length));
      for (let i = 0; i < chunks.length; i += 1) {
        if (res.destroyed || req.destroyed) break;
        res.write(chunks[i]);
        if (i < chunks.length - 1) {
          await new Promise((resolve) => setTimeout(resolve, stepDelay));
        }
      }
      if (!res.destroyed && !res.writableEnded) {
        res.end();
      }
    } finally {
      releaseSlot();
    }
  }

  async function executeAndRecordCyberRange() {
    const cyberRange = await runLiveCyberRangeComparison(createGuardianesServer);
    memory.postDialogue({
      from: 'CHRONICLER',
      to: 'SWARM',
      severity: 'SUCCESS',
      modelUsed: 'live-cyber-range-v5.0',
      message:
        `Campo de Tiro Real completado: Sin escudo = ${cyberRange.round1Summary.breachesSucceeded}/${cyberRange.round1Summary.totalAttacks} brechas críticas. ` +
        `Con Guardianes Eternos = ${cyberRange.round2Summary.trappedByGuardianes}/${cyberRange.round2Summary.totalAttacks} ataques atrapados, ` +
        `${cyberRange.round2Summary.realDataLeaks} fugas reales, Anti-Spoofing=${cyberRange.antiSpoofCheck.spoofBlocked ? 'OK' : 'FAIL'}.`
    });

    for (const r of cyberRange.round2) {
      await swarm.handleIncomingRequest(
        {
          ip: r.id === 'artex-ip-spoof' ? '185.220.101.47' : '198.51.100.210',
          path: r.payload.split('?')[0],
          rawUrl: r.payload,
          userAgent: 'RedTeam-CyberRange/5.0',
          headers: {},
          query: {}
        },
        { skipDelay: true, internalActorKey: `sim:range_${r.id}` }
      );
    }
    return cyberRange;
  }

  const hermes = new HermesCommander({
    store,
    aiRouter,
    memory,
    swarm,
    shieldConfig,
    updateShieldConfig,
    runCyberRangeFn: executeAndRecordCyberRange,
    memoryFilePath
  });

  if (memory.dialogueBus.length === 0) {
    memory.postDialogue({
      from: 'CHRONICLER',
      to: 'SWARM',
      severity: 'INFO',
      modelUsed: 'deterministic-swarm-v1',
      message:
        `Guardianes Eternos v5.0 Dual-Plane activo (${store.isMemory ? 'SQLite memoria' : 'SQLite disco'}). ` +
        `Capa de decepción, 43+ canarios, WAF DPI multicapa y Byte-Drip Tarpit adaptativo protegiendo ${shieldConfig.protectedTargetUrl}.`
    });
  }

  // =========================================================================
  // 1. DATA PLANE SERVER (Público / Tráfico protegido — SIN rutas de admin)
  // =========================================================================
  const dataServer = http.createServer(async (req, res) => {
    try {
      const safeRawUrl = String(req.url || '/').replace(/^\/+/, '/');
      const reqUrl = new URL(safeRawUrl, `http://${req.headers.host || 'localhost'}`);
      const cleanPath = reqUrl.pathname;
      const method = (req.method || 'GET').toUpperCase();
      const query = Object.fromEntries(reqUrl.searchParams.entries());
      const { clientIp: ip, socketIp } = resolveClientIdentity(
        req,
        shieldConfig.trustProxyHeaders,
        shieldConfig.trustedProxies
      );
      const userAgent = String(req.headers['user-agent'] || '');

      // 1A. Sensor JS con Nonce HMAC firmado por servidor (H-03, M-03)
      if (method === 'GET' && cleanPath === '/guardianes-sensor.js') {
        const origin = `http${req.socket.encrypted ? 's' : ''}://${req.headers.host || '127.0.0.1:4040'}`;
        res.writeHead(200, {
          'Content-Type': 'application/javascript; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
          'Cache-Control': 'no-store'
        });
        res.end(
          buildSensorScript(origin, {
            sensorNonce: issueBeaconNonce(),
            injectTrapLink: shieldConfig.injectDomCanary
          })
        );
        return;
      }

      // 1B. robots.txt completo bloqueando TODOS los canarios para proteger SEO (H-04)
      if (method === 'GET' && cleanPath === '/robots.txt') {
        const allCanaries = Array.from(new Set([...CANARY_PATHS, ...hermes.customCanaries]));
        const robotsTxt = [
          'User-agent: *',
          'Allow: /',
          '# Legacy & internal canary routes (do not index)',
          ...allCanaries.map((p) => `Disallow: ${p}`)
        ].join('\n');
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'X-Content-Type-Options': 'nosniff'
        });
        res.end(robotsTxt);
        return;
      }

      // 1C. Preflight CORS + Telemetry Beacon con Nonce firmado (H-03, M-03)
      if (cleanPath === '/telemetry-beacon') {
        const corsHeaders = {
          'Access-Control-Allow-Origin': req.headers.origin ? String(req.headers.origin) : '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '600'
        };

        if (method === 'OPTIONS') {
          res.writeHead(204, corsHeaders);
          res.end();
          return;
        }

        if (method === 'POST') {
          const rawBuf = await readBodyBuffer(req, 16 * 1024);
          let body = {};
          try {
            body = JSON.parse(rawBuf.toString('utf8') || '{}');
          } catch {
            sendJson(res, 400, { error: 'Invalid telemetry payload.' }, corsHeaders);
            return;
          }

          if (!verifyBeaconNonce(body.nonce)) {
            sendJson(res, 403, { error: 'Invalid or expired sensor nonce.' }, corsHeaders);
            return;
          }

          // H-03: El beacon solo añade riesgo pasivo (+35) y telemetría; NUNCA cuarentena una IP por sí solo.
          const actorKey = `ip:${ip}`;
          const existing = memory.threatGraph.get(actorKey);
          const nextScore = Math.min(80, Math.max(existing?.riskScore || 0, 35));
          memory.recordThreatInteraction({
            actorKey,
            ip,
            userAgent: String(body.ua || userAgent).slice(0, 180),
            signature: existing?.signature || 'Headless-Browser-Sensor-Signal',
            riskScore: nextScore,
            pathVisited: String(body.href || '/').slice(0, 180),
            status: existing?.quarantined ? 'QUARANTINED' : 'SIGNAL_RECORDED',
            tokensBurned: 0,
            attackVectors: ['HEADLESS_WEBDRIVER_SENSOR'],
            quarantined: Boolean(existing?.quarantined)
          });
          sendJson(res, 200, { ok: true, signalRecorded: true, quarantined: Boolean(existing?.quarantined) }, corsHeaders);
          return;
        }
      }

      // 1D. Sidecar Endpoint para nginx auth_request (Pilar 3 / H-06)
      if (cleanPath === '/guardianes/check' && (method === 'GET' || method === 'HEAD')) {
        const origRaw = String(req.headers['x-original-uri'] || '/').replace(/^\/+/, '/');
        const origUrl = new URL(origRaw, 'http://localhost');
        const inspection = swarm.sentinel.inspect({
          ip,
          socketIp,
          path: origUrl.pathname,
          rawUrl: origUrl.pathname + origUrl.search,
          userAgent,
          headers: req.headers,
          bodyText: '',
          wafRules: shieldConfig.wafRules,
          customCanaries: shieldConfig.customCanaries || [],
          customKeywords: shieldConfig.customKeywords || []
        });

        if (inspection.isThreat) {
          res.writeHead(403, {
            'X-Guardianes-Decision': 'BLOCK',
            'X-Guardianes-Vectors': (inspection.attackVectors || []).join(','),
            'Cache-Control': 'no-store'
          });
          res.end();
          return;
        }
        res.writeHead(200, {
          'X-Guardianes-Decision': 'ALLOW',
          'Cache-Control': 'no-store'
        });
        res.end();
        return;
      }

      // 1E. Leer cuerpo en TODOS los métodos que puedan traer carga (incluyendo DELETE - H-01 / H-06)
      let rawBodyBuffer = Buffer.alloc(0);
      if (!['GET', 'HEAD'].includes(method)) {
        rawBodyBuffer = await readBodyBuffer(req, MAX_PROXY_BODY_BYTES);
      }
      const dpiBodyText =
        rawBodyBuffer.length > 0
          ? rawBodyBuffer.subarray(0, MAX_DPI_INSPECT_BYTES).toString('utf8')
          : '';

      // 1F. Inspección de Defensa Activa (Centinela WAF DPI + Canarios + Cuarentena dedicada)
      const defenseOutcome = await swarm.handleIncomingRequest({
        ip,
        socketIp,
        path: cleanPath,
        rawUrl: reqUrl.pathname + reqUrl.search,
        userAgent,
        headers: req.headers,
        query,
        bodyText: dpiBodyText
      });

      if (defenseOutcome.intercepted) {
        await streamTarpitWithBudget(req, res, ip, defenseOutcome);
        return;
      }

      // 1G. Reverse Proxy Streaming hacia servidor protegido (H-06)
      if (shieldConfig.shieldMode === 'reverse-proxy') {
        await proxyToProtectedTarget({
          req,
          res,
          targetBaseUrl: shieldConfig.protectedTargetUrl,
          reqUrl,
          rawBodyBuffer,
          injectDomCanary: shieldConfig.injectDomCanary
        });
        return;
      }

      // Respuesta limpia de Data Plane standalone (sin exponer SOC ni APIs de administración)
      sendJson(res, 200, {
        status: 'ok',
        perimeter: 'Guardianes Eternos Data Plane v5.0',
        protected: true
      });
    } catch (err) {
      const status = err?.message === 'Payload too large' ? 413 : 500;
      const clientMsg = status === 413 ? 'Payload too large.' : 'Internal Server Error.';
      sendJson(res, status, { error: clientMsg });
    }
  });

  // =========================================================================
  // 2. CONTROL PLANE SERVER (Solo loopback + Auth obligatoria + CSRF + SSE)
  // =========================================================================
  const sseClients = new Set();
  const onMemoryDelta = (delta) => {
    if (sseClients.size === 0) return;
    const frame = `event: ${delta.type}\ndata: ${JSON.stringify(delta)}\n\n`;
    for (const clientRes of sseClients) {
      if (clientRes.destroyed || clientRes.writableEnded) {
        sseClients.delete(clientRes);
        continue;
      }
      try {
        clientRes.write(frame);
      } catch {
        sseClients.delete(clientRes);
      }
    }
  };
  memory.on('delta', onMemoryDelta);

  const sseHeartbeat = setInterval(() => {
    for (const clientRes of sseClients) {
      if (clientRes.destroyed || clientRes.writableEnded) {
        sseClients.delete(clientRes);
        continue;
      }
      try {
        clientRes.write(': ping\n\n');
      } catch {
        sseClients.delete(clientRes);
      }
    }
  }, 20_000);
  if (typeof sseHeartbeat.unref === 'function') sseHeartbeat.unref();

  const controlServer = http.createServer(async (req, res) => {
    try {
      // C-02: Protección anti-DNS Rebinding mediante lista blanca estricta de Host
      if (!isAllowedControlHost(req.headers.host, allowedControlHosts)) {
        sendJson(res, 421, { error: 'Misdirected Request: Host no permitido en el Control Plane.' });
        return;
      }

      const safeRawUrl = String(req.url || '/').replace(/^\/+/, '/');
      const reqUrl = new URL(safeRawUrl, `http://${req.headers.host}`);
      const cleanPath = reqUrl.pathname;
      const method = (req.method || 'GET').toUpperCase();
      const cookies = parseCookies(req.headers.cookie || '');
      const session = verifySignedSessionCookie(cookies.guardianes_session);
      const hasBearer = verifyBearerOrHeaderToken(req);

      const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

      // C-02: En todas las rutas mutantes, validar Origin/Sec-Fetch-Site (403) y Content-Type: application/json (415)
      if (isMutating) {
        if (!isSafeControlOrigin(req, allowedControlHosts)) {
          sendJson(res, 403, { error: 'Forbidden: origen cross-site bloqueado por política anti-CSRF.' });
          return;
        }
        const ct = String(req.headers['content-type'] || '').toLowerCase();
        if (!ct.includes('application/json')) {
          sendJson(res, 415, { error: 'Unsupported Media Type: se requiere Content-Type: application/json.' });
          return;
        }
      }

      // 2A. Endpoints de Autenticación del Control Plane
      if (cleanPath === '/api/auth/login' && method === 'POST') {
        const body = await readJsonBody(req);
        const token = String(body.token || '').trim();
        if (!token || !timingSafeHexEquals(sha256Hex(token), adminTokenHash)) {
          sendJson(res, 401, { error: 'Credenciales inválidas.' });
          return;
        }
        const sessionId = crypto.randomBytes(24).toString('hex');
        const csrfToken = crypto.randomBytes(24).toString('hex');
        activeSessions.set(sessionId, {
          csrfToken,
          expiresAt: Date.now() + 12 * 3600 * 1000
        });
        const signedCookie = signSessionId(sessionId);
        sendJson(
          res,
          200,
          { ok: true, authenticated: true, csrfToken },
          {
            'Set-Cookie': `guardianes_session=${encodeURIComponent(signedCookie)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`
          }
        );
        return;
      }

      if (cleanPath === '/api/auth/session' && method === 'GET') {
        if (hasBearer) {
          sendJson(res, 200, { ok: true, authenticated: true, authMode: 'bearer', csrfToken: null });
          return;
        }
        if (session) {
          sendJson(res, 200, { ok: true, authenticated: true, authMode: 'cookie', csrfToken: session.csrfToken });
          return;
        }
        sendJson(res, 200, { ok: true, authenticated: false });
        return;
      }

      if (cleanPath === '/api/auth/logout' && method === 'POST') {
        if (session) activeSessions.delete(session.sessionId);
        sendJson(
          res,
          200,
          { ok: true, authenticated: false },
          {
            'Set-Cookie': 'guardianes_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
          }
        );
        return;
      }

      // 2B. Archivos estáticos de la UI del SOC (index.html y /soc3d/soc3d.js)
      if (
        method === 'GET' &&
        (cleanPath === '/' || cleanPath === '/index.html' || cleanPath === '/soc' || cleanPath === '/soc/')
      ) {
        const targetFile = path.resolve(publicDir, 'index.html');
        if (!targetFile.startsWith(path.resolve(publicDir))) {
          sendJson(res, 403, { error: 'Forbidden' });
          return;
        }
        const html = fs.readFileSync(targetFile, 'utf8');
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'SAMEORIGIN',
          'Referrer-Policy': 'no-referrer'
        });
        res.end(html);
        return;
      }

      if (method === 'GET' && cleanPath === '/soc3d/soc3d.js') {
        const targetFile = path.resolve(publicDir, 'soc3d', 'soc3d.js');
        if (!targetFile.startsWith(path.resolve(publicDir)) || !fs.existsSync(targetFile)) {
          sendJson(res, 404, { error: 'Not Found' });
          return;
        }
        const js = fs.readFileSync(targetFile, 'utf8');
        res.writeHead(200, {
          'Content-Type': 'application/javascript; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
          'Cache-Control': 'no-cache'
        });
        res.end(js);
        return;
      }

      // 2C. Barrera de Autenticación Obligatoria para /events y /api/guardianes/* (C-01 & C-02)
      if (cleanPath === '/events' || cleanPath.startsWith('/api/guardianes/')) {
        if (!hasBearer && !session) {
          sendJson(res, 401, { error: 'No autorizado: inicia sesión o envía Authorization: Bearer <token>.' });
          return;
        }
        // Si autentica por cookie en método mutante, exige cabecera X-CSRF-Token válida
        if (isMutating && !hasBearer) {
          const providedCsrf = String(req.headers['x-csrf-token'] || '');
          if (!timingSafeHexEquals(providedCsrf, session.csrfToken)) {
            sendJson(res, 403, { error: 'Forbidden: token X-CSRF-Token inválido o ausente.' });
            return;
          }
        }
      }

      // 2D. Stream Server-Sent Events (SSE) en tiempo real para el SOC Holográfico 3D
      if (cleanPath === '/events' && method === 'GET') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache, no-transform',
          Connection: 'keep-alive',
          'X-Accel-Buffering': 'no'
        });
        sseClients.add(res);
        res.write(
          `event: hello\ndata: ${JSON.stringify({
            timestamp: new Date().toISOString(),
            metrics: memory.metrics
          })}\n\n`
        );
        req.on('close', () => {
          sseClients.delete(res);
        });
        return;
      }

      // 2E. Endpoints de Operaciones del Centro de Mando
      if (cleanPath === '/api/guardianes/state' && method === 'GET') {
        sendJson(res, 200, {
          ok: true,
          canaryPaths: [...CANARY_PATHS, ...hermes.customCanaries],
          hermesState: hermes.getState(),
          snapshot: memory.snapshot(aiRouter.getPublicConfig(), getPublicShieldConfig())
        });
        return;
      }

      if (cleanPath === '/api/guardianes/hermes/state' && method === 'GET') {
        sendJson(res, 200, {
          ok: true,
          hermesState: hermes.getState()
        });
        return;
      }

      if (cleanPath === '/api/guardianes/hermes/chat' && method === 'POST') {
        const body = await readJsonBody(req);
        const turn = await hermes.chat(body.message || '', {
          confirm: Boolean(body.confirm),
          cancel: Boolean(body.cancel),
          confirmationId: body.confirmationId || null
        });
        sendJson(res, 200, {
          ok: true,
          turn,
          hermesState: hermes.getState(),
          canaryPaths: [...CANARY_PATHS, ...hermes.customCanaries],
          snapshot: memory.snapshot(aiRouter.getPublicConfig(), getPublicShieldConfig())
        });
        return;
      }

      if (cleanPath === '/api/guardianes/openrouter-models' && method === 'GET') {
        const result = await aiRouter.fetchOpenRouterModels();
        sendJson(res, 200, {
          ok: true,
          ...result,
          ai: aiRouter.getPublicConfig()
        });
        return;
      }

      if (cleanPath === '/api/guardianes/config' && method === 'POST') {
        const body = await readJsonBody(req);
        const updated = aiRouter.updateConfig(body);
        aiRouter.saveToStore(store);
        memory.postDialogue({
          from: 'CHRONICLER',
          to: 'SWARM',
          severity: 'INFO',
          modelUsed: `${updated.activePerGuardian.CHRONICLER.provider}:${updated.activePerGuardian.CHRONICLER.model}`,
          message: `Motores de IA guardados en SQLite: modo "${updated.mode.toUpperCase()}", límite ${updated.maxApiCallsPerHour} API/h, Tarpit ${updated.tarpitDelayMs} ms.`
        });
        sendJson(res, 200, {
          ok: true,
          ai: updated,
          snapshot: memory.snapshot(updated, getPublicShieldConfig())
        });
        return;
      }

      if (cleanPath === '/api/guardianes/shield' && method === 'POST') {
        const body = await readJsonBody(req);
        const updatedShield = updateShieldConfig(body);
        memory.postDialogue({
          from: 'SENTINEL',
          to: 'SWARM',
          severity: 'INFO',
          modelUsed: 'waf-dpi-engine-v5',
          message: `Escudo WAF actualizado: objetivo ${updatedShield.protectedTargetUrl} (${updatedShield.shieldMode}).`
        });
        sendJson(res, 200, {
          ok: true,
          shield: updatedShield,
          snapshot: memory.snapshot(aiRouter.getPublicConfig(), updatedShield)
        });
        return;
      }

      if (cleanPath === '/api/guardianes/quarantine' && method === 'POST') {
        const body = await readJsonBody(req);
        const target = String(body.target || '').trim();
        const quarantined = Boolean(body.quarantined);
        if (!target) {
          sendJson(res, 400, { error: 'Falta parámetro target (actorKey o IP).' });
          return;
        }
        const updated = memory.setQuarantine(target, quarantined);
        memory.flushNow();
        memory.postDialogue({
          from: 'SENTINEL',
          to: 'SWARM',
          severity: quarantined ? 'CRITICAL' : 'INFO',
          modelUsed: 'waf-dpi-engine-v5',
          message: quarantined
            ? `Operador activó CUARENTENA manual para ${target}.`
            : `Operador liberó de cuarentena a ${target}.`
        });
        sendJson(res, 200, {
          ok: true,
          updated,
          snapshot: memory.snapshot(aiRouter.getPublicConfig(), getPublicShieldConfig())
        });
        return;
      }

      if (cleanPath === '/api/guardianes/export/nginx' && method === 'GET') {
        const conf = exportNginxDenyConf(Array.from(memory.threatGraph.values()));
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'Content-Disposition': 'attachment; filename="guardianes-deny.conf"'
        });
        res.end(conf);
        return;
      }

      if (cleanPath === '/api/guardianes/export/iptables' && method === 'GET') {
        const script = exportIptablesScript(Array.from(memory.threatGraph.values()));
        res.writeHead(200, {
          'Content-Type': 'text/x-shellscript; charset=utf-8',
          'Content-Disposition': 'attachment; filename="guardianes-iptables.sh"'
        });
        res.end(script);
        return;
      }

      if (cleanPath === '/api/guardianes/export/cloudflare' && method === 'GET') {
        const cfRule = exportCloudflareWaf(Array.from(memory.threatGraph.values()));
        sendJson(res, 200, cfRule, {
          'Content-Disposition': 'attachment; filename="guardianes-cloudflare-waf.json"'
        });
        return;
      }

      if (cleanPath === '/api/guardianes/deploy-kit' && method === 'GET') {
        const dataOrigin = `http://${process.env.DATA_PUBLIC_HOST || '127.0.0.1:4040'}`;
        const kit = buildDeployKit({
          guardianBaseUrl: dataOrigin,
          protectedTargetUrl: shieldConfig.protectedTargetUrl
        });
        sendJson(res, 200, { ok: true, kit });
        return;
      }

      if (cleanPath === '/api/guardianes/audit' && method === 'POST') {
        const body = await readJsonBody(req);
        const audit = await swarm.runAuditPentest(typeof body.mode === 'string' ? body.mode : 'full-audit');
        memory.flushNow();
        sendJson(res, 200, {
          ok: true,
          audit,
          snapshot: memory.snapshot(aiRouter.getPublicConfig(), getPublicShieldConfig())
        });
        return;
      }

      if (cleanPath === '/api/guardianes/simulate' && method === 'POST') {
        const body = await readJsonBody(req);
        const scenario = typeof body.scenario === 'string' ? body.scenario : 'artex';
        const simulation = await swarm.runSimulation(scenario);
        memory.flushNow();
        sendJson(res, 200, {
          ok: true,
          simulation,
          snapshot: memory.snapshot(aiRouter.getPublicConfig(), getPublicShieldConfig())
        });
        return;
      }

      if (cleanPath === '/api/guardianes/cyber-range' && method === 'POST') {
        const cyberRange = await executeAndRecordCyberRange();
        memory.flushNow();
        sendJson(res, 200, {
          ok: true,
          cyberRange,
          snapshot: memory.snapshot(aiRouter.getPublicConfig(), getPublicShieldConfig())
        });
        return;
      }

      if (cleanPath === '/api/guardianes/report' && method === 'POST') {
        const report = await swarm.chronicler.generateExecutiveReport({ syncToDisk: true });
        sendJson(res, 200, {
          ok: true,
          report,
          snapshot: memory.snapshot(aiRouter.getPublicConfig(), getPublicShieldConfig())
        });
        return;
      }

      if (cleanPath === '/api/guardianes/reset' && method === 'POST') {
        memory.reset(true);
        swarm.sentinel.rateLimiter.reset();
        memory.postDialogue({
          from: 'CHRONICLER',
          to: 'SWARM',
          severity: 'INFO',
          modelUsed: 'deterministic-swarm-v1',
          message: 'Sesión y base SQLite de amenazas limpiadas. 43+ cebos canario y WAF DPI vigilando.'
        });
        sendJson(res, 200, {
          ok: true,
          snapshot: memory.snapshot(aiRouter.getPublicConfig(), getPublicShieldConfig())
        });
        return;
      }

      sendJson(res, 404, { error: 'Endpoint no encontrado en el Control Plane.' });
    } catch (err) {
      const status =
        err?.message === 'Payload too large'
          ? 413
          : err?.message === 'Invalid JSON body'
            ? 400
            : 500;
      const clientMsg =
        status === 413
          ? 'Payload too large.'
          : status === 400
            ? 'Invalid JSON body.'
            : 'Internal Server Error.';
      sendJson(res, status, { error: clientMsg });
    }
  });

  // Hardening HTTP timeouts en ambos servidores (H-07)
  for (const srv of [dataServer, controlServer]) {
    srv.headersTimeout = 10_000;
    srv.requestTimeout = 70_000;
    srv.keepAliveTimeout = 5_000;
    srv.maxConnections = 2000;
  }

  let cleanedUp = false;
  function cleanupResources() {
    if (cleanedUp) return;
    cleanedUp = true;
    clearInterval(sseHeartbeat);
    memory.off('delta', onMemoryDelta);
    for (const c of sseClients) {
      try {
        c.end();
      } catch {
        // ignore
      }
    }
    sseClients.clear();
    memory.stopTimers();
    try {
      store.close();
    } catch {
      // ignore
    }
  }

  async function closeAll() {
    await Promise.all([
      new Promise((resolve) => (dataServer.listening ? dataServer.close(() => resolve()) : resolve())),
      new Promise((resolve) => (controlServer.listening ? controlServer.close(() => resolve()) : resolve()))
    ]);
    cleanupResources();
  }

  // Si alguien cierra el servidor directamente sin closeAll(), aseguramos limpieza si ambos están cerrados
  const maybeCleanup = () => {
    if (!dataServer.listening && !controlServer.listening) {
      cleanupResources();
    }
  };
  dataServer.on('close', maybeCleanup);
  controlServer.on('close', maybeCleanup);

  return {
    dataServer,
    controlServer,
    server: dataServer,
    store,
    aiRouter,
    memory,
    swarm,
    hermes,
    generatedAdminToken,
    issueBeaconNonce,
    closeAll
  };
}

const isDirectExecution =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename);

if (isDirectExecution) {
  const dataPort = Number(process.env.PORT) || 4040;
  const controlPort = Number(process.env.CONTROL_PORT) || 4041;
  const dataHost = process.env.DATA_HOST || '127.0.0.1';
  const controlHost = process.env.CONTROL_HOST || '127.0.0.1';

  const { dataServer, controlServer, generatedAdminToken } = createGuardianesServer();

  dataServer.listen(dataPort, dataHost, () => {
    console.log(`🛡️  Guardianes Eternos v5.0 [DATA PLANE]    activo en http://${dataHost}:${dataPort}`);
  });

  controlServer.listen(controlPort, controlHost, () => {
    console.log(`🎛️  Guardianes Eternos v5.0 [CONTROL PLANE] activo en http://${controlHost}:${controlPort}`);
    if (generatedAdminToken) {
      console.log(`🔑  [PRIMER ARRANQUE] Admin Token generado (guárdalo ahora, solo se muestra una vez):`);
      console.log(`    GUARDIANES_ADMIN_TOKEN=${generatedAdminToken}`);
    } else if (process.env.GUARDIANES_ADMIN_TOKEN) {
      console.log('🔐  Admin Token cargado desde variable de entorno GUARDIANES_ADMIN_TOKEN.');
    } else {
      console.log('🔐  Admin Token cargado desde hash persistido en SQLite.');
    }
  });
}
