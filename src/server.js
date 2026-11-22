/**
 * @fileoverview Servidor HTTP Nativo de Guardianes Eternos v5.1 (Arquitectura Enterprise Dual-Plane).
 * - Data Plane (puerto 4040): Capa de Decepción (43+ canarios + Byte-Drip Tarpit con presupuesto de sockets),
 *   Detector Estructural (body completo + gzip/deflate/br + todas las cabeceras - N-01),
 *   FCrDNS BotVerifier (N-02), bloqueo puntual sin cuarentena 24h en hits heurísticos (N-03),
 *   sidecar /guardianes/check autenticado con persistencia (N-04),
 *   Reverse Proxy Streaming + X-Forwarded-For real + WebSocket Upgrade nativo (N-06).
 * - Control Plane (puerto 4041, loopback): Auth obligatoria + Rate-Limit en login (N-07),
 *   anti-CSRF + anti-DNS-Rebinding (C-02), SSE en vivo GET /events para SOC Holográfico 3D y Comandante Hermes v5.1.
 */

import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AIRouter } from './engine/aiRouter.js';
import { SwarmMemory } from './engine/swarmMemory.js';
import { SQLiteStore } from './engine/sqliteStore.js';
import { CANARY_PATHS, DEFAULT_WAF_RULES } from './engine/sentinelWaf.js';
import { SearchBotVerifier } from './engine/botVerifier.js';
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
const MAX_TEXT_INSPECT_BYTES = 2 * 1024 * 1024; // 2 MB límite de inspección completa (elimina punto ciego de 64 KB - N-01)
const MAX_PROXY_BODY_BYTES = 20 * 1024 * 1024;
const DEFAULT_TRUSTED_PROXIES = ['127.0.0.1', '::1'];
const LOGIN_MAX_FAILURES = 5;
const LOGIN_WINDOW_MS = 5 * 60 * 1000;

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

const BINARY_CONTENT_TYPE_REGEX =
  /^(?:image\/|video\/|audio\/|font\/|application\/octet-stream|application\/pdf|application\/zip|application\/gzip|application\/x-tar|application\/wasm)/i;

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
 * N-01: Extrae texto completo del cuerpo para inspección estructural, descomprimiendo gzip/deflate/br
 * con tope anti zip-bomb (2 MB) y sin dejar un punto ciego a partir de 64 KB.
 * Los binarios puros (imágenes, PDF, octet-stream) pasan íntegros sin corrupción UTF-8.
 */
function extractInspectableBodyText(rawBodyBuffer, contentType = '', contentEncoding = '') {
  if (!rawBodyBuffer || rawBodyBuffer.length === 0) return { text: '', errorStatus: null };

  const ct = String(contentType || '').toLowerCase().trim();
  const ce = String(contentEncoding || '').toLowerCase().trim();

  // Binarios reales no se decodifican como UTF-8 salvo que vengan marcados como texto/JSON/XML/form
  if (BINARY_CONTENT_TYPE_REGEX.test(ct)) {
    return { text: '', errorStatus: null };
  }

  let inspectBuf = rawBodyBuffer;

  if (ce && ce !== 'identity') {
    try {
      if (ce.includes('gzip')) {
        inspectBuf = zlib.gunzipSync(rawBodyBuffer, { maxOutputLength: MAX_TEXT_INSPECT_BYTES });
      } else if (ce.includes('deflate')) {
        inspectBuf = zlib.inflateSync(rawBodyBuffer, { maxOutputLength: MAX_TEXT_INSPECT_BYTES });
      } else if (ce.includes('br')) {
        inspectBuf = zlib.brotliDecompressSync(rawBodyBuffer, { maxOutputLength: MAX_TEXT_INSPECT_BYTES });
      } else {
        return { text: '', errorStatus: 415 };
      }
    } catch (err) {
      if (err?.code === 'ERR_BUFFER_TOO_LARGE') {
        return { text: '', errorStatus: 413 };
      }
      return { text: '', errorStatus: 400 };
    }
  }

  // Si un cuerpo textual supera el límite máximo inspeccionable (2 MB), se rechaza con 413
  // en lugar de dejar pasar bytes sin inspeccionar (N-01).
  if (inspectBuf.length > MAX_TEXT_INSPECT_BYTES) {
    return { text: '', errorStatus: 413 };
  }

  return { text: inspectBuf.toString('utf8'), errorStatus: null };
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
 * H-06 & N-06: Reverse Proxy streaming nativo con http.request / https.request.
 * - Conserva Buffer binario sin corrupción, Cookie/Authorization/Set-Cookie/Cache-Control/302.
 * - Sobrescribe/anexa X-Forwarded-For y X-Real-IP con la IP real verificada (N-06).
 */
function proxyToProtectedTarget({
  req,
  res,
  targetBaseUrl,
  reqUrl,
  rawBodyBuffer,
  clientIp,
  socketIp,
  trustProxyHeaders = false,
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
      if (HOP_BY_HOP_HEADERS.has(lower) || lower === 'host' || lower === 'x-forwarded-for' || lower === 'x-real-ip') {
        continue;
      }
      if (v !== undefined) forwardHeaders[k] = v;
    }
    forwardHeaders.host = destination.host;

    // N-06: Garantiza que el backend reciba la IP real y nunca un X-Forwarded-For falsificado
    const verifiedIp = clientIp || socketIp || '127.0.0.1';
    if (trustProxyHeaders && req.headers['x-forwarded-for']) {
      forwardHeaders['x-forwarded-for'] = `${verifiedIp}, ${socketIp}`;
    } else {
      forwardHeaders['x-forwarded-for'] = socketIp || verifiedIp;
    }
    forwardHeaders['x-real-ip'] = verifiedIp;
    forwardHeaders['x-forwarded-proto'] = req.socket?.encrypted ? 'https' : 'http';

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

        resHeaders['X-Protected-By'] = 'Guardianes-Eternos-Deception/5.1';
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
      sendJson(res, 502, { error: 'No se pudo conectar con el servidor protegido aguas arriba.' });
      resolve();
    });

    if (rawBodyBuffer && rawBodyBuffer.length > 0 && !['GET', 'HEAD'].includes((req.method || 'GET').toUpperCase())) {
      upstreamReq.write(rawBodyBuffer);
    }
    upstreamReq.end();
  });
}

/**
 * N-06: Proxy nativo de WebSocket (`101 Switching Protocols`) mediante túnel TCP/TLS en `server.on('upgrade')`.
 */
function proxyWebSocketUpgrade({
  req,
  clientSocket,
  head,
  targetBaseUrl,
  clientIp,
  socketIp,
  trustProxyHeaders,
  trackedSockets = null
}) {
  let destination;
  try {
    const safeRawUrl = String(req.url || '/').replace(/^\/+/, '/');
    destination = new URL(safeRawUrl, targetBaseUrl);
  } catch {
    clientSocket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
    return;
  }

  const isTls = destination.protocol === 'https:' || destination.protocol === 'wss:';
  const port = Number(destination.port) || (isTls ? 443 : 80);

  const onConnect = (upstreamSocket) => {
    const lines = [`${req.method || 'GET'} ${destination.pathname}${destination.search} HTTP/1.1`];
    const skip = new Set(['host', 'x-forwarded-for', 'x-real-ip']);
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i];
      const val = req.rawHeaders[i + 1];
      if (!name || skip.has(name.toLowerCase())) continue;
      lines.push(`${name}: ${val}`);
    }
    const verifiedIp = clientIp || socketIp || '127.0.0.1';
    lines.push(`Host: ${destination.host}`);
    lines.push(`X-Forwarded-For: ${trustProxyHeaders ? `${verifiedIp}, ${socketIp}` : socketIp || verifiedIp}`);
    lines.push(`X-Real-IP: ${verifiedIp}`);
    lines.push('', '');

    upstreamSocket.write(lines.join('\r\n'));
    if (head && head.length > 0) upstreamSocket.write(head);

    upstreamSocket.pipe(clientSocket);
    clientSocket.pipe(upstreamSocket);
  };

  const upstreamSocket = isTls
    ? tls.connect({ host: destination.hostname, port, servername: destination.hostname }, () =>
        onConnect(upstreamSocket)
      )
    : net.connect({ host: destination.hostname, port }, () => onConnect(upstreamSocket));

  if (trackedSockets) {
    trackedSockets.add(clientSocket);
    trackedSockets.add(upstreamSocket);
  }

  const teardown = () => {
    if (trackedSockets) {
      trackedSockets.delete(clientSocket);
      trackedSockets.delete(upstreamSocket);
    }
    if (!upstreamSocket.destroyed) upstreamSocket.destroy();
    if (!clientSocket.destroyed) clientSocket.destroy();
  };

  upstreamSocket.on('error', () => {
    if (!clientSocket.destroyed) {
      clientSocket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
    }
    teardown();
  });
  clientSocket.on('error', teardown);
  clientSocket.on('end', teardown);
  clientSocket.on('close', teardown);
  upstreamSocket.on('end', teardown);
  upstreamSocket.on('close', teardown);
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

  // C-01 & N-07: Token administrativo obligatorio
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

  // N-04: Secreto compartido obligatorio para el endpoint sidecar nginx /guardianes/check
  const sidecarSecret =
    options.sidecarSecret ||
    process.env.GUARDIANES_SIDECAR_SECRET ||
    crypto.randomBytes(24).toString('hex');

  const sessionHmacSecret = crypto.randomBytes(32);
  const beaconHmacSecret = crypto.randomBytes(32);
  const activeSessions = new Map();
  const loginFailures = new Map(); // ip -> { count, windowStart } (N-07)

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
      dualPlaneArchitecture: true,
      sidecarAuthRequired: true
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

  const botVerifier = options.botVerifier || new SearchBotVerifier();
  const memory = new SwarmMemory(memoryFilePath, store);
  const swarm = new SwarmCoordinator(aiRouter, memory, () => shieldConfig, botVerifier);

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
      modelUsed: 'deterministic-local:cyber-range-v5.1',
      message:
        `Campo de Tiro Real completado: Sin escudo = ${cyberRange.round1Summary.breachesSucceeded}/${cyberRange.round1Summary.totalAttacks} brechas. ` +
        `Con Guardianes Eternos = ${cyberRange.round2Summary.trappedByGuardianes}/${cyberRange.round2Summary.totalAttacks} ataques detenidos, ` +
        `${cyberRange.round2Summary.realDataLeaks} fugas reales, Anti-Spoofing=${cyberRange.antiSpoofCheck.spoofBlocked ? 'OK' : 'FAIL'}.`
    });

    for (const r of cyberRange.round2) {
      await swarm.handleIncomingRequest(
        {
          ip: r.id === 'artex-ip-spoof' ? '185.220.101.47' : '198.51.100.210',
          path: r.payload.split('?')[0],
          rawUrl: r.payload,
          userAgent: 'RedTeam-CyberRange/5.1',
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
      modelUsed: 'deterministic-local:boot-v5.1',
      message:
        `Guardianes Eternos v5.1 Dual-Plane activo (${store.isMemory ? 'SQLite memoria' : 'SQLite disco'}). ` +
        `Capa de decepción (43+ canarios, Tarpit adaptativo y detector estructural) protegiendo ${shieldConfig.protectedTargetUrl}.`
    });
  }

  // =========================================================================
  // 1. DATA PLANE SERVER (Tráfico protegido — SIN rutas de administración)
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

      // 1A. Sensor JS con Nonce HMAC firmado
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

      // 1B. robots.txt completo bloqueando TODOS los canarios (H-04)
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

      // 1C. Telemetry Beacon con CORS + Nonce HMAC firmado (H-03, M-03)
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
          sendJson(
            res,
            200,
            { ok: true, signalRecorded: true, quarantined: Boolean(existing?.quarantined) },
            corsHeaders
          );
          return;
        }
      }

      // 1D. N-04: Sidecar Nginx auth_request autenticado (evita oráculo público + registra amenazas/cuarentenas)
      if (cleanPath === '/guardianes/check' && (method === 'GET' || method === 'HEAD')) {
        const trustedSet = new Set(shieldConfig.trustedProxies.map((p) => String(p).replace(/^::ffff:/, '').trim()));
        const providedSidecarSecret = String(req.headers['x-guardianes-sidecar-secret'] || '');
        if (!trustedSet.has(socketIp) || !timingSafeHexEquals(providedSidecarSecret, sidecarSecret)) {
          sendJson(res, 403, { error: 'Sidecar authorization required.' });
          return;
        }

        const origRaw = String(req.headers['x-original-uri'] || '/').replace(/^\/+/, '/');
        const origUrl = new URL(origRaw, 'http://localhost');
        const origQuery = Object.fromEntries(origUrl.searchParams.entries());
        const sidecarIdentity = resolveClientIdentity(req, true, shieldConfig.trustedProxies);

        // Registra amenazas y cuarentenas igual que el modo proxy (N-04)
        const outcome = await swarm.handleIncomingRequest(
          {
            ip: sidecarIdentity.clientIp,
            socketIp: sidecarIdentity.socketIp,
            path: origUrl.pathname,
            rawUrl: origUrl.pathname + origUrl.search,
            userAgent,
            headers: req.headers,
            query: origQuery,
            bodyText: ''
          },
          { skipDelay: true }
        );

        if (outcome.intercepted) {
          res.writeHead(403, {
            'X-Guardianes-Decision': 'BLOCK',
            'X-Guardianes-Vectors': (outcome.inspection?.attackVectors || []).join(','),
            'X-Guardianes-Quarantined': String(Boolean(outcome.threatEntry?.quarantined)),
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

      // 1E. Lectura de cuerpo completo + descompresión gzip/deflate/br sin punto ciego de 64 KB (N-01)
      let rawBodyBuffer = Buffer.alloc(0);
      if (!['GET', 'HEAD'].includes(method)) {
        rawBodyBuffer = await readBodyBuffer(req, MAX_PROXY_BODY_BYTES);
      }

      const { text: dpiBodyText, errorStatus: bodyDecodeErr } = extractInspectableBodyText(
        rawBodyBuffer,
        req.headers['content-type'],
        req.headers['content-encoding']
      );
      if (bodyDecodeErr) {
        const msg =
          bodyDecodeErr === 413
            ? 'Request body exceeds inspectable limit.'
            : bodyDecodeErr === 415
              ? 'Unsupported Content-Encoding.'
              : 'Malformed compressed request body.';
        sendJson(res, bodyDecodeErr, { error: msg });
        return;
      }

      // 1F. Inspección de Defensa Activa (Canarios + Detector Estructural + FCrDNS + Política N-03)
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
        // N-03: Un golpe heurístico aislado devuelve 403 puntual sin cuarentena 24h ni laberinto
        if (defenseOutcome.responseMode === 'REQUEST_BLOCK_ONLY') {
          sendJson(
            res,
            403,
            {
              error: 'Request blocked by structural inspection.',
              blocked: true,
              quarantined: false
            },
            {
              'X-Guardianes-Blocked': 'true',
              'X-Guardianes-Vectors': (defenseOutcome.inspection?.attackVectors || []).join(',')
            }
          );
          return;
        }

        await streamTarpitWithBudget(req, res, ip, defenseOutcome);
        return;
      }

      // 1G. Reverse Proxy Streaming con X-Forwarded-For real verificado (N-06)
      if (shieldConfig.shieldMode === 'reverse-proxy') {
        await proxyToProtectedTarget({
          req,
          res,
          targetBaseUrl: shieldConfig.protectedTargetUrl,
          reqUrl,
          rawBodyBuffer,
          clientIp: ip,
          socketIp,
          trustProxyHeaders: shieldConfig.trustProxyHeaders,
          injectDomCanary: shieldConfig.injectDomCanary
        });
        return;
      }

      sendJson(res, 200, {
        status: 'ok',
        perimeter: 'Guardianes Eternos Data Plane v5.1',
        protected: true
      });
    } catch (err) {
      const status = err?.message === 'Payload too large' ? 413 : 500;
      const clientMsg = status === 413 ? 'Payload too large.' : 'Internal Server Error.';
      sendJson(res, status, { error: clientMsg });
    }
  });

  const activeUpgradeSockets = new Set();

  // N-06: Soporte nativo de WebSockets (`101 Switching Protocols`) a través del Reverse Proxy
  dataServer.on('upgrade', (req, clientSocket, head) => {
    if (shieldConfig.shieldMode !== 'reverse-proxy') {
      clientSocket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      return;
    }

    const safeRawUrl = String(req.url || '/').replace(/^\/+/, '/');
    let reqUrl;
    try {
      reqUrl = new URL(safeRawUrl, `http://${req.headers.host || 'localhost'}`);
    } catch {
      clientSocket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      return;
    }

    const { clientIp, socketIp } = resolveClientIdentity(
      req,
      shieldConfig.trustProxyHeaders,
      shieldConfig.trustedProxies
    );
    const inspection = swarm.sentinel.inspect({
      ip: clientIp,
      socketIp,
      path: reqUrl.pathname,
      rawUrl: reqUrl.pathname + reqUrl.search,
      userAgent: String(req.headers['user-agent'] || ''),
      headers: req.headers,
      bodyText: '',
      wafRules: shieldConfig.wafRules,
      customCanaries: shieldConfig.customCanaries || [],
      customKeywords: shieldConfig.customKeywords || []
    });

    if (inspection.isThreat) {
      clientSocket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      return;
    }

    proxyWebSocketUpgrade({
      req,
      clientSocket,
      head,
      targetBaseUrl: shieldConfig.protectedTargetUrl,
      clientIp,
      socketIp,
      trustProxyHeaders: shieldConfig.trustProxyHeaders,
      trackedSockets: activeUpgradeSockets
    });
  });

  // =========================================================================
  // 2. CONTROL PLANE SERVER (Loopback + Auth + Login Rate-Limit + CSRF + SSE)
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
      const { socketIp: controlClientIp } = resolveClientIdentity(req, false);

      const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

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

      // 2A. Autenticación del Control Plane con Rate-Limit anti fuerza bruta (N-07)
      if (cleanPath === '/api/auth/login' && method === 'POST') {
        const nowMs = Date.now();
        let failRec = loginFailures.get(controlClientIp);
        if (failRec && nowMs - failRec.windowStart > LOGIN_WINDOW_MS) {
          loginFailures.delete(controlClientIp);
          failRec = null;
        }
        if (failRec && failRec.count >= LOGIN_MAX_FAILURES) {
          const retryAfterSec = Math.max(1, Math.ceil((LOGIN_WINDOW_MS - (nowMs - failRec.windowStart)) / 1000));
          sendJson(
            res,
            429,
            { error: 'Demasiados intentos fallidos de inicio de sesión. Intenta más tarde.' },
            { 'Retry-After': String(retryAfterSec) }
          );
          return;
        }

        const body = await readJsonBody(req);
        const token = String(body.token || '').trim();
        if (!token || !timingSafeHexEquals(sha256Hex(token), adminTokenHash)) {
          const nextCount = (failRec?.count || 0) + 1;
          loginFailures.set(controlClientIp, {
            count: nextCount,
            windowStart: failRec?.windowStart || nowMs
          });
          sendJson(res, 401, { error: 'Credenciales inválidas.' });
          return;
        }

        loginFailures.delete(controlClientIp);
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

      // 2B. Archivos estáticos de la UI del SOC
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

      // 2C. Barrera de Autenticación Obligatoria
      if (cleanPath === '/events' || cleanPath.startsWith('/api/guardianes/')) {
        if (!hasBearer && !session) {
          sendJson(res, 401, { error: 'No autorizado: inicia sesión o envía Authorization: Bearer <token>.' });
          return;
        }
        if (isMutating && !hasBearer) {
          const providedCsrf = String(req.headers['x-csrf-token'] || '');
          if (!timingSafeHexEquals(providedCsrf, session.csrfToken)) {
            sendJson(res, 403, { error: 'Forbidden: token X-CSRF-Token inválido o ausente.' });
            return;
          }
        }
      }

      // 2D. Stream SSE en vivo
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

      // 2E. Endpoints del Centro de Mando
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
          modelUsed: 'deterministic-local:config-v5.1',
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
          modelUsed: 'deterministic-local:config-v5.1',
          message: `Escudo actualizado: objetivo ${updatedShield.protectedTargetUrl} (${updatedShield.shieldMode}).`
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
          modelUsed: 'deterministic-local:quarantine-v5.1',
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
          modelUsed: 'deterministic-local:reset-v5.1',
          message: 'Sesión y base SQLite de amenazas limpiadas. 43+ cebos canario y detector estructural vigilando.'
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
    for (const s of activeUpgradeSockets) {
      try {
        s.destroy();
      } catch {
        // ignore
      }
    }
    activeUpgradeSockets.clear();
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
      new Promise((resolve) => {
        if (!dataServer.listening) return resolve();
        dataServer.close(() => resolve());
        dataServer.closeAllConnections?.();
      }),
      new Promise((resolve) => {
        if (!controlServer.listening) return resolve();
        controlServer.close(() => resolve());
        controlServer.closeAllConnections?.();
      })
    ]);
    cleanupResources();
  }

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
    botVerifier,
    sidecarSecret,
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
    console.log(`🛡️  Guardianes Eternos v5.1 [DATA PLANE]    activo en http://${dataHost}:${dataPort}`);
  });

  controlServer.listen(controlPort, controlHost, () => {
    console.log(`🎛️  Guardianes Eternos v5.1 [CONTROL PLANE] activo en http://${controlHost}:${controlPort}`);
    if (generatedAdminToken) {
      console.log('🔑  [PRIMER ARRANQUE] Admin Token generado (guárdalo ahora, solo se muestra una vez):');
      console.log(`    GUARDIANES_ADMIN_TOKEN=${generatedAdminToken}`);
    } else if (process.env.GUARDIANES_ADMIN_TOKEN) {
      if (process.env.GUARDIANES_ADMIN_TOKEN.length < 24) {
        console.warn('⚠️  [SEGURIDAD] GUARDIANES_ADMIN_TOKEN tiene menos de 24 caracteres. Usa un token largo aleatorio en producción.');
      } else {
        console.log('🔐  Admin Token cargado desde variable de entorno GUARDIANES_ADMIN_TOKEN.');
      }
    } else {
      console.log('🔐  Admin Token cargado desde hash persistido en SQLite.');
    }
    if (!process.env.GUARDIANES_VAULT_KEY) {
      console.warn('⚠️  [M-02] GUARDIANES_VAULT_KEY no configurada: usando data/.vault.key local. Define GUARDIANES_VAULT_KEY en producción.');
    }
  });
}
