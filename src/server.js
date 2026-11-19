/**
 * @fileoverview Servidor HTTP Nativo de Guardianes Eternos v2.0 (Producción).
 * Integra SQLite Nativo (node:sqlite), WAF DPI, Byte-Drip Socket Tarpit,
 * Reverse Proxy Shield, Sensor JS, Exportadores Firewall (Cloudflare/Nginx/iptables)
 * y Centro de Mando Visual.
 */

import crypto from 'node:crypto';
import http from 'node:http';
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
const MAX_DPI_BODY_BYTES = 64 * 1024;

function maskSecret(val) {
  if (!val || typeof val !== 'string') return '';
  const t = val.trim();
  if (t.length <= 8) return '••••••••';
  return `${t.slice(0, 4)}••••${t.slice(-4)}`;
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  res.end(body);
}

function readRawBody(req, maxBytes = MAX_JSON_BODY_BYTES) {
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
      resolve(chunks.length === 0 ? '' : Buffer.concat(chunks).toString('utf8'));
    });

    req.on('error', reject);
  });
}

async function readJsonBody(req) {
  const raw = await readRawBody(req, MAX_JSON_BODY_BYTES);
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('Invalid JSON body');
  }
}

function resolveClientIdentity(req, trustProxyHeaders = false) {
  const remoteRaw = String(req.socket?.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '');
  const socketIp = isValidIpAddress(remoteRaw) ? remoteRaw : '127.0.0.1';

  if (trustProxyHeaders) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
      const candidate = forwarded.split(',')[0].replace(/^::ffff:/, '').trim();
      if (isValidIpAddress(candidate)) {
        return { clientIp: candidate, socketIp };
      }
    }
  }

  return { clientIp: socketIp, socketIp };
}

function isAuthorizedControlRequest(req, socketIp, adminToken) {
  if (adminToken) {
    const authHeader = String(req.headers['authorization'] || '');
    const customToken = String(req.headers['x-guardianes-admin-token'] || '');
    const provided = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : customToken.trim();
    const a = Buffer.from(provided);
    const b = Buffer.from(adminToken);
    if (a.length !== b.length || a.length === 0) return false;
    return crypto.timingSafeEqual(a, b);
  }
  // Sin token explícito, las rutas administrativas solo responden al operador local en loopback
  return socketIp === '127.0.0.1' || socketIp === '::1';
}

/**
 * Envía el laberinto mediante Byte-Drip Socket Streaming para retener hilos ofensivos reales.
 */
async function streamTarpitResponse(req, res, { trapPayload, labyrinthResponse }) {
  res.writeHead(200, {
    'Content-Type': labyrinthResponse.contentType,
    'X-Kernel-Verification-Directive': trapPayload.headerDirective,
    'X-Canary-Watermark': labyrinthResponse.canaryToken,
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store'
  });

  const totalDelay = Math.min(Math.max(0, labyrinthResponse.delayMs || 0), 4000);
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
  if (!res.destroyed) {
    res.end();
  }
}

/**
 * Inyecta cabeceras de blindaje HTTP y cebo DOM invisible en tráfico HTML de Reverse Proxy.
 */
async function proxyToProtectedTarget({ req, res, targetBaseUrl, reqUrl, bodyText }) {
  const destination = new URL(reqUrl.pathname + reqUrl.search, targetBaseUrl);
  const forwardHeaders = {
    'User-Agent': req.headers['user-agent'] || 'GuardianesEternos-Shield/2.0',
    Accept: req.headers['accept'] || '*/*'
  };
  if (req.headers['content-type']) {
    forwardHeaders['Content-Type'] = req.headers['content-type'];
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);

  try {
    const upstream = await fetch(destination.toString(), {
      method: req.method,
      headers: forwardHeaders,
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : bodyText || undefined,
      signal: controller.signal
    });

    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    const securityHeaders = {
      'Content-Type': contentType,
      'X-Protected-By': 'Guardianes-Eternos-Swarm-WAF/2.0',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    };

    if (contentType.includes('text/html')) {
      let html = await upstream.text();
      const stealthCanary =
        '<a href="/api/v1/internal/admin-keys" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;opacity:0" tabindex="-1" aria-hidden="true">Internal Admin Vault</a>' +
        '<script src="/guardianes-sensor.js" defer></script>';
      if (html.includes('</body>')) {
        html = html.replace('</body>', `${stealthCanary}</body>`);
      } else {
        html += stealthCanary;
      }
      res.writeHead(upstream.status, securityHeaders);
      res.end(html);
      return;
    }

    const buf = Buffer.from(await upstream.arrayBuffer());
    res.writeHead(upstream.status, securityHeaders);
    res.end(buf);
  } catch (err) {
    sendJson(res, 502, {
      error: 'No se pudo conectar con el servidor protegido aguas arriba.',
      detail: err.message
    });
  } finally {
    clearTimeout(timer);
  }
}

export function createGuardianesServer(options = {}) {
  const memoryFilePath = options.memoryFilePath || DEFAULT_MEMORY_FILE;
  const publicDir = options.publicDir || DEFAULT_PUBLIC_DIR;
  const dbPath = options.dbPath !== undefined ? options.dbPath : DEFAULT_DB_FILE;

  const store = new SQLiteStore(dbPath);
  const aiRouter = new AIRouter(options.aiConfig || {});
  if (!options.aiConfig) {
    aiRouter.loadFromStore(store);
  } else if (options.aiConfig.tarpitDelayMs !== undefined) {
    aiRouter.updateConfig({ tarpitDelayMs: options.aiConfig.tarpitDelayMs });
  }

  // Configuración del Escudo WAF y Reverse Proxy
  const savedShield = store.loadSetting('shield_config_public', null);
  const savedShieldSecrets = store.decryptSecretObject(store.loadSetting('shield_secrets_vault', null));
  const override = options.shieldConfigOverride || {};
  const adminToken = options.adminToken || process.env.GUARDIANES_ADMIN_TOKEN || '';

  const shieldConfig = {
    protectedTargetUrl: override.protectedTargetUrl || savedShield?.protectedTargetUrl || 'https://www.365collaboration.net',
    shieldMode:
      override.shieldMode || (savedShield?.shieldMode === 'reverse-proxy' ? 'reverse-proxy' : 'standalone'),
    trustProxyHeaders:
      override.trustProxyHeaders !== undefined
        ? Boolean(override.trustProxyHeaders)
        : Boolean(savedShield?.trustProxyHeaders),
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
      wafRules: { ...shieldConfig.wafRules },
      webhookUrl: shieldConfig.webhookUrl,
      webhookSecretConfigured: Boolean(shieldConfig.webhookSecret),
      webhookSecretMasked: maskSecret(shieldConfig.webhookSecret),
      cloudflareZoneId: shieldConfig.cloudflareZoneId,
      cloudflareTokenConfigured: Boolean(shieldConfig.cloudflareApiToken),
      cloudflareTokenMasked: maskSecret(shieldConfig.cloudflareApiToken),
      adminTokenEnabled: Boolean(adminToken)
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

  async function executeAndRecordCyberRange() {
    const cyberRange = await runLiveCyberRangeComparison(createGuardianesServer);
    memory.postDialogue({
      from: 'CHRONICLER',
      to: 'SWARM',
      severity: 'SUCCESS',
      modelUsed: 'live-cyber-range-v3.1',
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
          userAgent: 'RedTeam-CyberRange/3.1',
          headers: { 'x-sim-session': `range_${r.id}` },
          query: {}
        },
        { skipDelay: true }
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
        `Guardianes Eternos v3.1 Blindado en producción (${store.isMemory ? 'SQLite memoria' : 'SQLite disco'}). ` +
        `42+ cebos canario por familia, WAF DPI multicapa y Byte-Drip Tarpit protegiendo ${shieldConfig.protectedTargetUrl}.`
    });
  }

  const server = http.createServer(async (req, res) => {
    try {
      const safeRawUrl = String(req.url || '/').replace(/^\/+/, '/');
      const reqUrl = new URL(safeRawUrl, `http://${req.headers.host || 'localhost'}`);
      const cleanPath = reqUrl.pathname;
      const method = (req.method || 'GET').toUpperCase();
      const query = Object.fromEntries(reqUrl.searchParams.entries());
      const { clientIp: ip, socketIp } = resolveClientIdentity(req, shieldConfig.trustProxyHeaders);
      const userAgent = String(req.headers['user-agent'] || '');

      // 1. Sensor JS instalable para páginas reales
      if (method === 'GET' && cleanPath === '/guardianes-sensor.js') {
        const origin = `http${req.socket.encrypted ? 's' : ''}://${req.headers.host || '127.0.0.1:4040'}`;
        res.writeHead(200, {
          'Content-Type': 'application/javascript; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
          'Cache-Control': 'public, max-age=300'
        });
        res.end(buildSensorScript(origin));
        return;
      }

      // 2. robots.txt con cebos silenciosos para crawlers agresivos
      if (method === 'GET' && cleanPath === '/robots.txt') {
        const robotsTxt = [
          'User-agent: *',
          'Allow: /',
          '# Legacy staging archives (do not index)',
          ...CANARY_PATHS.slice(0, 10).map((p) => `Disallow: ${p}`)
        ].join('\n');
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(robotsTxt);
        return;
      }

      // 3. Control Plane API & Ruta dedicada /soc (protege / cuando actúa como Reverse Proxy o lleva query)
      const isProtectedRoot =
        cleanPath === '/' && (shieldConfig.shieldMode === 'reverse-proxy' || reqUrl.search !== '');
      const isControlPlane =
        cleanPath.startsWith('/api/guardianes/') ||
        cleanPath === '/soc' ||
        cleanPath === '/soc/' ||
        cleanPath === '/index.html' ||
        (cleanPath === '/' && !isProtectedRoot);

      let bodyText = '';
      if (!isControlPlane && ['POST', 'PUT', 'PATCH'].includes(method)) {
        bodyText = await readRawBody(req, MAX_DPI_BODY_BYTES);
      }

      // 4. Inspección de Defensa Activa: Centinela (WAF DPI Multicapa + Canarios + Anti-Spoofing)
      if (!isControlPlane) {
        const defenseOutcome = await swarm.handleIncomingRequest({
          ip,
          socketIp,
          path: cleanPath,
          rawUrl: reqUrl.pathname + reqUrl.search,
          userAgent,
          headers: req.headers,
          query,
          bodyText
        });

        if (defenseOutcome.intercepted) {
          await streamTarpitResponse(req, res, defenseOutcome);
          return;
        }

        // Si el tráfico es legítimo y está activo el Reverse Proxy Shield, reenviar blindado
        if (shieldConfig.shieldMode === 'reverse-proxy') {
          await proxyToProtectedTarget({
            req,
            res,
            targetBaseUrl: shieldConfig.protectedTargetUrl,
            reqUrl,
            bodyText
          });
          return;
        }
      }

      // Guardián de Autenticación Administrativa para el Control Plane (excluyendo telemetría pública)
      if (cleanPath.startsWith('/api/guardianes/') && cleanPath !== '/api/guardianes/telemetry-beacon') {
        if (!isAuthorizedControlRequest(req, socketIp, adminToken)) {
          sendJson(res, 401, { error: 'No autorizado: se requiere acceso local o GUARDIANES_ADMIN_TOKEN válido.' });
          return;
        }
      }

      // 5. Endpoints de Operaciones del Centro de Mando
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
        const turn = await hermes.chat(body.message);
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

      if (cleanPath === '/api/guardianes/telemetry-beacon' && method === 'POST') {
        const body = await readJsonBody(req);
        const actorKey = `ip:${ip}`;
        const { entry } = memory.recordThreatInteraction({
          actorKey,
          ip,
          userAgent: String(body.ua || userAgent),
          signature: 'Headless-Browser-Sensor',
          riskScore: 94,
          pathVisited: String(body.href || '/'),
          status: 'QUARANTINED',
          tokensBurned: 0,
          attackVectors: ['HEADLESS_WEBDRIVER_SENSOR'],
          quarantined: true
        });
        memory.postDialogue({
          from: 'SENTINEL',
          to: 'CHRONICLER',
          severity: 'CRITICAL',
          modelUsed: 'browser-sensor-v2',
          message: `Sensor JS detectó navegador automatizado (WebDriver) desde ${ip}. IP puesta en CUARENTENA ACTIVA.`
        });
        sendJson(res, 200, { ok: true, quarantined: entry.quarantined });
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
          modelUsed: 'waf-dpi-engine-v2',
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
        memory.postDialogue({
          from: 'SENTINEL',
          to: 'SWARM',
          severity: quarantined ? 'CRITICAL' : 'INFO',
          modelUsed: 'waf-dpi-engine-v2',
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
        const origin = `http${req.socket.encrypted ? 's' : ''}://${req.headers.host || '127.0.0.1:4040'}`;
        const kit = buildDeployKit({
          guardianBaseUrl: origin,
          protectedTargetUrl: shieldConfig.protectedTargetUrl
        });
        sendJson(res, 200, { ok: true, kit });
        return;
      }

      if (cleanPath === '/api/guardianes/audit' && method === 'POST') {
        const body = await readJsonBody(req);
        const audit = await swarm.runAuditPentest(typeof body.mode === 'string' ? body.mode : 'full-audit');
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
        sendJson(res, 200, {
          ok: true,
          simulation,
          snapshot: memory.snapshot(aiRouter.getPublicConfig(), getPublicShieldConfig())
        });
        return;
      }

      if (cleanPath === '/api/guardianes/cyber-range' && method === 'POST') {
        const cyberRange = await executeAndRecordCyberRange();
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
          message: 'Sesión y base SQLite de amenazas limpiadas. 42 cebos canario y WAF DPI vigilando.'
        });
        sendJson(res, 200, {
          ok: true,
          snapshot: memory.snapshot(aiRouter.getPublicConfig(), getPublicShieldConfig())
        });
        return;
      }

      // 6. Centro de Mando Visual (/soc siempre accesible aunque / sea Reverse Proxy)
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
          'X-Frame-Options': 'SAMEORIGIN'
        });
        res.end(html);
        return;
      }

      sendJson(res, 404, { error: 'Ruta no encontrada en el perímetro público.' });
    } catch (err) {
      const status =
        err.message === 'Payload too large' ? 413 : err.message === 'Invalid JSON body' ? 400 : 500;
      sendJson(res, status, { error: err.message || 'Internal Server Error' });
    }
  });

  server.on('close', () => {
    try {
      store.close();
    } catch {
      // ignora cierre repetido
    }
  });

  return { server, store, aiRouter, memory, swarm, hermes };
}

const isDirectExecution =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename);

if (isDirectExecution) {
  const port = Number(process.env.PORT) || 4040;
  const { server } = createGuardianesServer();
  server.listen(port, '127.0.0.1', () => {
    console.log(`🛡️  Guardianes Eternos v4.0 (Comandante Hermes + WAF SOC) activo en http://127.0.0.1:${port}`);
    console.log('⚡  Hermes Anti-Prompt-Injection + SQLite Nativo + WAF DPI + Byte-Drip Tarpit listos.');
  });
}
