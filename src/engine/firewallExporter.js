/**
 * @fileoverview Exportador Real de Reglas de Firewall (Nginx, iptables, Cloudflare WAF),
 * Webhooks firmados con HMAC-SHA256 + Timestamp anti-replay (M-06),
 * Cloudflare Auto-Ban y Generador de Kits de Despliegue (incl. Nginx auth_request sidecar).
 */

import crypto from 'node:crypto';
import net from 'node:net';

/**
 * Valida estrictamente que una IP sea IPv4 o IPv6 válida para prevenir inyección en archivos de firewall.
 */
export function isValidIpAddress(rawIp) {
  if (!rawIp || typeof rawIp !== 'string') return false;
  const trimmed = rawIp.trim();
  return net.isIP(trimmed) !== 0;
}

/**
 * Extrae IPs únicas validadas de amenazas cuarentenadas o de alto riesgo.
 */
export function extractHostileIps(threats = []) {
  const unique = new Set();
  for (const t of threats) {
    if (!t || (!t.quarantined && (t.riskScore || 0) < 80)) continue;
    const clean = String(t.ip || '').replace(/^::ffff:/, '').trim();
    if (isValidIpAddress(clean) && clean !== '127.0.0.1' && clean !== '::1') {
      unique.add(clean);
    }
  }
  return Array.from(unique);
}

export function exportNginxDenyConf(threats = []) {
  const ips = extractHostileIps(threats);
  const lines = [
    '# Guardianes Eternos v5.0 — Reglas de Bloqueo Automático Nginx',
    `# Generado: ${new Date().toISOString()}`,
    '# Incluir en /etc/nginx/conf.d/guardianes-deny.conf y ejecutar: nginx -t && systemctl reload nginx',
    ''
  ];

  if (ips.length === 0) {
    lines.push('# Ninguna IP hostil externa en cuarentena todavía.');
  } else {
    for (const ip of ips) {
      lines.push(`deny ${ip};`);
    }
  }
  return lines.join('\n');
}

export function exportIptablesScript(threats = []) {
  const ips = extractHostileIps(threats);
  const lines = [
    '#!/usr/bin/env bash',
    '# Guardianes Eternos v5.0 — Bloqueo a Nivel Kernel Linux (iptables / ufw)',
    `# Generado: ${new Date().toISOString()}`,
    'set -euo pipefail',
    ''
  ];

  if (ips.length === 0) {
    lines.push('echo "No hay IPs hostiles externas en cuarentena para bloquear."');
  } else {
    for (const ip of ips) {
      const cmd = net.isIPv6(ip) ? 'ip6tables' : 'iptables';
      lines.push(`${cmd} -C INPUT -s ${ip} -j DROP 2>/dev/null || ${cmd} -A INPUT -s ${ip} -j DROP`);
    }
    lines.push('echo "Bloqueo Guardianes Eternos aplicado correctamente."');
  }
  return lines.join('\n');
}

export function exportCloudflareWaf(threats = []) {
  const ips = extractHostileIps(threats);
  const expression =
    ips.length > 0
      ? `(ip.src in {${ips.join(' ')}})`
      : '(http.request.uri.path in {"/.env" "/.env.prod" "/api/v1/internal/admin-keys"})';

  return {
    generatedAt: new Date().toISOString(),
    ipsCount: ips.length,
    ips,
    cloudflareWafRule: {
      description: 'Guardianes Eternos — Block Quarantined Autonomous Attackers & Canary Probes',
      action: 'block',
      expression,
      enabled: true
    }
  };
}

/**
 * Envía una alerta webhook firmada con HMAC-SHA256 sobre `${timestamp}.${body}`
 * incluyendo `X-Guardianes-Timestamp` para defensa anti-replay (M-06).
 */
export async function dispatchSignedWebhook({ webhookUrl, webhookSecret = '', event }) {
  if (!webhookUrl || (!webhookUrl.startsWith('https://') && !webhookUrl.startsWith('http://'))) {
    return { sent: false, reason: 'invalid_url' };
  }

  const body = JSON.stringify(event);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const headers = {
    'Content-Type': 'application/json',
    'User-Agent': 'GuardianesEternos-Webhook/5.0',
    'X-Guardianes-Timestamp': timestamp
  };

  if (webhookSecret) {
    const sig = crypto
      .createHmac('sha256', webhookSecret)
      .update(`${timestamp}.${body}`)
      .digest('hex');
    headers['X-Guardianes-Signature'] = `sha256=${sig}`;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const res = await fetch(webhookUrl, { method: 'POST', headers, body, signal: controller.signal });
    return { sent: res.ok, status: res.status };
  } catch (err) {
    return { sent: false, reason: err.message };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Envía un bloqueo IP directo a Cloudflare Access Rules API cuando el usuario configura Token + Zone ID.
 */
export async function pushCloudflareIpBlock({ apiToken, zoneId, ip, note = 'Blocked by Guardianes Eternos' }) {
  if (!apiToken || !zoneId || !isValidIpAddress(ip)) {
    return { pushed: false, reason: 'missing_credentials_or_invalid_ip' };
  }

  const url = `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zoneId)}/firewall/access_rules/rules`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiToken}`
      },
      body: JSON.stringify({
        mode: 'block',
        configuration: { target: net.isIPv6(ip) ? 'ip6' : 'ip', value: ip },
        notes: note
      }),
      signal: controller.signal
    });
    const data = await res.json();
    return { pushed: Boolean(data?.success), status: res.status };
  } catch (err) {
    return { pushed: false, reason: err.message };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Genera el sensor JS ligero con nonce firmado por el servidor (H-03) y sendBeacon cross-origin (M-03).
 * Usa rel="nofollow noopener" para no afectar SEO ni crawlers legítimos (H-04).
 */
export function buildSensorScript(shieldEndpointBase = '', { sensorNonce = '', injectTrapLink = false } = {}) {
  const endpoint = shieldEndpointBase ? `${shieldEndpointBase.replace(/\/+$/, '')}` : '';
  const safeNonce = String(sensorNonce || '').replace(/[^a-zA-Z0-9._-]/g, '');

  return `/* Guardianes Eternos Browser & Headless Sensor v5.0 (MIT) */
(function(){
  try {
    var isHeadless = Boolean(navigator.webdriver || window.__playwright || window._phantom || window.callPhantom);
    if (${injectTrapLink ? 'true' : 'false'}) {
      var trap = document.createElement('a');
      trap.href = '${endpoint}/api/v1/internal/admin-keys';
      trap.textContent = 'Internal Admin Vault';
      trap.setAttribute('rel', 'nofollow noopener');
      trap.setAttribute('aria-hidden', 'true');
      trap.setAttribute('tabindex', '-1');
      trap.style.cssText = 'position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;';
      if (document.body) document.body.appendChild(trap);
    }

    if (isHeadless) {
      var payload = JSON.stringify({
        type: 'HEADLESS_BROWSER_DETECTED',
        nonce: '${safeNonce}',
        webdriver: Boolean(navigator.webdriver),
        href: location.href,
        ua: navigator.userAgent
      });
      var beaconUrl = '${endpoint}/telemetry-beacon';
      if (navigator.sendBeacon) {
        navigator.sendBeacon(beaconUrl, new Blob([payload], { type: 'text/plain;charset=UTF-8' }));
      } else {
        fetch(beaconUrl, {
          method: 'POST',
          mode: 'cors',
          headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
          body: payload
        }).catch(function(){});
      }
    }
  } catch (e) {}
})();
`;
}

/**
 * Construye el Kit de Despliegue Real para Nginx auth_request Sidecar, WordPress, Next.js,
 * Cloudflare Workers y HTML estático.
 */
export function buildDeployKit({
  guardianBaseUrl = 'https://shield.365collaboration.net',
  protectedTargetUrl = 'https://www.365collaboration.net'
} = {}) {
  const base = guardianBaseUrl.replace(/\/+$/, '');
  const target = protectedTargetUrl.replace(/\/+$/, '');

  return {
    protectedTargetUrl: target,
    guardianBaseUrl: base,
    nginxAuthRequestSnippet: `# Recomendado para producción: Nginx / Caddy Sidecar con auth_request (cero latencia en estáticos)
# Colocar dentro de server { ... } para ${target}
location = /guardianes/check {
    internal;
    proxy_pass http://127.0.0.1:4040/guardianes/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header User-Agent $http_user_agent;
}

location / {
    auth_request /guardianes/check;
    error_page 403 = @guardianes_tarpit;
    proxy_pass ${target};
}

location @guardianes_tarpit {
    proxy_pass http://127.0.0.1:4040;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}`,
    htmlSensorSnippet: `<!-- Pegar antes de </body> en ${target} -->\n<script src="${base}/guardianes-sensor.js" defer></script>`,
    wordpressPhpSnippet: `<?php
/**
 * Pegar en wp-content/mu-plugins/guardianes-eternos.php
 * Redirige escáneres de secretos hacia el Laberinto Tarpit de Guardianes Eternos.
 */
add_action('init', function () {
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $traps = ['/.env', '/.env.prod', '/.git/config', '/wp-config.php.bak', '/xmlrpc.php', '/vendor/phpunit'];
    foreach ($traps as $t) {
        if (stripos($uri, $t) !== false) {
            header('Location: ${base}' . $uri, true, 307);
            exit;
        }
    }
});
`,
    nextjsMiddlewareSnippet: `// middleware.ts (Next.js App Router) para ${target}
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const CANARY_PREFIXES = ['/.env', '/.git', '/wp-config.php.bak', '/api/v1/internal/admin-keys', '/actuator/env'];

export function middleware(req: NextRequest) {
  const path = req.nextUrl.pathname;
  if (CANARY_PREFIXES.some((p) => path.startsWith(p))) {
    return NextResponse.rewrite(new URL(path + req.nextUrl.search, '${base}'));
  }
  const res = NextResponse.next();
  res.headers.set('X-Frame-Options', 'SAMEORIGIN');
  res.headers.set('X-Content-Type-Options', 'nosniff');
  return res;
}
`,
    cloudflareWorkerSnippet: `// Cloudflare Worker de Borde para proteger ${target} con Guardianes Eternos
const SHIELD_ORIGIN = '${base}';
const CANARY_ROUTES = ['/.env', '/.env.prod', '/.git/config', '/wp-config.php.bak', '/api/v1/internal/admin-keys'];

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const isCanary = CANARY_ROUTES.some((r) => url.pathname.startsWith(r));
    const hasAttack = /(union\\s+select|<script|\\$\\{jndi:|\\.\\.\\/)/i.test(decodeURIComponent(url.search));
    if (isCanary || hasAttack) {
      return fetch(SHIELD_ORIGIN + url.pathname + url.search, request);
    }
    return fetch(request);
  }
};
`
  };
}
