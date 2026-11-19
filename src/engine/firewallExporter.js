/**
 * @fileoverview Exportador Real de Reglas de Firewall (Nginx, iptables, Cloudflare WAF),
 * Webhooks firmados con HMAC-SHA256, Cloudflare Auto-Ban y Generador de Kits de Despliegue.
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
    '# Guardianes Eternos — Reglas de Bloqueo Automático Nginx',
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
    '# Guardianes Eternos — Bloqueo a Nivel Kernel Linux (iptables / ufw)',
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
 * Envía una alerta webhook firmada con HMAC-SHA256 hacia Slack, Discord, n8n o SIEM.
 */
export async function dispatchSignedWebhook({ webhookUrl, webhookSecret = '', event }) {
  if (!webhookUrl || (!webhookUrl.startsWith('https://') && !webhookUrl.startsWith('http://'))) {
    return { sent: false, reason: 'invalid_url' };
  }

  const body = JSON.stringify(event);
  const headers = {
    'Content-Type': 'application/json',
    'User-Agent': 'GuardianesEternos-Webhook/2.0'
  };

  if (webhookSecret) {
    const sig = crypto.createHmac('sha256', webhookSecret).update(body).digest('hex');
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
 * Genera el sensor JS ligero para incrustar en cualquier sitio web (ej. 365collaboration.net).
 */
export function buildSensorScript(shieldEndpointBase = '') {
  const endpoint = shieldEndpointBase ? `${shieldEndpointBase.replace(/\/+$/, '')}` : '';
  return `/* Guardianes Eternos Browser & Headless Sensor v2.0 (MIT) */
(function(){
  try {
    var isHeadless = Boolean(navigator.webdriver || window.__playwright || window._phantom || window.callPhantom);
    var trap = document.createElement('a');
    trap.href = '${endpoint}/api/v1/internal/admin-keys';
    trap.textContent = 'Internal Admin Vault';
    trap.setAttribute('aria-hidden', 'true');
    trap.setAttribute('tabindex', '-1');
    trap.style.cssText = 'position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;';
    if (document.body) document.body.appendChild(trap);

    if (isHeadless) {
      fetch('${endpoint}/api/guardianes/telemetry-beacon', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'HEADLESS_BROWSER_DETECTED',
          webdriver: Boolean(navigator.webdriver),
          href: location.href,
          ua: navigator.userAgent
        })
      }).catch(function(){});
    }
  } catch (e) {}
})();
`;
}

/**
 * Construye el Kit de Despliegue Real para WordPress, Next.js, Cloudflare Workers y HTML estático.
 */
export function buildDeployKit({ guardianBaseUrl = 'https://shield.365collaboration.net', protectedTargetUrl = 'https://www.365collaboration.net' } = {}) {
  const base = guardianBaseUrl.replace(/\/+$/, '');
  const target = protectedTargetUrl.replace(/\/+$/, '');

  return {
    protectedTargetUrl: target,
    guardianBaseUrl: base,
    htmlSensorSnippet: `<!-- Pegar antes de </body> en ${target} -->\n<script src="${base}/guardianes-sensor.js" defer></script>`,
    wordpressPhpSnippet: `<?php
/**
 * Pegar en wp-content/mu-plugins/guardianes-eternos.php
 * Redirige escáneres de secretos e intentos SQLi/RCE hacia el Laberinto Tarpit de Guardianes Eternos.
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
