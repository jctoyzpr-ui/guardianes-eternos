/**
 * @fileoverview Benchmark Independiente v5.3 de Guardianes Eternos.
 * Mide y reporta porcentajes honestos sobre conjuntos independientes (sin copiar informes externos):
 *   1. Tasa de detección (%) sobre patrones OWASP genéricos por familia (REST, multipart, UTF-16, JSON profundo, SSTI, etc.)
 *   2. Tasa de falsos positivos (%) y tasa de bloqueo a clientes (%) sobre textos reales de comercio electrónico y soporte
 *   3. Rendimiento en página de tienda con 80 archivos a través del proxy
 *   4. Resiliencia CPU ante bodies repetitivos de 2 MB (comprimidos con gzip y planos)
 */

import http from 'node:http';
import zlib from 'node:zlib';
import { createGuardianesServer } from '../src/server.js';
import { inspectPayloadDPI, decodeBufferToInspectableText } from '../src/engine/sentinelWaf.js';
import { SearchBotVerifier } from '../src/engine/botVerifier.js';

function pct(part, total) {
  return total === 0 ? '0.0%' : `${((part / total) * 100).toFixed(1)}%`;
}

// 1. Corpus independiente de patrones OWASP por familia (REST, query, JSON profundo, multipart, UTF-16, headers)
const deepJsonNoSql = (() => {
  let obj = { $gt: '' };
  for (let i = 0; i < 18; i += 1) obj = { nested: obj };
  return JSON.stringify(obj);
})();

const longArrayNoSql = JSON.stringify({
  items: [...Array.from({ length: 260 }, (_, i) => i), { role: { $ne: 'guest' } }]
});

const multipartSqli = [
  '------WebKitFormBoundary7MA4YWxkTrZu0gW',
  'Content-Disposition: form-data; name="bio"',
  '',
  'A'.repeat(6000),
  '------WebKitFormBoundary7MA4YWxkTrZu0gW',
  'Content-Disposition: form-data; name="coupon"',
  '',
  "' OR 1 LIKE 1-- ",
  '------WebKitFormBoundary7MA4YWxkTrZu0gW--'
].join('\r\n');

const OWASP_BENCHMARK_CASES = [
  // SQLi (REST path, multipart, tautologies without '=', long prefix, UNION, blind)
  { family: 'SQLi', rawUrl: "/api/orders/99' OR TRUE-- " },
  { family: 'SQLi', rawUrl: "/items?code=' OR 'x' LIKE 'x" },
  { family: 'SQLi', rawUrl: '/items?id=42 OR 1 IS NOT NULL' },
  { family: 'SQLi', rawUrl: '/items?id=5 OR 5 IN (5,6)' },
  { family: 'SQLi', rawUrl: '/items?id=7 UNION ALL SELECT null,table_name FROM information_schema.tables' },
  { family: 'SQLi', rawUrl: '/items?id=3; INSERT INTO logs VALUES (1)' },
  { family: 'SQLi', rawUrl: '/items?id=10 ORDER BY 25#' },
  { family: 'SQLi', rawUrl: '/upload', contentType: 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW', bodyText: multipartSqli },
  { family: 'SQLi', rawUrl: '/api/long', bodyText: JSON.stringify({ text: `${'word '.repeat(1200)} ' OR 1=1-- ` }) },
  // XSS (unclosed tag, JS context breakout, SVG/event handlers, URI scheme, UTF-16)
  { family: 'XSS', rawUrl: '/search?q=<img/src=x/onerror=alert(1)' },
  { family: 'XSS', rawUrl: '/search?q=<svg/onmouseenter=confirm(1)' },
  { family: 'XSS', rawUrl: "/search?q='-alert(1)-'" },
  { family: 'XSS', rawUrl: '/search?q=" ;prompt(1);//' },
  { family: 'XSS', rawUrl: '/search?next=javascript:void(alert(1))' },
  { family: 'XSS', rawUrl: '/search?q=<iframe src="javascript:alert(1)">' },
  { family: 'XSS', rawUrl: '/api/utf16', bodyText: decodeBufferToInspectableText(Buffer.from('{"bio":"<details open ontoggle=alert(1)>"}', 'utf16le'), 'application/json; charset=utf-16le') },
  // LFI / Traversal
  { family: 'LFI', rawUrl: '/download?doc=../config.yml' },
  { family: 'LFI', rawUrl: '/download?doc=..\\..\\windows\\win.ini' },
  { family: 'LFI', rawUrl: '/download?doc=php://filter/resource=config.php' },
  { family: 'LFI', rawUrl: '/download?doc=/proc/self/cmdline' },
  // SSRF
  { family: 'SSRF', rawUrl: '/preview?url=//169.254.169.254/latest/meta-data/' },
  { family: 'SSRF', rawUrl: '/preview?url=http://10.0.0.1.sslip.io/internal' },
  { family: 'SSRF', rawUrl: '/preview?webhook=http://0x7f000001:8080/metrics' },
  { family: 'SSRF', rawUrl: '/preview?target=http://[::1]:6379/' },
  // RCE / Shell / Log4Shell
  { family: 'RCE', rawUrl: '/tools?host=example.com;uname -a' },
  { family: 'RCE', rawUrl: '/tools?host=$(ls -la)' },
  { family: 'RCE', rawUrl: '/tools?host=`head /etc/passwd`' },
  { family: 'RCE', rawUrl: '/tools?host=a|{cat,/etc/passwd}' },
  { family: 'RCE', rawUrl: '/tools', headers: { 'x-custom-lang': '${jndi:dns://probe.invalid/x}' } },
  { family: 'RCE', rawUrl: '/tools?host=ok;b"a"sh -c id' },
  // SSTI (with and without {{ }})
  { family: 'SSTI', rawUrl: '/tpl?name=<%= 9*9 %>' },
  { family: 'SSTI', rawUrl: '/tpl?name=#{7*7}' },
  { family: 'SSTI', rawUrl: '/tpl?name={% print(7*7) %}' },
  { family: 'SSTI', rawUrl: '/tpl?name=<#assign ex="freemarker.template.utility.Execute"?new()>' },
  { family: 'SSTI', rawUrl: '/tpl?name=${7*7}' },
  // NoSQL / XXE / Prototype Pollution (deep & wide JSON)
  { family: 'NoSQL', rawUrl: '/api/deep', bodyText: deepJsonNoSql },
  { family: 'NoSQL', rawUrl: '/api/wide', bodyText: longArrayNoSql },
  { family: 'XXE', rawUrl: '/api/xml', bodyText: '<!DOCTYPE data SYSTEM "http://external.invalid/ext.dtd"><data/>' },
  { family: 'XXE', rawUrl: '/api/xml', bodyText: '<!DOCTYPE r [<!ENTITY a "b">]><r>&a;</r>' },
  { family: 'Proto', rawUrl: '/api/prefs', bodyText: '{"nested":{"constructor":{"prototype":{"polluted":true}}}}' }
];

// 2. Corpus independiente de 36 textos realistas de clientes de tienda, soporte y correos
const LEGIT_CUSTOMER_CORPUS = [
  { label: 'Búsqueda libro técnico', rawUrl: '/search?q=Python%3A+Crash+Course+3rd+Edition' },
  { label: 'Búsqueda artículo programación', rawUrl: '/search?q=TypeScript%3A+Effective+Patterns' },
  { label: 'Catálogo con barras verticales', rawUrl: '/api/review', bodyText: '{"text":"Camiseta Azul | Talla M | Algodón 100% | Envío 24h"}' },
  { label: 'Comparativa con pipes', rawUrl: '/api/review', bodyText: '{"text":"Modelo A | Modelo B | Precio $49.99 | Garantía 2 años"}' },
  { label: 'Reseña multilínea español', rawUrl: '/api/review', bodyText: '{"text":"Excelente calidad.\nLlegó en 2 días.\nLo volvería a comprar sin dudarlo."}' },
  { label: 'Reseña multilínea inglés', rawUrl: '/api/review', bodyText: '{"text":"Great fabric!\nMy kids sleep peacefully all night.\nHighly recommended."}' },
  { label: 'Ticket soporte red doméstica', rawUrl: '/api/ticket', bodyText: '{"message":"Mi impresora WiFi en http://192.168.0.105 no aparece en la app de facturación."}' },
  { label: 'Ticket soporte localhost dev', rawUrl: '/api/ticket', bodyText: '{"message":"Probando el webhook desde http://localhost:3000 antes de pasar a producción."}' },
  { label: 'Plantilla correo variables simples', rawUrl: '/api/email', bodyText: '{"html":"Hola {{customer_name}}, tu orden {{order_number}} fue enviada a {{city}}."}' },
  { label: 'Correo con DOCTYPE XHTML estándar', rawUrl: '/api/email', bodyText: '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html><body><h1>Recibo #8821</h1></body></html>' },
  { label: 'Nota de entrega con doble guion', rawUrl: '/api/checkout', bodyText: '{"note":"Dejar en recepción -- horario de 9am a 5pm -- preguntar por Marta"}' },
  { label: 'Apellido con apóstrofe', rawUrl: '/api/checkout', bodyText: '{"customer":"Patrick O\'Brien","city":"San Juan"}' },
  { label: 'Factura con separadores =', rawUrl: '/api/invoice', bodyText: '{"summary":"======== FACTURA ========\nSubtotal: $120.00\n========"}' },
  { label: 'Comentario con punto y coma', rawUrl: '/api/ticket', bodyText: '{"msg":"El paquete llegó bien; id de rastreo 998212; gracias por el soporte"}' },
  { label: 'Búsqueda con OR natural', rawUrl: '/search?q=zapatos+rojos+or+azules+talla+42' },
  { label: 'Foro discusión comité', rawUrl: '/api/forum', bodyText: '{"body":"The trade union will select new representatives next Tuesday."}' },
  { label: 'Artículo salud sueño', rawUrl: '/api/blog', bodyText: '{"content":"Adults should sleep (7 to 9 hours) every night for better focus."}' },
  { label: 'Consulta ruta archivo soporte', rawUrl: '/api/ticket', bodyText: '{"msg":"En macOS revisé /etc/hosts pero el dominio sigue resolviendo al servidor viejo."}' },
  { label: 'Referencia código SKU', rawUrl: '/productos/SKU-2026-ALPHA-99?color=negro&envio=express' },
  { label: 'JSON carrito normal', rawUrl: '/api/cart', bodyText: '{"items":[{"sku":"A1","qty":2,"price":19.99},{"sku":"B2","qty":1,"price":45.00}]}' },
  { label: 'Reseña matemáticas escolar', rawUrl: '/api/review', bodyText: '{"text":"El cuaderno trae tablas como 3 x 4 = 12 y ejercicios claros."}' },
  { label: 'Nota descuento con apóstrofe', rawUrl: '/api/checkout', bodyText: '{"note":"Cliente VIP -- cupón VERANO26 aplicado"}' },
  { label: 'Búsqueda JavaScript moderno', rawUrl: '/search?q=JavaScript%3A+Definitive+Guide' },
  { label: 'HTML newsletter simple', rawUrl: '/api/email', bodyText: '<p>Gracias por tu compra. Visita <b>nuestra tienda</b> pronto.</p>' },
  { label: 'Comentario con moneda $', rawUrl: '/api/review', bodyText: '{"text":"Costó $25 dólares y vale cada centavo ($10 menos que en otra tienda)."}' },
  { label: 'Dirección con barra /', rawUrl: '/api/checkout', bodyText: '{"address":"Calle Luna #14, Apt 2B / Edificio Norte"}' },
  { label: 'Navegación con Referer IP privada', rawUrl: '/catalogo?page=2', headers: { referer: 'http://192.168.1.25:4040/', origin: 'http://192.168.1.25:4040' } },
  { label: 'API móvil cliente Go', rawUrl: '/api/v1/products', headers: { 'user-agent': 'Go-http-client/2.0' } },
  { label: 'Webhook integración Python', rawUrl: '/api/v1/inventory', headers: { 'user-agent': 'python-requests/2.32.3' } },
  { label: 'Petición CSS estático', rawUrl: '/static/main.css' },
  { label: 'Petición imagen producto', rawUrl: '/images/hero-banner.webp' },
  { label: 'Petición fuente tipográfica', rawUrl: '/fonts/inter-var.woff2' },
  { label: 'Soporte mención fecha SQL', rawUrl: '/api/ticket', bodyText: '{"msg":"Necesito actualizar los datos de facturación desde el mes pasado."}' },
  { label: 'Reseña teclado mecánico', rawUrl: '/api/review', bodyText: '{"text":"Switches suaves | Retroiluminación RGB | Cable USB-C desmontable"}' },
  { label: 'Plantilla correo confirmación', rawUrl: '/api/email', bodyText: '{"subject":"Pedido {{id}} confirmado","body":"Estimado {{name}}, gracias por confiar en nosotros."}' },
  { label: 'Soporte horario atención', rawUrl: '/api/ticket', bodyText: '{"msg":"¿Trabajan sábados?\nNecesito cambiar la talla de mi chaqueta.\nGracias!"}' }
];

async function runBenchmark() {
  // 1. Tasa de detección sobre corpus OWASP independiente
  const familyStats = {};
  let totalDetected = 0;
  for (const c of OWASP_BENCHMARK_CASES) {
    familyStats[c.family] = familyStats[c.family] || { detected: 0, total: 0 };
    familyStats[c.family].total += 1;
    const r = inspectPayloadDPI({
      rawUrl: c.rawUrl,
      headers: c.headers || {},
      bodyText: c.bodyText || '',
      contentType: c.contentType || ''
    });
    if (r.malicious) {
      totalDetected += 1;
      familyStats[c.family].detected += 1;
    }
  }

  // 2. Tasa de falsos positivos (alertas) y tasa de bloqueo real en modo por defecto ('detect')
  let fpAlerts = 0;
  const fpDetails = [];
  for (const sample of LEGIT_CUSTOMER_CORPUS) {
    const r = inspectPayloadDPI({
      rawUrl: sample.rawUrl,
      headers: sample.headers || {},
      bodyText: sample.bodyText || ''
    });
    if (r.malicious) {
      fpAlerts += 1;
      fpDetails.push(`${sample.label} -> ${r.vectors.join(',')}`);
    }
  }

  // 3. Prueba en vivo: página de tienda con 80 archivos + DoS de CPU 2 MB gzip/repetitivo
  const upstream = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));

  const srv = createGuardianesServer({
    dbPath: ':memory:',
    memoryFilePath: null,
    adminToken: 'benchmark-admin-token-long-random-1234',
    aiConfig: { tarpitDelayMs: 0 },
    botVerifier: new SearchBotVerifier({ enableLiveDns: false }),
    shieldConfigOverride: {
      shieldMode: 'reverse-proxy',
      protectedTargetUrl: `http://127.0.0.1:${upstream.address().port}`,
      trustProxyHeaders: true
    }
  });
  await new Promise((r) => srv.dataServer.listen(0, '127.0.0.1', r));
  const dataUrl = `http://127.0.0.1:${srv.dataServer.address().port}`;

  try {
    // 3A. Bloqueos reales sobre clientes legítimos en modo por defecto
    let legitBlocked = 0;
    let legitQuarantined = 0;
    for (let i = 0; i < LEGIT_CUSTOMER_CORPUS.length; i += 1) {
      const s = LEGIT_CUSTOMER_CORPUS[i];
      const ip = `198.51.100.${10 + i}`;
      const res = await fetch(`${dataUrl}${s.rawUrl}`, {
        method: s.bodyText ? 'POST' : 'GET',
        headers: {
          'x-forwarded-for': ip,
          ...(s.bodyText ? { 'Content-Type': 'application/json' } : {}),
          ...(s.headers || {})
        },
        body: s.bodyText || undefined
      });
      if (res.status !== 200) legitBlocked += 1;
      if (srv.memory.getActiveQuarantine(ip)) legitQuarantined += 1;
    }

    // 3B. Página de tienda con 80 archivos
    const storeAssets = [
      '/tienda/index.html',
      ...Array.from({ length: 79 }, (_, i) => `/assets/f-${i}.${i % 3 === 0 ? 'webp' : i % 3 === 1 ? 'css' : 'js'}`)
    ];
    const storeRes = await Promise.all(
      storeAssets.map((p) => fetch(`${dataUrl}${p}`, { headers: { 'x-forwarded-for': '203.0.113.50' } }))
    );
    const storeOkPct = pct(storeRes.filter((r) => r.status === 200).length, storeAssets.length);
    const storeQuarantined = Boolean(srv.memory.getActiveQuarantine('203.0.113.50'));

    // 3C. Estrés CPU: 6 bodies de 2 MB repetitivos (3 gzip + 3 planos) + latencia concurrente
    const heavyPayloads = [
      { gz: true, buf: zlib.gzipSync(Buffer.from('/*'.repeat(1_000_000))) },
      { gz: true, buf: zlib.gzipSync(Buffer.from('{{'.repeat(1_000_000))) },
      { gz: true, buf: zlib.gzipSync(Buffer.from('<a '.repeat(650_000))) },
      { gz: false, buf: Buffer.from('${'.repeat(1_000_000)) },
      { gz: false, buf: Buffer.from('A'.repeat(2_000_000)) },
      { gz: false, buf: Buffer.from('"'.repeat(2_000_000)) }
    ];
    const cpuStart = Date.now();
    const heavyCalls = heavyPayloads.map((item, idx) =>
      fetch(`${dataUrl}/api/heavy`, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          ...(item.gz ? { 'Content-Encoding': 'gzip' } : {}),
          'x-forwarded-for': `203.0.113.${80 + idx}`
        },
        body: item.buf
      })
    );
    const latencies = [];
    for (let i = 0; i < 10; i += 1) {
      const t0 = Date.now();
      await fetch(`${dataUrl}/catalogo`, { headers: { 'x-forwarded-for': '203.0.113.200' } });
      latencies.push(Date.now() - t0);
    }
    await Promise.all(heavyCalls);
    const cpuTotalMs = Date.now() - cpuStart;
    latencies.sort((a, b) => a - b);
    const p99Ms = latencies[latencies.length - 1];

    console.log('=== BENCHMARK INDEPENDIENTE GUARDIANES ETERNOS v5.3 ===');
    console.log(`Detección estructural global: ${pct(totalDetected, OWASP_BENCHMARK_CASES.length)}`);
    for (const [fam, st] of Object.entries(familyStats)) {
      console.log(`  - ${fam}: ${pct(st.detected, st.total)}`);
    }
    console.log(`Falsos positivos en alertas (corpus cliente): ${pct(fpAlerts, LEGIT_CUSTOMER_CORPUS.length)}`);
    if (fpDetails.length > 0) console.log(`  Detalle FP: ${fpDetails.join(' | ')}`);
    console.log(`Clientes legítimos bloqueados (modo detect por defecto): ${pct(legitBlocked, LEGIT_CUSTOMER_CORPUS.length)}`);
    console.log(`Clientes legítimos cuarentenados: ${pct(legitQuarantined, LEGIT_CUSTOMER_CORPUS.length)}`);
    console.log(`Carga página tienda (80 archivos): ${storeOkPct} OK | Cuarentena: ${storeQuarantined ? 'SÍ' : 'NO'}`);
    console.log(`Resiliencia CPU (6 bodies de 2 MB repetitivos/gzip): total ${cpuTotalMs} ms | p99 cliente concurrente ${p99Ms} ms`);
  } finally {
    await srv.closeAll();
    await new Promise((r) => {
      upstream.close(r);
      upstream.closeAllConnections?.();
    });
  }
}

runBenchmark().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
