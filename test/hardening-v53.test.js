/**
 * @fileoverview Pruebas de regresión v5.3 — "ningún punto ciego".
 * Cada prueba fija una INVARIANTE de seguridad (no un payload memorizado):
 *   1. Lo que el backend interpreta se inspecciona: cuerpos comprimidos (gzip/deflate/br/encadenados), multipart a
 *      nivel de bytes, campos largos completos, claves duplicadas, nombres de parámetro, rutas estáticas con cabeceras.
 *   2. Lo que no se puede inspeccionar nunca sale "limpio": se rechaza en block-request y se alerta en detect.
 *   3. El pool de workers no hace fail-open: un timeout afecta solo a su petición y la cola no vacía a las demás.
 *   4. Costo lineal: ningún patrón de 1 MB supera el presupuesto del worker.
 *   5. Sin regresión de falsos positivos en textos reales de clientes.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';
import { createGuardianesServer } from '../src/server.js';
import { inspectRequest, buildInspectableBody } from '../src/engine/requestInspector.js';
import { DpiWorkerRunner } from '../src/engine/dpiRunner.js';
import { scanJsonLexical } from '../src/engine/structuralDetector.js';

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36';

async function startShield(mode = 'block-request', extraRules = {}) {
  const victim = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => res.end('ORIGIN_OK'));
  });
  await new Promise((r) => victim.listen(0, '127.0.0.1', r));
  const g = createGuardianesServer({
    dbPath: ':memory:',
    memoryFilePath: null,
    aiConfig: { tarpitDelayMs: 0 },
    shieldConfigOverride: {
      shieldMode: 'reverse-proxy',
      protectedTargetUrl: `http://127.0.0.1:${victim.address().port}`,
      trustProxyHeaders: true,
      wafRules: { wafActionMode: mode, rateLimitMaxPer10s: 100000, ...extraRules }
    }
  });
  await new Promise((r) => g.dataServer.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${g.dataServer.address().port}`;
  const send = async (path, { method, headers = {}, body } = {}) => {
    const r = await fetch(url + path, {
      method: method || (body !== undefined ? 'POST' : 'GET'),
      headers: { 'user-agent': UA, ...headers },
      body
    });
    await r.text();
    return r.status;
  };
  return {
    g,
    send,
    close: async () => {
      await g.closeAll();
      victim.close();
    }
  };
}

const sqliJson = JSON.stringify({ email: "nobody@x.io' UNION SELECT token FROM sessions-- -" });

test('v5.3 #1: cuerpos comprimidos se inspeccionan (gzip, x-gzip, deflate zlib y raw, br y capas encadenadas)', async () => {
  const s = await startShield();
  try {
    const J = { 'content-type': 'application/json' };
    assert.equal(await s.send('/api/a', { headers: { ...J, 'content-encoding': 'gzip' }, body: zlib.gzipSync(sqliJson) }), 403);
    assert.equal(await s.send('/api/a', { headers: { ...J, 'content-encoding': 'x-gzip' }, body: zlib.gzipSync(sqliJson) }), 403);
    assert.equal(await s.send('/api/a', { headers: { ...J, 'content-encoding': 'deflate' }, body: zlib.deflateSync(sqliJson) }), 403);
    assert.equal(await s.send('/api/a', { headers: { ...J, 'content-encoding': 'deflate' }, body: zlib.deflateRawSync(sqliJson) }), 403);
    assert.equal(await s.send('/api/a', { headers: { ...J, 'content-encoding': 'br' }, body: zlib.brotliCompressSync(sqliJson) }), 403);
    assert.equal(await s.send('/api/a', { headers: { ...J, 'content-encoding': 'deflate, gzip' }, body: zlib.gzipSync(zlib.deflateSync(sqliJson)) }), 403);
    // Legítimo comprimido pasa
    assert.equal(await s.send('/api/a', { headers: { ...J, 'content-encoding': 'gzip' }, body: zlib.gzipSync(JSON.stringify({ note: 'feliz cumpleaños' })) }), 200);
  } finally {
    await s.close();
  }
});

test('v5.3 #2: lo no inspeccionable se rechaza en block-request y se alerta (sin bloquear) en detect', async () => {
  const blocked = await startShield('block-request', { maxInspectBodyKb: 64 });
  const detect = await startShield('detect', { maxInspectBodyKb: 64 });
  try {
    const big = JSON.stringify({ a: 'x'.repeat(70 * 1024) });
    assert.equal(await blocked.send('/api/a', { headers: { 'content-type': 'application/json' }, body: big }), 413);
    assert.equal(await blocked.send('/api/a', { headers: { 'content-type': 'application/json', 'content-encoding': 'compress' }, body: 'abc' }), 415);
    assert.equal(await blocked.send('/api/a', { headers: { 'content-type': 'text/plain; charset=utf-7' }, body: '+ADw-script+AD4-' }), 415);
    assert.equal(await blocked.send('/api/a', { headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' }, body: 'no-es-gzip' }), 400);
    // gzip-bomb: 10 MB de ceros comprimidos -> se corta en el tope, no consume CPU ni memoria sin límite
    const bomb = zlib.gzipSync(Buffer.alloc(10 * 1024 * 1024));
    assert.equal(await blocked.send('/api/a', { headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' }, body: bomb }), 413);

    assert.equal(await detect.send('/api/a', { headers: { 'content-type': 'application/json' }, body: big }), 200);
    const alerts = [...detect.g.memory.threatGraph.values()].flatMap((t) => t.attackVectors || []);
    assert.ok(alerts.some((v) => String(v).startsWith('UNINSPECTABLE_')), 'detect debe registrar la alerta de contenido no inspeccionable');
  } finally {
    await blocked.close();
    await detect.close();
  }
});

test('v5.3 #3: rutas estáticas siguen exentas de ráfagas pero sus cabeceras, cookies y ruta se inspeccionan', async () => {
  const s = await startShield();
  try {
    assert.equal(await s.send('/assets/site.css', { headers: { 'x-correlation-id': '${jndi:dns://probe.example/z}' } }), 403);
    assert.equal(await s.send('/assets/logo.svg', { headers: { cookie: `pref=${encodeURIComponent("a' OR 9=9-- -")}` } }), 403);
    assert.equal(await s.send(`/media/${encodeURIComponent('<svg/onload=confirm(9)>')}.png`), 403);
    for (let i = 0; i < 90; i += 1) assert.equal(await s.send(`/media/p${i}.webp`, { headers: { referer: 'https://tienda.example/' } }), 200);
  } finally {
    await s.close();
  }
});

test('v5.3 #4: multipart a nivel de bytes — campos con NUL, campo N>120, filename*, webshell en binario; foto real pasa', async () => {
  const s = await startShield();
  const mp = (parts) => {
    const b = 'b0und4ry';
    const body = Buffer.concat([
      ...parts.map(([h, v]) => Buffer.concat([Buffer.from(`--${b}\r\n${h}\r\n\r\n`), Buffer.isBuffer(v) ? v : Buffer.from(v), Buffer.from('\r\n')])),
      Buffer.from(`--${b}--\r\n`)
    ]);
    return { headers: { 'content-type': `multipart/form-data; boundary=${b}` }, body };
  };
  try {
    const nulField = Buffer.concat([Buffer.from('<img src=x onerror=prompt(7)>'), Buffer.alloc(64, 0)]);
    assert.equal(await s.send('/up', mp([['Content-Disposition: form-data; name="bio"', nulField]])), 403);
    const many = Array.from({ length: 300 }, (_, i) => [`Content-Disposition: form-data; name="c${i}"`, `ok${i}`]);
    many.push(['Content-Disposition: form-data; name="z"', "1 UNION SELECT secret FROM vault-- -"]);
    assert.equal(await s.send('/up', mp(many)), 403);
    assert.equal(await s.send('/up', mp([[`Content-Disposition: form-data; name="f"; filename*=UTF-8''..%2F..%2Froot%2F.ssh%2Fauthorized_keys`, 'k']])), 403);
    const gif = Buffer.concat([Buffer.from('GIF89a'), Buffer.alloc(500, 1), Buffer.from('<?php passthru($_POST[1]); ?>')]);
    assert.equal(await s.send('/up', mp([['Content-Disposition: form-data; name="img"; filename="x.gif"\r\nContent-Type: image/gif', gif]])), 403);
    const photo = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.from(Array.from({ length: 30000 }, (_, i) => (i * 131) % 256))]);
    assert.equal(await s.send('/up', mp([['Content-Disposition: form-data; name="img"; filename="foto.jpg"\r\nContent-Type: image/jpeg', photo], ['Content-Disposition: form-data; name="desc"', 'Mi muñeca favorita']])), 200);
  } finally {
    await s.close();
  }
});

test('v5.3 #5: ataque escondido al final de un campo largo, en clave duplicada o en el NOMBRE del parámetro', async () => {
  const s = await startShield();
  try {
    const J = { 'content-type': 'application/json' };
    assert.equal(await s.send('/api/r', { headers: J, body: JSON.stringify({ t: 'lorem '.repeat(60000) + '<iframe src=javascript:alert(2)>' }) }), 403);
    assert.equal(await s.send('/api/r', { headers: J, body: '{"q":"\' OR 5=5-- -","q":"normal"}' }), 403);
    assert.equal(await s.send(`/list?${encodeURIComponent("n') UNION SELECT 1,2-- -")}=v`), 403);
    const lex = scanJsonLexical('{"a":"1","a":"2","b":{"c":["x"]}}');
    assert.ok(lex.ok);
    assert.deepEqual(lex.params.map((p) => p.value), ['1', '2', 'x']);
  } finally {
    await s.close();
  }
});

test('v5.3 #6: el pool no hace fail-open — timeout solo afecta a su petición y nunca devuelve "limpio"', async () => {
  const runner = new DpiWorkerRunner({ poolSize: 2, timeoutMs: 1 });
  try {
    const heavy = Buffer.from('lorem ipsum '.repeat(80000));
    const results = await Promise.all(
      Array.from({ length: 6 }, () => runner.inspectAsync({ rawUrl: '/x', headers: {}, rawBody: heavy, contentType: 'text/plain' }, { clientKey: 'a' }))
    );
    for (const r of results) {
      assert.ok(r.malicious || r.uninspectable, 'un resultado sin inspeccionar debe venir marcado, nunca como limpio');
    }
  } finally {
    await runner.close();
  }
  const runner2 = new DpiWorkerRunner({ poolSize: 2, timeoutMs: 2000 });
  try {
    const benign = await runner2.inspectAsync({ rawUrl: '/ok?q=hola', headers: {} }, { clientKey: 'b' });
    assert.equal(benign.malicious, false);
    assert.equal(benign.uninspectable ?? null, null);
    const attack = await runner2.inspectAsync({ rawUrl: `/x?q=${encodeURIComponent('<script>alert(1)</script>')}`, headers: {} }, { clientKey: 'b' });
    assert.equal(attack.malicious, true);
  } finally {
    await runner2.close();
  }
});

test('v5.3 #7: costo lineal — patrones patológicos de 1 MB por debajo del presupuesto del worker', () => {
  const MB = 1024 * 1024 - 64;
  const rep = (t) => t.repeat(Math.floor(MB / t.length));
  for (const t of ['$(', '<a', '{{', "'\\", '`', ';', 'http://a.', '../', '(SELECT ', '" a=b ', '%c0%ae']) {
    const t0 = performance.now();
    inspectRequest({ rawUrl: '/x', headers: {}, rawBody: Buffer.from(rep(t)), contentType: 'text/plain' });
    const ms = performance.now() - t0;
    assert.ok(ms < 900, `patrón ${JSON.stringify(t)} tardó ${ms.toFixed(0)} ms`);
  }
});

test('v5.3 #8: sin falsos positivos en textos reales de clientes y cuerpos legítimos', () => {
  const J = 'application/json';
  const texts = [
    "Please leave it with the neighbor at Lucy's, or 2nd floor -- thanks!",
    'Quiero 2 or 3 unidades, la que tenga en stock (select one) por favor',
    'Mi contador me pidió: SELECT total FROM ventas WHERE mes = 10, ¿me ayudan?',
    'En Liquid uso {{ product.price | money }} y {% if %}, no me sale',
    'La ruta es C:\\Users\\Pedro\\Desktop\\pedido.pdf y no abre',
    'Probé ping 1.1.1.1 && tracert google.com; sigue fallando',
    'Precio ${total} aparece literal en el correo',
    'Talla <M> o <L>? Mi nena tiene 8 años <3',
    'Visiten https://mi-negocio.pr/catalogo?ref=fb&utm=1'
  ];
  for (const msg of texts) {
    const r = inspectRequest({ rawUrl: '/api/support', headers: { 'content-type': J }, rawBody: Buffer.from(JSON.stringify({ msg })), contentType: J });
    assert.equal(r.malicious, false, `falso positivo: ${msg}`);
    assert.equal(r.uninspectable, null);
  }
  const png = buildInspectableBody({ rawBody: Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47]), Buffer.alloc(2000, 3)]), contentType: 'image/png' });
  assert.equal(png.bodyStatus, 'binary');
  assert.equal(png.uninspectable, null);
});
