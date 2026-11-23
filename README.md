# Guardianes Eternos v5.3 (*Deception-First Cyber Defense, Canary Tripwires & 3D Holographic SOC*)

> **Capa Open Source (Licencia MIT) de Decepción Cibernética, 43+ Rutas Canario, Laberinto Polimórfico con Byte-Drip Tarpit Adaptativo, Trampas IDPI, Inspección Estructural sin Puntos Ciegos en Pool de Workers y SOC Holográfico 3D (Three.js + SSE).**  
> Construido en **Node.js nativo (0 dependencias externas npm)** + **SQLite WAL nativo (`node:sqlite`)**.
>
> **Posicionamiento honesto:** Guardianes Eternos está diseñado como una **capa de engaño, detección temprana y contención** (*honeypots*, canarios, laberinto y tarpit) para operar **junto a un WAF de borde probado** como **Cloudflare WAF**, **Nginx + OWASP CRS / Coraza** o **ModSecurity** — **no** como reemplazo único de un WAF empresarial completo.

---

## Capturas de Pantalla del Centro de Mando SOC

### 1. SOC Holográfico 3D (Three.js + SSE en Vivo) y Enjambre Dual-Plane
![SOC Holográfico 3D](remotion-assets/06-soc-holografico-3d-v5.png)

### 2. Campo de Tiro Real (*Live Cyber Range*: Ronda 1 Sin Escudo vs. Ronda 2 Protegido)
![Campo de Tiro Real](remotion-assets/02-campo-de-tiro-batalla-real.png)

### 3. Escudo, Nginx `auth_request` Sidecar, Exportación de Firewalls y Kit de Despliegue
![Escudo y Firewalls](remotion-assets/04-escudo-waf-deploy-firewalls.png)

### 4. Comandante Hermes (Copiloto AI con Confirmación 2-Step y Telemetría Enum-Only)
![Comandante Hermes](remotion-assets/05-comandante-hermes-chat-autonomo.png)

---

## Arquitectura Enterprise Dual-Plane v5.3

1. **Separación Física de Planos (Data Plane `:4040` vs. Control Plane `:4041`):**
   - **Data Plane (`PORT=4040`):** Solo atiende tráfico protegido, Reverse Proxy streaming nativo (`http.request`/`https.request` preservando `Cookie`, `Authorization`, `Set-Cookie`, `302`, binarios, IP real en `X-Forwarded-For` y túnel **WebSocket `101 Switching Protocols`**), sidecar autenticado `GET /guardianes/check` (`X-Guardianes-Sidecar-Secret` + IP de confianza), `/robots.txt` completo y `/telemetry-beacon` con nonce HMAC firmado.
   - **Control Plane (`CONTROL_PORT=4041`, loopback `127.0.0.1`):** Autenticación obligatoria (sin bypass por loopback), rate-limit anti fuerza bruta en `POST /api/auth/login` (`429 Too Many Requests`), cookie firmada `HttpOnly; SameSite=Strict` + `X-CSRF-Token`, lista blanca de `Host` (`421`), validación `Origin`/`Sec-Fetch-Site` (`403`), `Content-Type: application/json` (`415`) y streaming **SSE (`GET /events`)**.
2. **Apto para Tiendas Reales (Sin Bloqueos a Clientes Legítimos):**
   - **Exención de archivos estáticos y ráfagas seguras:** Imágenes, CSS, JS y fuentes no consumen el límite de ráfagas (una página con 80+ archivos carga sin fricción). Si una IP excede las navegaciones permitidas (pensado para oficinas y CGNAT), recibe únicamente **`429 Too Many Requests`** de 5 segundos — **nunca cuarentena de 24 h**.
   - **Cuarentena reservada exclusivamente al engaño:** Solo las señales deterministas de engaño (43+ rutas canario, laberinto polimórfico y baliza IDPI) disparan cuarentena persistente (no renovable) y Byte-Drip Tarpit con presupuesto de sockets.
   - **Heurísticas en modo detección por defecto (`wafActionMode: 'detect'`):** Registran y alertan en el SOC sin bloquear clientes y sin reglas "3 strikes".
3. **Inspección sin puntos ciegos (v5.3):** todo lo que el backend va a interpretar se inspecciona, o se declara *no inspeccionable* con un motivo. Nunca se reenvía en silencio algo que no se miró.
   - **Cuerpos comprimidos:** `gzip`, `x-gzip`, `deflate` (zlib y raw), `br` y capas encadenadas (`gzip, gzip`), descomprimidos con tope de salida (una *gzip-bomb* se corta al llegar al tope).
   - **Charset:** UTF-8, ASCII, Latin-1, Windows-1252 y UTF-16 (BOM o heurística). Charsets usados para evadir WAFs (IBM037/EBCDIC, UTF-7…) se declaran no inspeccionables.
   - **multipart/form-data a nivel de bytes:** los campos de formulario siempre se inspeccionan (aunque traigan bytes nulos), sin tope de número de campos; `filename` y `filename*` (RFC 5987) incluidos. En archivos binarios reales se buscan marcas de webshell (`<?php`, `__HALT_COMPILER`…).
   - **JSON léxico:** un escáner lineal ve *todas* las claves y valores, incluidas claves duplicadas (`JSON.parse` se queda con la última; muchos backends usan la primera) y sin tope de nodos ni profundidad.
   - **Campos completos:** no hay recorte silencioso a 64 KB; un ataque escondido al final de un campo de 1 MB se detecta (el SQL se tokeniza por ventanas solapadas).
   - **Nombres de parámetro, cookies, User-Agent y Accept-Language** se inspeccionan además de los valores.
   - **Archivos estáticos** (`.png`, `.js`, fuentes…) siguen exentos del límite de ráfagas, pero su ruta, cookies y cabeceras se inspeccionan (Log4Shell viaja en cabeceras hacia cualquier URL).
   - **Tope de texto inspeccionable:** `maxInspectBodyKb` (1024 KB por defecto). Los archivos binarios de un multipart no cuentan.
4. **Pool de Workers sin fail-open (v5.3):**
   - La inspección (descompresión, decodificación, multipart y DPI) corre en un pool de `node:worker_threads` (por defecto `min(4, CPUs-1)`), nunca en el hilo principal.
   - El tope de cómputo (`1000 ms` por defecto) cuenta desde que un worker **toma** la petición, no desde que entra a la cola. Un timeout termina solo ese worker; las demás peticiones no se ven afectadas.
   - Planificación justa: los cuerpos pesados (> 16 KB) de un mismo cliente ocupan como máximo la mitad del pool. Cola con tope y espera máxima.
   - Todos los analizadores son lineales: el peor patrón patológico de 1 MB medido tarda ~370 ms en un Ryzen 9 7950X.
5. **Política para lo no inspeccionable (`uninspectablePolicy`):**
   - `'auto'` (por defecto): en `block-request` se rechaza (`413` demasiado grande, `415` encoding/charset no soportado, `400` comprimido corrupto, `503` sobrecarga, `403` contenido patológico); en `detect` se deja pasar **con alerta** en el SOC.
   - `'block'` o `'allow-with-alert'` para forzar uno de los dos comportamientos.
6. **Modos de acción (`wafActionMode`):**
   - `'detect'` (por defecto, pensado para empezar sin riesgo en una tienda real): las heurísticas **registran y alertan, no bloquean** inyecciones. La cuarentena por engaño (canarios, laberinto, baliza) sí actúa.
   - `'block-request'`: cada petición con ataque recibe `403` puntual (sin cuarentena de 24 h). **Es el modo que hay que activar para que Guardianes frene inyecciones.**
   - Inspección independiente del `Content-Type` declarado, exclusión de `Referer`/`Origin` en SSRF y FCrDNS estricta de Googlebot (`.googlebot.com` / `.google.com`).
7. **Límites conocidos (honestos):**
   - Es detección heurística estructural, no un parser de cada lenguaje del backend: siempre puede existir una forma de ataque nueva que no reconozca. Por eso se recomienda operar **junto a un WAF de borde** y con código de backend seguro (consultas parametrizadas, escape de salida).
   - Un dominio público cuyo DNS apunta a una IP interna (SSRF por resolución) no se puede detectar sin resolver DNS; valida destinos en el backend.
   - Paneles de administración que envían HTML legítimo (descripciones de producto con `<iframe>`) pueden generar alertas; en `block-request` conviene probarlos antes.
8. **Uso Real y Transparente de IA (OpenRouter / BYOK):**
   - **Motor Local (`$0.00`):** Canarios, laberinto polimórfico, 4 estrategias IDPI base y detección estructural en worker corren localmente con etiquetado honesto `deterministic-local:*`.
   - **IA Externa Asíncrona (cuando configuras OpenRouter/BYOK):** Al confirmar una nueva cuarentena por engaño, **Cronista** realiza triaje forense asíncrono (*enum-only*) e **Ilusionista** genera/cachea trampas IDPI adaptativas (respetando `maxApiCallsPerHour`). También potencia Reportes Ejecutivos y **Comandante Hermes v5.3** (confirmación 2-Step + negaciones + contexto *enum-only*).

---

## Instalación y Uso Rápido

Requiere **Node.js >= 22** (0 dependencias externas en `node_modules`).

```bash
# 1. Clonar el repositorio
git clone https://github.com/jctoyzpr-ui/guardianes-eternos.git
cd guardianes-eternos

# 2. Definir secretos largos aleatorios en producción
export GUARDIANES_ADMIN_TOKEN="$(node -e "console.log(require('crypto').randomBytes(24).toString('hex'))")"
export GUARDIANES_VAULT_KEY="$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
export GUARDIANES_SIDECAR_SECRET="$(node -e "console.log(require('crypto').randomBytes(24).toString('hex'))")"

# 3. Iniciar ambos planos (Data Plane :4040 + Control Plane SOC 3D :4041)
npm start

# 4. Ejecutar suite de pruebas unitarias/integración y benchmark independiente
npm test
npm run benchmark
```

---

## Licencia y Uso Ético

Distribuido bajo la **Licencia MIT** ([LICENSE](./LICENSE)). Diseñado estrictamente para defensa perimetral, decepción cibernética, *honeypots* y pruebas en entornos autorizados. Impulsado por **365 Collaboration** (`365collaboration.net`).
