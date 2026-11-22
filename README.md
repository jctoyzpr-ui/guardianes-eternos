# Guardianes Eternos v5.2 (*Deception-First Cyber Defense, Canary Tripwires & 3D Holographic SOC*)

> **Capa Open Source (Licencia MIT) de Decepción Cibernética, 43+ Rutas Canario, Laberinto Polimórfico con Byte-Drip Tarpit Adaptativo, Trampas IDPI, Telemetría Estructural en Worker Thread y SOC Holográfico 3D (Three.js + SSE).**  
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

## Arquitectura Enterprise Dual-Plane v5.2

1. **Separación Física de Planos (Data Plane `:4040` vs. Control Plane `:4041`):**
   - **Data Plane (`PORT=4040`):** Solo atiende tráfico protegido, Reverse Proxy streaming nativo (`http.request`/`https.request` preservando `Cookie`, `Authorization`, `Set-Cookie`, `302`, binarios, IP real en `X-Forwarded-For` y túnel **WebSocket `101 Switching Protocols`**), sidecar autenticado `GET /guardianes/check` (`X-Guardianes-Sidecar-Secret` + IP de confianza), `/robots.txt` completo y `/telemetry-beacon` con nonce HMAC firmado.
   - **Control Plane (`CONTROL_PORT=4041`, loopback `127.0.0.1`):** Autenticación obligatoria (sin bypass por loopback), rate-limit anti fuerza bruta en `POST /api/auth/login` (`429 Too Many Requests`), cookie firmada `HttpOnly; SameSite=Strict` + `X-CSRF-Token`, lista blanca de `Host` (`421`), validación `Origin`/`Sec-Fetch-Site` (`403`), `Content-Type: application/json` (`415`) y streaming **SSE (`GET /events`)**.
2. **Apto para Tiendas Reales (Sin Bloqueos a Clientes Legítimos):**
   - **Exención de archivos estáticos y ráfagas seguras:** Imágenes, CSS, JS y fuentes no consumen el límite de ráfagas (una página con 80+ archivos carga sin fricción). Si una IP excede las navegaciones permitidas (pensado para oficinas y CGNAT), recibe únicamente **`429 Too Many Requests`** de 5 segundos — **nunca cuarentena de 24 h**.
   - **Cuarentena reservada exclusivamente al engaño:** Solo las señales deterministas de engaño (43+ rutas canario, laberinto polimórfico y baliza IDPI) disparan cuarentena persistente (no renovable) y Byte-Drip Tarpit con presupuesto de sockets.
   - **Heurísticas en modo detección por defecto (`wafActionMode: 'detect'`):** Registran y alertan en el SOC sin bloquear clientes y sin reglas "3 strikes".
3. **Inmune a DoS de CPU (Worker Thread + Costo Lineal O(n)):**
   - La inspección estructural corre fuera del hilo principal en un **`node:worker_threads` Worker** con tope estricto de tiempo por petición (`50 ms` fail-open).
   - Todos los analizadores (tokenizador SQL, scanner HTML/XSS, SSRF, RCE, SSTI, walker JSON iterativo) son lineales $O(n)$, y por defecto **no se descomprimen ni inspeccionan cuerpos grandes (> 64 KB)** para impedir ataques de CPU/gzip-bomb.
   - Inspección independiente del `Content-Type` declarado (mediante *magic bytes*), soporte **UTF-16LE/BE**, exclusión de `Referer`/`Origin` en SSRF y verificación FCrDNS estricta de Googlebot (únicamente `.googlebot.com` y `.google.com`).
4. **Uso Real y Transparente de IA (OpenRouter / BYOK):**
   - **Motor Local (`$0.00`):** Canarios, laberinto polimórfico, 4 estrategias IDPI base y detección estructural en worker corren localmente con etiquetado honesto `deterministic-local:*`.
   - **IA Externa Asíncrona (cuando configuras OpenRouter/BYOK):** Al confirmar una nueva cuarentena por engaño, **Cronista** realiza triaje forense asíncrono (*enum-only*) e **Ilusionista** genera/cachea trampas IDPI adaptativas (respetando `maxApiCallsPerHour`). También potencia Reportes Ejecutivos y **Comandante Hermes v5.2** (confirmación 2-Step + negaciones + contexto *enum-only*).

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
