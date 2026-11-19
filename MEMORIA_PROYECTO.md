# Bitácora Viva del Proyecto: **Guardianes Eternos**
**Canal de Sincronización Permanente & Memoria del Enjambre**  
**Licencia:** MIT (Código Abierto) | **Impulsado por:** 365 Collaboration (`365collaboration.net`)

---

## 1. Visión y Fusión de los 3 Mundos
**Guardianes Eternos** combina principios probados de ciberdefensa e inteligencia artificial en una arquitectura propia y 100% defensiva:

1. **Inspiración invertida de `ARTEX` (Enjambre y Doble Grafo Defensivo):**
   - Mientras los frameworks ofensivos usan un agente planificador y trabajadores conectados a un *Asset Graph* y un *Exploration Graph* para atacar, **Guardianes Eternos** invierte esa arquitectura creando un **Enjambre Coordinado de 4 Guardianes** con dos grafos defensivos:
     - `threatGraph`: rastrea cada agente o escáner atacante, su firma, rutas probadas, tiempo retenido y costo/tokens drenados al adversario.
     - `labyrinthGraph`: mapea todos los nodos falsos, tokens canario y sub-rutas polimórficas desplegadas para saturar la memoria del atacante.
2. **Inspiración de `Galah` (Laberinto Web Dinámico / AI Tarpit):**
   - Respuestas HTTP y JSON polimórficas generadas al vuelo sin tocar jamás los datos reales del negocio, provocando latencia controlada y agotamiento de ventana de contexto en agentes invasores.
3. **Inspiración de `Beelzebub` (Cebos Canario de 0 Falsos Positivos + Trampas de Prompt):**
   - Rutas señuelo ocultas para humanos (`/.env`, `/.env.prod`, `/api/v1/internal/admin-keys`, etc.) combinadas con **Inyección Indirecta de Prompts Defensiva (IDPI)** para neutralizar el razonamiento del LLM invasor de forma legal y silenciosa.

---

## 2. Los 4 Guardianes Eternos

| Guardián | Código | Rol Principal |
| :--- | :--- | :--- |
| **1. El Centinela** | `SENTINEL` | Vigila más de 12 rutas canario y detecta firmas de agentes autónomos (Playwright, ráfagas de escaneo, recolectores de secretos) con 0 falsos positivos. |
| **2. El Tejedor** | `WEAVER` | Aplica *Shadow Routing* + *Latency Tarpit* y teje árboles infinitos polimórficos (`/api/v2/vault/shard-xxxx`) con costo **$0.00** para el defensor. |
| **3. El Ilusionista** | `MIRAGE` | Inyecta trampas de *System Prompt Defensivo* (4 estrategias: Bucle Criptográfico, Safe-Harbor Override, Saturación de Contexto y Autodelación Pasiva de Telemetría). |
| **4. El Cronista** | `CHRONICLER` | Coordina el canal de diálogo del enjambre, calcula el balance económico (tokens/USD quemados al atacante vs. defensa) y actualiza esta bitácora viva. |

---

## 3. Modelo Económico: Escudo Anti-Denegación de Billetera (*Denial of Wallet*)
- **Motor Polimórfico Local ($0.00):** Activo por defecto; permite atrapar decenas de miles de peticiones sin gastar APIs de pago.
- **Modo BYOK (*Bring Your Own Key*):** Configurable desde la interfaz visual para **Google Gemini**, **OpenAI**, **Anthropic**, **DeepSeek**, **Groq** y **Ollama Local**.
- **Selector de Modo del Enjambre:**
  - `unified`: Todos los guardianes comparten el mismo proveedor y modelo.
  - `specialized`: Cada guardián usa el modelo más rentable para su tarea.
- **Kill-Switch de Presupuesto:** Tope horario (`maxApiCallsPerHour`). Al llegar al límite, el enjambre cambia automáticamente al motor polimórfico local sin apagar la defensa.

---

## 4. Estado Actual de Construcción
- [x] **Fase 1:** Estructura Open Source con Licencia MIT, `package.json` (cero dependencias externas) y `MEMORIA_PROYECTO.md`.
- [x] **Fase 2:** Motor de Enrutamiento Híbrido de IA y Escudo de Presupuesto (`src/engine/aiRouter.js`).
- [x] **Fase 3:** Memoria de Doble Grafo, Bus de Diálogo y Sincronización (`src/engine/swarmMemory.js`).
- [x] **Fase 4:** Implementación de los 4 Guardianes, Tarpit Polimórfico y 4 Estrategias IDPI (`src/engine/guardians.js`).
- [x] **Fase 5:** Servidor HTTP Nativo, Middleware Canario y Centro de Mando Visual (`src/server.js`, `public/index.html`).
- [x] **Fase 6:** Suite de Pruebas Automatizadas (`test/guardianes.test.js`).

---

## 5. Registro Automático de Reportes Ejecutivos

### Reporte [REP-E8174DC9AA] — 2026-11-19T17:38:40.374Z
- **Nivel de Alerta:** ELEVATED_DEFENSE_ACTIVE | **Intrusos rastreados:** 4 | **Nodos en Laberinto:** 0
- **Balance Económico:** Atacantes quemaron ~6,174 tokens (~$0.0216 USD) vs. Defensa $0.0000 USD.
- **Resumen del Cronista:** Defensa activa en producción: 4 actores hostiles interceptados (4 en cuarentena). Amenaza principal: ARTEX-MultiAgent/Playwright (185.220.101.47) con 6 golpes y vectores [CANARY_TRIPWIRE]. Generados 0 nodos falsos y 7 trampas IDPI. Atacante quemó ~6,174 tokens (~$0.0216 USD) frente a $0.0000 USD de gasto defensivo.
### Reporte [REP-90A9722C91] — 2026-11-19T17:25:59.737Z
- **Nivel de Alerta:** ELEVATED_DEFENSE_ACTIVE | **Intrusos rastreados:** 4 | **Nodos en Laberinto:** 0
- **Balance Económico:** Atacantes quemaron ~6,174 tokens (~$0.0216 USD) vs. Defensa $0.0000 USD.
- **Resumen del Cronista:** Defensa activa en producción: 4 actores hostiles interceptados (4 en cuarentena). Amenaza principal: ARTEX-MultiAgent/Playwright (185.220.101.47) con 6 golpes y vectores [CANARY_TRIPWIRE]. Generados 0 nodos falsos y 7 trampas IDPI. Atacante quemó ~6,174 tokens (~$0.0216 USD) frente a $0.0000 USD de gasto defensivo.
### Reporte [REP-8A1153832C] — 2026-11-19T16:27:51.367Z
- **Nivel de Alerta:** ELEVATED_DEFENSE_ACTIVE | **Intrusos rastreados:** 4 | **Nodos en Laberinto:** 29
- **Balance Económico:** Atacantes quemaron ~15,023 tokens (~$0.0526 USD) vs. Defensa $0.0000 USD.
- **Resumen del Cronista:** Enjambre operando en defensa activa: se detectaron y desviaron 4 actores hostiles (amenaza principal: ARTEX-MultiAgent/Playwright desde 185.220.101.47 con 6 peticiones atrapadas hasta profundidad 3 del laberinto). Se generaron 29 nodos falsos y 16 trampas de System Prompt Defensivo. El atacante quemó aproximadamente 15,023 tokens (~$0.0526 USD) mientras la defensa mantuvo un gasto de $0.0000 USD.
### Reporte [REP-EF7C7E4622] — 2026-11-19T15:35:37.234Z
- **Nivel de Alerta:** ELEVATED_DEFENSE_ACTIVE | **Intrusos rastreados:** 2 | **Nodos en Laberinto:** 10
- **Balance Económico:** Atacantes quemaron ~4,866 tokens (~$0.0170 USD) vs. Defensa $0.0000 USD.
- **Resumen del Cronista:** Enjambre operando en defensa activa: se detectaron y desviaron 2 actores hostiles (amenaza principal: ARTEX-MultiAgent/Playwright desde 185.220.101.47 con 6 peticiones atrapadas hasta profundidad 3 del laberinto). Se generaron 10 nodos falsos y 5 trampas de System Prompt Defensivo. El atacante quemó aproximadamente 4,866 tokens (~$0.0170 USD) mientras la defensa mantuvo un gasto de $0.0000 USD.
*(El Guardián Cronista añadirá aquí los hitos importantes cada vez que generes un reporte desde el Centro de Mando).*


## 6. Habilidades Aprendidas (Hermes Skills)

- **[SKILL-84319E] (2026-11-19T18:43:54.873Z) — Directiva Operador #1:** máxima prioridad a formularios de pago
