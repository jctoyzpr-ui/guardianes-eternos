/**
 * @fileoverview Memoria de Doble Grafo Defensivo, Bus de Diálogo del Enjambre,
 * persistencia respaldada por SQLite nativo y Sincronizador con MEMORIA_PROYECTO.md.
 */

import fs from 'node:fs';
import path from 'node:path';

const MAX_DIALOGUE_MESSAGES = 200;
const MAX_LABYRINTH_NODES = 500;
const MAX_REPORTS = 30;
const MAX_THREATS = 250;

const SYNC_SECTION_MARKER = '## 5. Registro Automático de Reportes Ejecutivos';

export class SwarmMemory {
  /**
   * @param {string} [memoryFilePath]
   * @param {import('./sqliteStore.js').SQLiteStore|null} [store]
   */
  constructor(memoryFilePath = path.resolve(process.cwd(), 'MEMORIA_PROYECTO.md'), store = null) {
    this.memoryFilePath = memoryFilePath;
    this.store = store;
    this.reset(false);
    if (this.store) {
      this._hydrateFromStore();
    }
  }

  /**
   * Carga amenazas, diálogos y reportes persistidos desde SQLite al arrancar.
   */
  _hydrateFromStore() {
    if (!this.store) return;
    const savedThreats = this.store.loadThreats(MAX_THREATS);
    for (const t of savedThreats) {
      this.threatGraph.set(t.actorKey, t);
      this.metrics.totalBlockedOrTrappedHits += t.totalHits || 0;
      this.metrics.totalTimeWastedByAttackersMs += t.timeWastedMs || 0;
      this.metrics.totalAttackerTokensBurned += t.estimatedAttackerTokensBurned || 0;
      this.metrics.estimatedAttackerCostUsd = Number(
        (this.metrics.estimatedAttackerCostUsd + (t.estimatedAttackerCostUsd || 0)).toFixed(6)
      );
      this.metrics.totalPromptTrapsInjected += (t.appliedTraps || []).length;
      if (Array.isArray(t.telemetryLeaked)) {
        for (const beacon of t.telemetryLeaked) {
          this.telemetryBeacons.push(beacon);
        }
      }
    }

    const savedDialogues = this.store.loadDialogues(MAX_DIALOGUE_MESSAGES);
    this.dialogueBus = savedDialogues;
    this.metrics.totalDialogues = savedDialogues.length;

    const savedReports = this.store.loadReports(MAX_REPORTS);
    this.executiveReports = savedReports;
  }

  /**
   * Reinicia las estructuras de memoria (y limpia SQLite si clearPersistent=true).
   */
  reset(clearPersistent = true) {
    this.startedAt = new Date().toISOString();
    this.threatGraph = new Map();
    this.labyrinthGraph = new Map();
    this.dialogueBus = [];
    this.executiveReports = [];
    this.telemetryBeacons = [];
    this.metrics = {
      totalLegitRequests: 0,
      totalBlockedOrTrappedHits: 0,
      totalDecoyNodesGenerated: 0,
      totalPromptTrapsInjected: 0,
      totalTimeWastedByAttackersMs: 0,
      totalAttackerTokensBurned: 0,
      estimatedAttackerCostUsd: 0,
      totalDialogues: 0
    };
    if (clearPersistent && this.store) {
      this.store.clearSessionData();
    }
  }

  /**
   * Registra o actualiza un nodo de amenaza dentro del Grafo de Amenazas (threatGraph) y SQLite.
   */
  recordThreatInteraction({
    actorKey,
    ip,
    userAgent,
    signature,
    riskScore,
    pathVisited,
    status,
    delayMs = 0,
    tokensBurned = 0,
    trapStrategy = null,
    attackVectors = [],
    quarantined = false
  }) {
    const now = new Date().toISOString();
    let entry = this.threatGraph.get(actorKey);
    const isNewThreat = !entry;

    if (!entry) {
      if (this.threatGraph.size >= MAX_THREATS) {
        const oldestKey = this.threatGraph.keys().next().value;
        if (oldestKey) this.threatGraph.delete(oldestKey);
      }

      entry = {
        actorKey,
        ip: ip || 'unknown',
        userAgent: userAgent || 'unknown',
        signature: signature || 'Autonomous-Scanner',
        riskScore: Math.min(100, Math.max(10, riskScore || 75)),
        status: status || 'TRAPPED_IN_LABYRINTH',
        firstSeen: now,
        lastSeen: now,
        pathsVisited: [],
        totalHits: 0,
        labyrinthDepth: 0,
        timeWastedMs: 0,
        estimatedAttackerTokensBurned: 0,
        estimatedAttackerCostUsd: 0,
        appliedTraps: [],
        attackVectors: [],
        telemetryLeaked: [],
        quarantined: Boolean(quarantined)
      };
      this.threatGraph.set(actorKey, entry);
    }

    entry.lastSeen = now;
    entry.totalHits += 1;
    entry.riskScore = Math.max(entry.riskScore, Math.min(100, riskScore || entry.riskScore));
    if (quarantined) entry.quarantined = true;
    if (status) entry.status = entry.quarantined && status !== 'NEUTRALIZED_BY_IDPI' ? 'QUARANTINED' : status;
    if (signature && entry.signature === 'Autonomous-Scanner') {
      entry.signature = signature;
    }

    if (Array.isArray(attackVectors)) {
      for (const vec of attackVectors) {
        if (vec && !entry.attackVectors.includes(vec)) {
          entry.attackVectors.push(vec);
        }
      }
    }

    if (pathVisited && !entry.pathsVisited.includes(pathVisited)) {
      if (entry.pathsVisited.length >= 60) entry.pathsVisited.shift();
      entry.pathsVisited.push(pathVisited);
    }

    if (pathVisited && (pathVisited.includes('/shard-') || pathVisited.includes('/vault/'))) {
      entry.labyrinthDepth += 1;
    }

    entry.timeWastedMs += delayMs;
    entry.estimatedAttackerTokensBurned += tokensBurned;
    const addedCost = (tokensBurned / 1_000_000) * 3.5;
    entry.estimatedAttackerCostUsd = Number((entry.estimatedAttackerCostUsd + addedCost).toFixed(6));

    if (trapStrategy && !entry.appliedTraps.includes(trapStrategy)) {
      entry.appliedTraps.push(trapStrategy);
      this.metrics.totalPromptTrapsInjected += 1;
    }

    this.metrics.totalBlockedOrTrappedHits += 1;
    this.metrics.totalTimeWastedByAttackersMs += delayMs;
    this.metrics.totalAttackerTokensBurned += tokensBurned;
    this.metrics.estimatedAttackerCostUsd = Number(
      (this.metrics.estimatedAttackerCostUsd + addedCost).toFixed(6)
    );

    if (this.store) {
      this.store.upsertThreat(entry);
    }

    return { entry, isNewThreat };
  }

  /**
   * Activa o libera manualmente la cuarentena sobre un actor o IP.
   */
  setQuarantine(target, quarantined) {
    let updated = 0;
    for (const entry of this.threatGraph.values()) {
      if (entry.actorKey === target || entry.ip === target) {
        entry.quarantined = Boolean(quarantined);
        entry.status = quarantined ? 'QUARANTINED' : 'TRACKING';
        if (this.store) this.store.upsertThreat(entry);
        updated += 1;
      }
    }
    if (this.store) {
      this.store.setThreatQuarantine(target, quarantined);
    }
    return updated;
  }

  /**
   * Registra un nodo falso generado en el Grafo del Laberinto (labyrinthGraph).
   */
  recordDecoyNode({ path: decoyPath, nodeType, parentPath, actorKey, canaryToken }) {
    const now = new Date().toISOString();
    const existing = this.labyrinthGraph.get(decoyPath);
    if (existing) {
      existing.hits += 1;
      existing.lastHit = now;
      return existing;
    }

    if (this.labyrinthGraph.size >= MAX_LABYRINTH_NODES) {
      const oldestKey = this.labyrinthGraph.keys().next().value;
      if (oldestKey) this.labyrinthGraph.delete(oldestKey);
    }

    const node = {
      path: decoyPath,
      nodeType,
      parentPath: parentPath || '/',
      actorKey,
      canaryToken,
      createdAt: now,
      lastHit: now,
      hits: 1
    };

    this.labyrinthGraph.set(decoyPath, node);
    this.metrics.totalDecoyNodesGenerated += 1;
    return node;
  }

  /**
   * Registra la autodelación de un agente atacante que siguió una baliza de telemetría.
   */
  recordTelemetryBeacon(actorKey, telemetry) {
    const entry = this.threatGraph.get(actorKey);
    const beacon = {
      timestamp: new Date().toISOString(),
      actorKey,
      ...telemetry
    };
    this.telemetryBeacons.push(beacon);
    if (this.telemetryBeacons.length > 100) this.telemetryBeacons.shift();

    if (entry) {
      entry.status = 'NEUTRALIZED_BY_IDPI';
      entry.quarantined = true;
      entry.telemetryLeaked.push(beacon);
      if (this.store) this.store.upsertThreat(entry);
    }
    return beacon;
  }

  /**
   * Publica un mensaje en el Bus de Diálogo Coordinado del Enjambre.
   */
  postDialogue({ from, to = 'SWARM', severity = 'INFO', modelUsed = 'deterministic-swarm-v1', message, metadata = {} }) {
    this.metrics.totalDialogues += 1;
    const item = {
      id: `dlg_${Date.now()}_${this.metrics.totalDialogues}`,
      timestamp: new Date().toISOString(),
      from,
      to,
      severity,
      modelUsed,
      message,
      metadata
    };
    this.dialogueBus.push(item);
    if (this.dialogueBus.length > MAX_DIALOGUE_MESSAGES) {
      this.dialogueBus.shift();
    }
    if (this.store) {
      this.store.insertDialogue(item);
    }
    return item;
  }

  /**
   * Guarda un reporte ejecutivo en memoria, SQLite y MEMORIA_PROYECTO.md.
   */
  addExecutiveReport(report, syncToDisk = true) {
    this.executiveReports.unshift(report);
    if (this.executiveReports.length > MAX_REPORTS) {
      this.executiveReports.pop();
    }
    if (this.store) {
      this.store.insertReport(report);
    }
    if (syncToDisk) {
      this.syncReportToMarkdown(report);
    }
    return report;
  }

  /**
   * Añade el reporte ejecutivo a la sección 5 de MEMORIA_PROYECTO.md sin alterar el resto del documento.
   */
  syncReportToMarkdown(report) {
    if (!this.memoryFilePath) return false;
    try {
      const bullet = [
        `### Reporte [${report.id}] — ${report.createdAt}`,
        `- **Nivel de Alerta:** ${report.alertLevel} | **Intrusos rastreados:** ${report.summaryMetrics.activeThreats} | **Nodos en Laberinto:** ${report.summaryMetrics.decoyNodes}`,
        `- **Balance Económico:** Atacantes quemaron ~${report.summaryMetrics.attackerTokensBurned.toLocaleString('en-US')} tokens (~$${report.summaryMetrics.attackerCostUsd.toFixed(4)} USD) vs. Defensa $${report.summaryMetrics.defenseSpendUsd.toFixed(4)} USD.`,
        `- **Resumen del Cronista:** ${report.narrative.replace(/\r?\n+/g, ' ')}`,
        ''
      ].join('\n');

      if (!fs.existsSync(this.memoryFilePath)) {
        fs.writeFileSync(
          this.memoryFilePath,
          `# Bitácora Viva del Proyecto: **Guardianes Eternos**\n\n${SYNC_SECTION_MARKER}\n\n${bullet}`,
          'utf8'
        );
        return true;
      }

      const current = fs.readFileSync(this.memoryFilePath, 'utf8');
      const idx = current.indexOf(SYNC_SECTION_MARKER);
      if (idx === -1) {
        fs.appendFileSync(this.memoryFilePath, `\n\n${SYNC_SECTION_MARKER}\n\n${bullet}`, 'utf8');
        return true;
      }

      const headerEnd = idx + SYNC_SECTION_MARKER.length;
      const before = current.slice(0, headerEnd);
      const after = current.slice(headerEnd).replace(/\s*\*\(El Guardián Cronista[^\n]*\)\*\s*/g, '');
      const updated = `${before}\n\n${bullet}${after.trimStart()}`;
      fs.writeFileSync(this.memoryFilePath, updated, 'utf8');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Serializa el estado completo para el Centro de Mando Visual.
   */
  snapshot(aiConfigSnapshot, shieldConfig = null) {
    return {
      startedAt: this.startedAt,
      persistenceMode: this.store ? (this.store.isMemory ? 'sqlite-memory' : 'sqlite-disk') : 'memory-only',
      metrics: {
        ...this.metrics,
        quarantinedCount: Array.from(this.threatGraph.values()).filter((t) => t.quarantined).length
      },
      threats: Array.from(this.threatGraph.values()).sort(
        (a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime()
      ),
      labyrinthNodes: Array.from(this.labyrinthGraph.values()).slice(-60).reverse(),
      dialogues: this.dialogueBus.slice(-80).reverse(),
      executiveReports: this.executiveReports.slice(0, 10),
      telemetryBeacons: this.telemetryBeacons.slice(-20).reverse(),
      ai: aiConfigSnapshot,
      shield: shieldConfig
    };
  }
}
