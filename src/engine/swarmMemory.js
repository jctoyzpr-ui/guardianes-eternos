/**
 * @fileoverview Memoria de Doble Grafo Defensivo v5.0:
 *  - Cuarentena separada (`quarantineMap`) persistente con TTL e IPv6 /64 (H-02).
 *  - `threatGraph` con política LRU verdadera (nunca expulsa cuarentenas).
 *  - Cola asíncrona por lotes hacia SQLite cada 250ms (H-07).
 *  - EventEmitter de deltas en tiempo real para SSE (`GET /events`).
 */

import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';

const MAX_DIALOGUE_MESSAGES = 200;
const MAX_LABYRINTH_NODES = 500;
const MAX_REPORTS = 30;
const MAX_THREATS = 250;
const DEFAULT_QUARANTINE_TTL_MS = 24 * 3600 * 1000; // 24 horas

const SYNC_SECTION_MARKER = '## 5. Registro Automático de Reportes Ejecutivos';

/**
 * Normaliza una IP; para IPv6 agrupa por prefijo /64 para evitar inundación de subred (H-02).
 */
export function normalizeIpKey(rawIp) {
  const clean = String(rawIp || '127.0.0.1').replace(/^::ffff:/, '').trim();
  if (net.isIPv6(clean)) {
    const expanded = expandIpv6(clean);
    if (expanded) {
      return `ip:${expanded.slice(0, 4).join(':')}::/64`;
    }
  }
  return `ip:${clean}`;
}

function expandIpv6(ip) {
  try {
    const parts = ip.split('::');
    if (parts.length > 2) return null;
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 0) return null;
    const full = [...left, ...Array(missing).fill('0'), ...right];
    return full.map((h) => h.padStart(4, '0').toLowerCase());
  } catch {
    return null;
  }
}

export class SwarmMemory extends EventEmitter {
  /**
   * @param {string} [memoryFilePath]
   * @param {import('./sqliteStore.js').SQLiteStore|null} [store]
   * @param {object} [opts]
   */
  constructor(
    memoryFilePath = path.resolve(process.cwd(), 'MEMORIA_PROYECTO.md'),
    store = null,
    opts = {}
  ) {
    super();
    this.setMaxListeners(100);
    this.memoryFilePath = memoryFilePath;
    this.store = store;
    this.quarantineTtlMs = opts.quarantineTtlMs || DEFAULT_QUARANTINE_TTL_MS;
    this._pendingThreats = new Map();
    this._pendingQuarantines = new Map();
    this._pendingDeletedQuarantines = new Set();
    this._pendingDialogues = [];
    this._flushTimer = null;
    this._pruneTimer = null;

    this.reset(false);
    if (this.store) {
      this._hydrateFromStore();
      this._startBackgroundLoops();
    }
  }

  _startBackgroundLoops() {
    this._flushTimer = setInterval(() => {
      this.flushNow();
    }, 250);
    this._flushTimer.unref?.();

    // M-01: poda periódica de retención cada hora
    this._pruneTimer = setInterval(() => {
      try {
        this.store?.pruneOldLogs();
      } catch {
        // ignore prune error
      }
    }, 3600_000);
    this._pruneTimer.unref?.();
  }

  stopTimers() {
    if (this._flushTimer) clearInterval(this._flushTimer);
    if (this._pruneTimer) clearInterval(this._pruneTimer);
    this._flushTimer = null;
    this._pruneTimer = null;
    this.flushNow();
  }

  /**
   * Vacía inmediatamente el lote pendiente a SQLite en una sola transacción.
   */
  flushNow() {
    if (!this.store) return;
    if (
      this._pendingThreats.size === 0 &&
      this._pendingQuarantines.size === 0 &&
      this._pendingDeletedQuarantines.size === 0 &&
      this._pendingDialogues.length === 0
    ) {
      return;
    }

    const threats = Array.from(this._pendingThreats.values());
    const quarantines = Array.from(this._pendingQuarantines.values());
    const deletedQuarantines = Array.from(this._pendingDeletedQuarantines.values());
    const dialogues = this._pendingDialogues.splice(0, this._pendingDialogues.length);

    this._pendingThreats.clear();
    this._pendingQuarantines.clear();
    this._pendingDeletedQuarantines.clear();

    try {
      this.store.flushBatch({ threats, quarantines, deletedQuarantines, dialogues });
    } catch {
      // evita caída del servidor si la base está cerrada durante shutdown
    }
  }

  _hydrateFromStore() {
    if (!this.store) return;

    const activeQuarantines = this.store.loadActiveQuarantines();
    for (const q of activeQuarantines) {
      this.quarantineMap.set(q.ipKey, q);
    }

    const savedThreats = this.store.loadThreats(MAX_THREATS);
    for (const t of savedThreats.reverse()) {
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

  reset(clearPersistent = true) {
    this.startedAt = new Date().toISOString();
    this.threatGraph = new Map();
    this.quarantineMap = new Map();
    this.labyrinthGraph = new Map();
    this.dialogueBus = [];
    this.executiveReports = [];
    this.telemetryBeacons = [];
    this._pendingThreats?.clear();
    this._pendingQuarantines?.clear();
    this._pendingDeletedQuarantines?.clear();
    if (this._pendingDialogues) this._pendingDialogues.length = 0;

    this.metrics = {
      totalLegitRequests: 0,
      totalBlockedOrTrappedHits: 0,
      totalDecoyNodesGenerated: 0,
      totalPromptTrapsInjected: 0,
      totalTimeWastedByAttackersMs: 0,
      totalAttackerTokensBurned: 0,
      estimatedAttackerCostUsd: 0,
      totalDialogues: 0,
      tarpitSocketsInUse: 0
    };
    if (clearPersistent && this.store) {
      this.store.clearSessionData();
    }
    this.emit('delta', { type: 'reset', timestamp: this.startedAt });
  }

  /**
   * H-02: Consulta cuarentena separada con verificación de TTL.
   */
  getActiveQuarantine(ipOrKey) {
    if (!ipOrKey) return null;
    const direct = this.quarantineMap.get(ipOrKey);
    const key = direct ? ipOrKey : normalizeIpKey(ipOrKey);
    const entry = direct || this.quarantineMap.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.quarantineMap.delete(key);
      this._pendingDeletedQuarantines.add(key);
      return null;
    }
    return entry;
  }

  /**
   * Registra cuarentena persistente independiente del límite LRU de 250 amenazas.
   */
  addQuarantine(ip, reason = 'High-risk threat', ttlMs = this.quarantineTtlMs) {
    const ipKey = normalizeIpKey(ip);
    const existing = this.quarantineMap.get(ipKey);
    const entry = {
      ipKey,
      ip: String(ip || 'unknown').replace(/^::ffff:/, ''),
      reason,
      expiresAt: Date.now() + ttlMs,
      createdAt: existing?.createdAt || new Date().toISOString(),
      hits: (existing?.hits || 0) + 1
    };
    this.quarantineMap.set(ipKey, entry);
    this._pendingDeletedQuarantines.delete(ipKey);
    this._pendingQuarantines.set(ipKey, entry);
    return entry;
  }

  /**
   * Registra o actualiza una amenaza con política LRU verdadera en `threatGraph`
   * y escritura en lote asíncrona (H-02, H-07).
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

    if (entry) {
      // LRU verdadero: mover al final del Map
      this.threatGraph.delete(actorKey);
      this.threatGraph.set(actorKey, entry);
    } else {
      if (this.threatGraph.size >= MAX_THREATS) {
        const oldestKey = this.threatGraph.keys().next().value;
        if (oldestKey) this.threatGraph.delete(oldestKey);
      }

      entry = {
        actorKey,
        ip: String(ip || 'unknown').replace(/^::ffff:/, ''),
        userAgent: userAgent || 'unknown',
        signature: signature || 'Autonomous-Scanner',
        riskScore: Math.min(100, Math.max(10, riskScore || 75)),
        status: status || 'TRACKING',
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
        quarantined: Boolean(quarantined),
        signalTypes: []
      };
      this.threatGraph.set(actorKey, entry);
    }

    entry.lastSeen = now;
    entry.totalHits += 1;
    entry.riskScore = Math.max(entry.riskScore, Math.min(100, riskScore || entry.riskScore));
    if (quarantined) {
      entry.quarantined = true;
      this.addQuarantine(entry.ip, signature || 'WAF-Quarantine');
    }
    if (status) {
      entry.status = entry.quarantined && status !== 'NEUTRALIZED_BY_IDPI' ? 'QUARANTINED' : status;
    }
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

    // Encolado para vaciado por lote cada 250 ms (H-07)
    this._pendingThreats.set(actorKey, entry);

    this.emit('delta', {
      type: 'threat',
      isNewThreat,
      threat: {
        actorKey: entry.actorKey,
        ip: entry.ip,
        signature: entry.signature,
        riskScore: entry.riskScore,
        quarantined: entry.quarantined,
        totalHits: entry.totalHits,
        labyrinthDepth: entry.labyrinthDepth,
        attackVectors: entry.attackVectors,
        appliedTraps: entry.appliedTraps
      },
      metrics: this.getMetricsSnapshot()
    });

    return { entry, isNewThreat };
  }

  /**
   * Activa o libera manualmente la cuarentena sobre un actor o IP.
   */
  setQuarantine(target, quarantined) {
    let updated = 0;
    const ipKey = target.startsWith('ip:') ? target : normalizeIpKey(target);

    if (quarantined) {
      const cleanIp = target.replace(/^ip:/, '');
      this.addQuarantine(cleanIp, 'Manual-Operator-Quarantine');
      updated += 1;
    } else {
      if (this.quarantineMap.delete(ipKey) || this.quarantineMap.delete(target)) {
        updated += 1;
      }
      this._pendingQuarantines.delete(ipKey);
      this._pendingDeletedQuarantines.add(ipKey);
      this._pendingDeletedQuarantines.add(target);
    }

    for (const entry of this.threatGraph.values()) {
      if (entry.actorKey === target || entry.ip === target || normalizeIpKey(entry.ip) === ipKey) {
        entry.quarantined = Boolean(quarantined);
        entry.status = quarantined ? 'QUARANTINED' : 'TRACKING';
        this._pendingThreats.set(entry.actorKey, entry);
        updated += 1;
      }
    }

    if (this.store) {
      this.flushNow();
      this.store.setThreatQuarantine(target, quarantined);
    }

    this.emit('delta', {
      type: 'quarantine',
      target,
      quarantined: Boolean(quarantined),
      metrics: this.getMetricsSnapshot()
    });
    return updated;
  }

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
    this.emit('delta', { type: 'labyrinth', node });
    return node;
  }

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
      entry.telemetryLeaked.push(beacon);
      this._pendingThreats.set(actorKey, entry);
    }
    this.emit('delta', { type: 'beacon', beacon });
    return beacon;
  }

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
    this._pendingDialogues.push(item);
    if (this._pendingDialogues.length > 500) {
      this._pendingDialogues.shift();
    }

    this.emit('delta', { type: 'dialogue', dialogue: item });
    return item;
  }

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
    this.emit('delta', { type: 'report', report });
    return report;
  }

  syncReportToMarkdown(report) {
    if (!this.memoryFilePath) return false;
    try {
      const bullet = [
        `### Reporte [${report.id}] — ${report.createdAt}`,
        `- **Nivel de Alerta:** ${report.alertLevel} | **Intrusos rastreados:** ${report.summaryMetrics.activeThreats} | **Cuarentenas activas:** ${report.summaryMetrics.quarantinedCount ?? 0}`,
        `- **Balance Económico (Estimado):** Atacantes quemaron ~${report.summaryMetrics.attackerTokensBurned.toLocaleString('en-US')} tokens est. (~$${report.summaryMetrics.attackerCostUsd.toFixed(4)} USD est.) vs. Defensa $${report.summaryMetrics.defenseSpendUsd.toFixed(4)} USD.`,
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

  getMetricsSnapshot() {
    const now = Date.now();
    let activeQuarantines = 0;
    for (const q of this.quarantineMap.values()) {
      if (q.expiresAt > now) activeQuarantines += 1;
    }
    return {
      ...this.metrics,
      quarantinedCount: activeQuarantines
    };
  }

  snapshot(aiConfigSnapshot, shieldConfig = null) {
    return {
      startedAt: this.startedAt,
      persistenceMode: this.store ? (this.store.isMemory ? 'sqlite-memory' : 'sqlite-disk') : 'memory-only',
      metrics: this.getMetricsSnapshot(),
      threats: Array.from(this.threatGraph.values()).sort(
        (a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime()
      ),
      quarantines: Array.from(this.quarantineMap.values()).filter((q) => q.expiresAt > Date.now()),
      labyrinthNodes: Array.from(this.labyrinthGraph.values()).slice(-60).reverse(),
      dialogues: this.dialogueBus.slice(-80).reverse(),
      executiveReports: this.executiveReports.slice(0, 10),
      telemetryBeacons: this.telemetryBeacons.slice(-20).reverse(),
      ai: aiConfigSnapshot,
      shield: shieldConfig
    };
  }
}
