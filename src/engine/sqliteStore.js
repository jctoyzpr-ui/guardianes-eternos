/**
 * @fileoverview Persistencia real en SQLite nativo (node:sqlite / DatabaseSync).
 * Almacena amenazas, cuarentenas de IPs, diálogos del enjambre, reportes ejecutivos
 * y configuración protegida con cifrado AES-256-GCM para llaves/tokens sensibles.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export class SQLiteStore {
  /**
   * @param {string} [dbPath] Ruta del archivo SQLite o ':memory:' para pruebas.
   */
  constructor(dbPath = path.resolve(process.cwd(), 'data/guardianes.sqlite')) {
    this.dbPath = dbPath;
    this.isMemory = dbPath === ':memory:';

    if (!this.isMemory) {
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    }

    this.db = new DatabaseSync(dbPath);
    if (!this.isMemory) {
      this.db.exec('PRAGMA journal_mode = WAL;');
    }
    this.db.exec('PRAGMA busy_timeout = 3000;');
    this._vaultKey = this._initVaultKey();
    this._initSchema();
  }

  _initVaultKey() {
    if (this.isMemory) {
      return crypto.randomBytes(32);
    }
    const keyPath = path.join(path.dirname(this.dbPath), '.vault.key');
    if (fs.existsSync(keyPath)) {
      const hex = fs.readFileSync(keyPath, 'utf8').trim();
      if (/^[0-9a-f]{64}$/i.test(hex)) {
        return Buffer.from(hex, 'hex');
      }
    }
    const generated = crypto.randomBytes(32);
    fs.writeFileSync(keyPath, generated.toString('hex'), { encoding: 'utf8', mode: 0o600 });
    return generated;
  }

  _initSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS threats (
        actor_key TEXT PRIMARY KEY,
        ip TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        signature TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        status TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        total_hits INTEGER NOT NULL,
        labyrinth_depth INTEGER NOT NULL,
        time_wasted_ms INTEGER NOT NULL,
        tokens_burned INTEGER NOT NULL,
        attacker_cost_usd REAL NOT NULL,
        paths_json TEXT NOT NULL,
        traps_json TEXT NOT NULL,
        telemetry_json TEXT NOT NULL,
        attack_vectors_json TEXT NOT NULL,
        quarantined INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS dialogue_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        severity TEXT NOT NULL,
        model_used TEXT NOT NULL,
        message TEXT NOT NULL,
        metadata_json TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS executive_reports (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        alert_level TEXT NOT NULL,
        model_used TEXT NOT NULL,
        narrative TEXT NOT NULL,
        metrics_json TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS kv_settings (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL
      );
    `);

    this._stmtUpsertThreat = this.db.prepare(`
      INSERT INTO threats (
        actor_key, ip, user_agent, signature, risk_score, status,
        first_seen, last_seen, total_hits, labyrinth_depth, time_wasted_ms,
        tokens_burned, attacker_cost_usd, paths_json, traps_json,
        telemetry_json, attack_vectors_json, quarantined
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(actor_key) DO UPDATE SET
        ip = excluded.ip,
        user_agent = excluded.user_agent,
        signature = excluded.signature,
        risk_score = excluded.risk_score,
        status = excluded.status,
        last_seen = excluded.last_seen,
        total_hits = excluded.total_hits,
        labyrinth_depth = excluded.labyrinth_depth,
        time_wasted_ms = excluded.time_wasted_ms,
        tokens_burned = excluded.tokens_burned,
        attacker_cost_usd = excluded.attacker_cost_usd,
        paths_json = excluded.paths_json,
        traps_json = excluded.traps_json,
        telemetry_json = excluded.telemetry_json,
        attack_vectors_json = excluded.attack_vectors_json,
        quarantined = excluded.quarantined
    `);

    this._stmtInsertDialogue = this.db.prepare(`
      INSERT OR REPLACE INTO dialogue_logs (
        id, timestamp, sender, recipient, severity, model_used, message, metadata_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    this._stmtInsertReport = this.db.prepare(`
      INSERT OR REPLACE INTO executive_reports (
        id, created_at, alert_level, model_used, narrative, metrics_json
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    this._stmtSaveSetting = this.db.prepare(`
      INSERT INTO kv_settings (key, value_json) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json
    `);

    this._stmtLoadSetting = this.db.prepare('SELECT value_json FROM kv_settings WHERE key = ?');
  }

  encryptSecretObject(obj) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this._vaultKey, iv);
    const plaintext = JSON.stringify(obj);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      data: encrypted.toString('hex')
    };
  }

  decryptSecretObject(payload) {
    if (!payload || !payload.iv || !payload.tag || !payload.data) return null;
    try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        this._vaultKey,
        Buffer.from(payload.iv, 'hex')
      );
      decipher.setAuthTag(Buffer.from(payload.tag, 'hex'));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(payload.data, 'hex')),
        decipher.final()
      ]);
      return JSON.parse(decrypted.toString('utf8'));
    } catch {
      return null;
    }
  }

  upsertThreat(entry) {
    this._stmtUpsertThreat.run(
      entry.actorKey,
      entry.ip,
      entry.userAgent,
      entry.signature,
      entry.riskScore,
      entry.status,
      entry.firstSeen,
      entry.lastSeen,
      entry.totalHits,
      entry.labyrinthDepth,
      entry.timeWastedMs,
      entry.estimatedAttackerTokensBurned,
      entry.estimatedAttackerCostUsd,
      JSON.stringify(entry.pathsVisited || []),
      JSON.stringify(entry.appliedTraps || []),
      JSON.stringify(entry.telemetryLeaked || []),
      JSON.stringify(entry.attackVectors || []),
      entry.quarantined ? 1 : 0
    );
  }

  loadThreats(limit = 250) {
    const rows = this.db
      .prepare('SELECT * FROM threats ORDER BY last_seen DESC LIMIT ?')
      .all(limit);
    return rows.map((row) => ({
      actorKey: row.actor_key,
      ip: row.ip,
      userAgent: row.user_agent,
      signature: row.signature,
      riskScore: row.risk_score,
      status: row.status,
      firstSeen: row.first_seen,
      lastSeen: row.last_seen,
      totalHits: row.total_hits,
      labyrinthDepth: row.labyrinth_depth,
      timeWastedMs: row.time_wasted_ms,
      estimatedAttackerTokensBurned: row.tokens_burned,
      estimatedAttackerCostUsd: row.attacker_cost_usd,
      pathsVisited: JSON.parse(row.paths_json || '[]'),
      appliedTraps: JSON.parse(row.traps_json || '[]'),
      telemetryLeaked: JSON.parse(row.telemetry_json || '[]'),
      attackVectors: JSON.parse(row.attack_vectors_json || '[]'),
      quarantined: Boolean(row.quarantined)
    }));
  }

  setThreatQuarantine(target, quarantined) {
    const flag = quarantined ? 1 : 0;
    const status = quarantined ? 'QUARANTINED' : 'TRACKING';
    const info = this.db
      .prepare('UPDATE threats SET quarantined = ?, status = ? WHERE actor_key = ? OR ip = ?')
      .run(flag, status, target, target);
    return info.changes;
  }

  insertDialogue(item) {
    this._stmtInsertDialogue.run(
      item.id,
      item.timestamp,
      item.from,
      item.to,
      item.severity,
      item.modelUsed,
      item.message,
      JSON.stringify(item.metadata || {})
    );
  }

  loadDialogues(limit = 120) {
    const rows = this.db
      .prepare('SELECT * FROM dialogue_logs ORDER BY timestamp DESC LIMIT ?')
      .all(limit);
    return rows
      .reverse()
      .map((r) => ({
        id: r.id,
        timestamp: r.timestamp,
        from: r.sender,
        to: r.recipient,
        severity: r.severity,
        modelUsed: r.model_used,
        message: r.message,
        metadata: JSON.parse(r.metadata_json || '{}')
      }));
  }

  insertReport(report) {
    this._stmtInsertReport.run(
      report.id,
      report.createdAt,
      report.alertLevel,
      report.modelUsed,
      report.narrative,
      JSON.stringify(report.summaryMetrics || {})
    );
  }

  loadReports(limit = 30) {
    const rows = this.db
      .prepare('SELECT * FROM executive_reports ORDER BY created_at DESC LIMIT ?')
      .all(limit);
    return rows.map((r) => ({
      id: r.id,
      createdAt: r.created_at,
      alertLevel: r.alert_level,
      modelUsed: r.model_used,
      narrative: r.narrative,
      summaryMetrics: JSON.parse(r.metrics_json || '{}')
    }));
  }

  saveSetting(key, value) {
    this._stmtSaveSetting.run(key, JSON.stringify(value));
  }

  loadSetting(key, defaultValue = null) {
    const row = this._stmtLoadSetting.get(key);
    if (!row) return defaultValue;
    try {
      return JSON.parse(row.value_json);
    } catch {
      return defaultValue;
    }
  }

  clearSessionData() {
    this.db.exec('DELETE FROM threats; DELETE FROM dialogue_logs; DELETE FROM executive_reports;');
  }

  close() {
    this.db.close();
  }
}
