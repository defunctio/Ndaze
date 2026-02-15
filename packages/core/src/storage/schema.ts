import { Database } from "bun:sqlite";

const MIGRATIONS = [
  `CREATE TABLE IF NOT EXISTS cves (
    cve_id           TEXT PRIMARY KEY,
    summary          TEXT NOT NULL,
    description      TEXT,
    published_at     TEXT NOT NULL,
    modified_at      TEXT,
    cvss_v3_score    REAL,
    cvss_v3_vector   TEXT,
    cvss_v4_score    REAL,
    cvss_v4_vector   TEXT,
    cwe_ids          TEXT NOT NULL DEFAULT '[]',
    affected_products TEXT NOT NULL DEFAULT '[]',
    "references"     TEXT NOT NULL DEFAULT '[]',
    raw_data         TEXT,
    created_at       TEXT DEFAULT (datetime('now')),
    updated_at       TEXT DEFAULT (datetime('now'))
  )`,

  `CREATE TABLE IF NOT EXISTS cve_sources (
    cve_id      TEXT NOT NULL REFERENCES cves(cve_id),
    source_name TEXT NOT NULL,
    source_id   TEXT,
    fetched_at  TEXT NOT NULL,
    PRIMARY KEY (cve_id, source_name)
  )`,

  `CREATE TABLE IF NOT EXISTS scores (
    cve_id          TEXT PRIMARY KEY REFERENCES cves(cve_id),
    composite_score REAL NOT NULL,
    cvss_weight     REAL,
    epss_score      REAL,
    epss_percentile REAL,
    in_cisa_kev     INTEGER DEFAULT 0,
    has_public_poc  INTEGER DEFAULT 0,
    patch_available INTEGER DEFAULT 0,
    recency_bonus   REAL,
    scored_at       TEXT DEFAULT (datetime('now'))
  )`,

  `CREATE TABLE IF NOT EXISTS exploits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT NOT NULL REFERENCES cves(cve_id),
    status      TEXT NOT NULL DEFAULT 'proposed',
    notes       TEXT,
    workspace   TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now'))
  )`,

  `CREATE TABLE IF NOT EXISTS sync_state (
    source_name TEXT PRIMARY KEY,
    last_cursor TEXT,
    last_run_at TEXT,
    status      TEXT DEFAULT 'idle'
  )`,

  `CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_at)`,
  `CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_v3_score)`,
  `CREATE INDEX IF NOT EXISTS idx_scores_composite ON scores(composite_score DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_exploits_cve ON exploits(cve_id)`,
  `CREATE INDEX IF NOT EXISTS idx_exploits_status ON exploits(status)`,
];

export function applyMigrations(db: Database): void {
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");

  db.transaction(() => {
    for (const sql of MIGRATIONS) {
      db.exec(sql);
    }
  })();
}
