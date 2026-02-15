# Ndaze — CVE Monitor & Exploit Research Platform

## Overview

A tool that continuously crawls public vulnerability databases, normalizes and stores CVE data, scores/prioritizes vulnerabilities by exploitability and impact, and provides a workspace for developing proof-of-concept exploits for security research.

---

## Tech Stack

| Layer | Choice | Rationale |
|---|---|---|
| **Primary language** | TypeScript (Node/Bun) | Best ecosystem for HTTP clients, scrapers, APIs, scheduling. Strong typing. |
| **Runtime** | Bun | Fast startup, built-in test runner, native TS, SQLite driver built-in. |
| **Database** | SQLite (via `bun:sqlite`) | Zero-config, embedded, good enough for single-node. Migrate to Postgres later if needed. |
| **Scheduler** | `cron`-style in-process (e.g. `croner`) | Keeps it simple — single binary, no external deps. |
| **CLI / TUI** | `commander` + `ink` (optional TUI) | Fast to build, good DX. |
| **Future option** | Rust modules via NAPI | If any analysis pipeline becomes a bottleneck, hot paths can be rewritten. |

---

## Data Sources (Priority Order)

### Tier 1 — Structured APIs (machine-readable, reliable)
1. **NVD (National Vulnerability Database)** — REST API v2.0 (`services.nvd.nist.gov/rest/json/cves/2.0`)
   - CVSS scores, CWE mappings, CPE affected products
   - Rate-limited (no key: 5 req/30s, with key: 50 req/30s)
2. **CISA KEV (Known Exploited Vulnerabilities)** — JSON feed
   - Actively exploited in the wild — highest signal for prioritization
3. **GitHub Security Advisories (GHSA)** — GraphQL API
   - Covers open-source ecosystem well, has severity + affected package ranges
4. **OSV (Open Source Vulnerabilities)** — REST API (`api.osv.dev`)
   - Google-backed, covers Go, npm, PyPI, crates.io, etc.

### Tier 2 — Semi-structured (requires parsing)
5. **Linux Kernel Security** — `git log` of stable/security branches + lore.kernel.org
6. **oss-security mailing list** — Archive scraping (`www.openwall.com/lists/oss-security`)
7. **Exploit-DB** — Has a searchable archive and a git mirror (`gitlab.com/exploit-database/exploitdb`)
8. **PacketStorm Security** — RSS + scraping

### Tier 3 — Enrichment
9. **EPSS (Exploit Prediction Scoring System)** — CSV/API from FIRST.org
   - Probability a CVE will be exploited in the next 30 days
10. **MITRE ATT&CK** — Map CVEs to attack techniques
11. **Nuclei Templates** — Check if a detection template already exists

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                     CLI / TUI                        │
│              (query, browse, triage)                 │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│                  Core Engine                          │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────┐ │
│  │  Ingestion │ │ Scoring /  │ │  Exploit Tracker  │ │
│  │  Pipeline  │ │ Ranking    │ │  & Workspace      │ │
│  └─────┬──────┘ └─────┬──────┘ └────────┬─────────┘ │
│        │              │                  │           │
│  ┌─────▼──────────────▼──────────────────▼─────────┐ │
│  │              SQLite Database                     │ │
│  │  cves | sources | scores | exploits | tags      │ │
│  └─────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│              Source Adapters                          │
│  ┌─────┐ ┌──────┐ ┌─────┐ ┌─────┐ ┌──────┐        │
│  │ NVD │ │ CISA │ │ OSV │ │GHSA │ │ EPSS │ ...    │
│  └─────┘ └──────┘ └─────┘ └─────┘ └──────┘        │
└──────────────────────────────────────────────────────┘
```

---

## Project Structure

```
ndaze/
├── package.json
├── tsconfig.json
├── bunfig.toml
├── src/
│   ├── index.ts                  # CLI entrypoint
│   ├── config.ts                 # Configuration loading
│   ├── db/
│   │   ├── schema.ts             # Table definitions, migrations
│   │   └── queries.ts            # Prepared statements / query helpers
│   ├── sources/
│   │   ├── adapter.ts            # Base adapter interface
│   │   ├── nvd.ts                # NVD API adapter
│   │   ├── cisa-kev.ts           # CISA KEV feed adapter
│   │   ├── ghsa.ts               # GitHub Security Advisories
│   │   ├── osv.ts                # OSV API adapter
│   │   ├── epss.ts               # EPSS scoring data
│   │   ├── exploit-db.ts         # Exploit-DB adapter
│   │   └── kernel.ts             # Linux kernel security tracker
│   ├── scoring/
│   │   ├── engine.ts             # Composite scoring engine
│   │   ├── cvss.ts               # CVSS vector parsing / recalculation
│   │   ├── epss.ts               # EPSS integration
│   │   └── heuristics.ts         # Custom heuristics (age, patch availability, etc.)
│   ├── scheduler/
│   │   └── cron.ts               # Scheduled crawl orchestration
│   ├── exploit/
│   │   ├── tracker.ts            # Track PoC development status per CVE
│   │   └── templates.ts          # Scaffold exploit workspace from CVE metadata
│   └── util/
│       ├── http.ts               # Rate-limited HTTP client
│       └── logger.ts             # Structured logging
├── data/
│   └── ndaze.db                  # SQLite database (gitignored)
└── tests/
    ├── sources/
    └── scoring/
```

---

## Database Schema (Core Tables)

```sql
-- Core CVE records
CREATE TABLE cves (
    cve_id          TEXT PRIMARY KEY,       -- e.g. CVE-2024-1234
    summary         TEXT NOT NULL,
    description     TEXT,
    published_at    TEXT NOT NULL,           -- ISO 8601
    modified_at     TEXT,
    cvss_v3_score   REAL,
    cvss_v3_vector  TEXT,
    cvss_v4_score   REAL,
    cvss_v4_vector  TEXT,
    cwe_ids         TEXT,                   -- JSON array
    affected_products TEXT,                 -- JSON array of CPE strings
    references      TEXT,                   -- JSON array of URLs
    raw_data        TEXT,                   -- Full JSON from source
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now'))
);

-- Which sources have reported this CVE
CREATE TABLE cve_sources (
    cve_id      TEXT NOT NULL REFERENCES cves(cve_id),
    source_name TEXT NOT NULL,              -- 'nvd', 'ghsa', 'osv', etc.
    source_id   TEXT,                       -- source-specific ID
    fetched_at  TEXT NOT NULL,
    PRIMARY KEY (cve_id, source_name)
);

-- Composite priority scores
CREATE TABLE scores (
    cve_id          TEXT PRIMARY KEY REFERENCES cves(cve_id),
    composite_score REAL NOT NULL,          -- 0-100, our weighted score
    cvss_weight     REAL,
    epss_score      REAL,                   -- probability of exploitation
    epss_percentile REAL,
    in_cisa_kev     INTEGER DEFAULT 0,      -- boolean: actively exploited
    has_public_poc  INTEGER DEFAULT 0,      -- boolean
    patch_available INTEGER DEFAULT 0,      -- boolean
    recency_bonus   REAL,                   -- newer = higher
    scored_at       TEXT DEFAULT (datetime('now'))
);

-- Exploit PoC tracking
CREATE TABLE exploits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT NOT NULL REFERENCES cves(cve_id),
    status      TEXT NOT NULL DEFAULT 'proposed',  -- proposed | research | wip | done | abandoned
    notes       TEXT,
    workspace   TEXT,                       -- path to local exploit workspace
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now'))
);

-- Crawl state tracking
CREATE TABLE sync_state (
    source_name TEXT PRIMARY KEY,
    last_cursor TEXT,                       -- source-specific cursor/timestamp
    last_run_at TEXT,
    status      TEXT DEFAULT 'idle'         -- idle | running | error
);
```

---

## Prioritization / Scoring Model

The composite score (0–100) is calculated as a weighted blend:

| Signal | Weight | Source | Rationale |
|---|---|---|---|
| CVSS v3/v4 base score | 25% | NVD | Industry-standard severity |
| EPSS score | 25% | FIRST.org | Empirical exploit probability |
| CISA KEV membership | 20% | CISA | Confirmed active exploitation |
| Public PoC exists | 15% | Exploit-DB, GitHub, Nuclei | Lowers barrier to exploitation |
| Recency | 10% | Published date | Newer CVEs = more actionable |
| Patch unavailable | 5% | NVD references | 0-days are higher priority |

Bonuses / overrides:
- **CISA KEV** → floor score at 75 regardless of other signals
- **Linux kernel** CVEs get a category tag boost (configurable per project interest)
- **Memory corruption** CWEs (CWE-119, CWE-416, CWE-787, etc.) get +10 bonus

---

## Implementation Phases

### Phase 1 — Foundation
- [ ] Project scaffolding (Bun + TypeScript, tsconfig, linting)
- [ ] SQLite database setup with schema + migrations
- [ ] Rate-limited HTTP client utility
- [ ] Source adapter interface definition
- [ ] NVD adapter (primary, most comprehensive source)
- [ ] CISA KEV adapter (simple JSON fetch)
- [ ] Basic CLI: `ndaze sync` to run a crawl, `ndaze list` to query

### Phase 2 — Scoring & Prioritization
- [ ] EPSS data ingestion
- [ ] CVSS vector parser
- [ ] Composite scoring engine
- [ ] CLI: `ndaze top` — show top N prioritized CVEs
- [ ] CLI: `ndaze search <query>` — full-text search
- [ ] Filtering by CWE, product, date range, score threshold

### Phase 3 — More Sources & Enrichment
- [ ] OSV adapter
- [ ] GHSA adapter
- [ ] Exploit-DB adapter (git mirror or scraping)
- [ ] Linux kernel security tracker
- [ ] Cross-reference deduplication (same CVE from multiple sources)
- [ ] Nuclei template existence check

### Phase 4 — Exploit Workspace
- [ ] `ndaze exploit init <CVE-ID>` — scaffold a workspace directory
- [ ] Auto-populate workspace with: advisory text, affected versions, references, related patches
- [ ] Status tracking (proposed → research → wip → done → abandoned)
- [ ] `ndaze exploit list` — show all tracked exploit efforts

### Phase 5 — Automation & Monitoring
- [ ] Scheduled crawls (configurable interval per source)
- [ ] Notifications on new high-priority CVEs (webhook, or simple stdout alert)
- [ ] Watch lists (specific products/vendors to track)
- [ ] Dashboard TUI (optional, using `ink`)

---

## Key Design Decisions to Confirm

1. **Bun vs Node** — Plan uses Bun for speed and built-in SQLite. Fallback to Node + better-sqlite3 if needed.
2. **SQLite vs Postgres** — Starting with SQLite for zero-config. If multi-user or high-volume is needed later, Postgres migration path is straightforward.
3. **CLI-first** — No web UI initially. TUI is optional in Phase 5. Web frontend can be added later.
4. **Monorepo, single package** — No need for workspace splitting until the project is large enough to warrant it.
5. **NVD API key** — Optional but recommended. Free to request at https://nvd.nist.gov/developers/request-an-api-key. We'll support both keyed and unkeyed modes.
