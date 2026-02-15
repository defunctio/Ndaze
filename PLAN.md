# Ndaze — CVE Monitor & Exploit Research Platform

## Overview

A **library-first, componentized** platform that crawls public vulnerability databases, normalizes and stores CVE data, scores/prioritizes vulnerabilities by exploitability and impact, and provides a workspace for developing proof-of-concept exploits for security research.

The core is a TypeScript library with four distinct components — **Discovery, Ranking, Research, Development** — each with clear boundaries so they can start as in-process modules and later be extracted into standalone services that scale independently.

---

## Tech Stack

| Layer | Choice | Rationale |
|---|---|---|
| **Primary language** | TypeScript (Node/Bun) | Best ecosystem for HTTP clients, scrapers, APIs, scheduling. Strong typing. |
| **Runtime** | Bun | Fast startup, built-in test runner, native TS, SQLite driver built-in. |
| **Monorepo** | Bun workspaces | `packages/core` (library) + `packages/cli` (thin consumer). Clean separation. |
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

### Component Model

The library is organized into **four components** that map to the vulnerability lifecycle. Each component owns its types, exposes a public API, and depends only on shared types + the storage abstraction — never on another component's internals. This means any component can later be extracted into a standalone service behind an API boundary.

```
┌──────────────────────────────────────────────────────────────────┐
│  Consumers (CLI, future web API, scripts, other services)        │
└──────┬──────────────────────────────────────────────────────┬────┘
       │  imports @ndaze/core                                 │
┌──────▼──────────────────────────────────────────────────────▼────┐
│                        @ndaze/core                               │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  ┌────────┐ │
│  │  Discovery    │  │   Ranking    │  │  Research  │  │  Dev   │ │
│  │              │  │              │  │            │  │        │ │
│  │ Source       │  │ Scoring      │  │ Enrichment │  │ PoC    │ │
│  │ adapters,   │  │ engine,      │  │ correlation│  │ scaffold│ │
│  │ crawling,   │  │ prioritize,  │  │ analysis,  │  │ tracking│ │
│  │ ingestion   │  │ filtering    │  │ cross-ref  │  │ workspace│ │
│  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  └───┬────┘ │
│         │                │               │             │       │
│  ┌──────▼────────────────▼───────────────▼─────────────▼─────┐ │
│  │                    Storage Layer                            │ │
│  │         (abstract interface — SQLite impl default)         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Shared: types, config, http client, logger, events        │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Owns | Inputs | Outputs |
|---|---|---|---|
| **Discovery** | Source adapters, crawl scheduling, sync state, raw ingestion | External APIs/feeds | Normalized `CveRecord` objects written to storage |
| **Ranking** | Scoring engine, composite weights, filter/sort | `CveRecord` + enrichment signals (EPSS, KEV, etc.) | `ScoredCve` with composite score + breakdown |
| **Research** | Cross-source correlation, CWE analysis, patch tracking, enrichment | `CveRecord` from multiple sources | Enriched metadata, dedup results, related CVE links |
| **Development** | PoC workspace scaffolding, exploit status tracking | `ScoredCve` + enrichment data | Workspace dirs, status updates, notes |

### Inter-Component Communication

**Today (in-process):** Components call each other through typed interfaces. The `Ndaze` facade class wires them together.

**Future (services):** Replace in-process calls with message queues or gRPC. Each component becomes a service with its own storage instance. The interfaces stay the same — only the transport layer changes.

```typescript
// Example: components don't import each other — they go through interfaces
interface DiscoveryService {
  sync(sources?: string[]): AsyncGenerator<CveRecord>;
  registerAdapter(name: string, adapter: SourceAdapter): void;
  getSyncState(): Promise<SyncState[]>;
}

interface RankingService {
  score(cveId: string): Promise<ScoredCve>;
  scoreAll(): AsyncGenerator<ScoredCve>;
  top(n: number, filters?: FilterOpts): Promise<ScoredCve[]>;
}

interface ResearchService {
  enrich(cveId: string): Promise<EnrichedCve>;
  findRelated(cveId: string): Promise<CveRecord[]>;
  deduplicate(): Promise<DedupeResult>;
}

interface DevelopmentService {
  initWorkspace(cveId: string): Promise<Workspace>;
  updateStatus(cveId: string, status: ExploitStatus): Promise<void>;
  listExploits(filters?: ExploitFilter): Promise<Exploit[]>;
}
```

### Storage Abstraction

Storage is behind an interface so components don't depend on SQLite directly. This enables:
- Swapping SQLite for Postgres when scaling up
- Each service owning its own database in a distributed setup
- Easy testing with in-memory stores

```typescript
interface CveStore {
  upsert(record: CveRecord): Promise<void>;
  get(cveId: string): Promise<CveRecord | null>;
  query(opts: QueryOpts): Promise<CveRecord[]>;
  stream(opts: QueryOpts): AsyncGenerator<CveRecord>;
}

interface ScoreStore { /* similar pattern */ }
interface ExploitStore { /* similar pattern */ }
interface SyncStateStore { /* similar pattern */ }
```

---

## Project Structure

```
ndaze/
├── package.json                    # Workspace root
├── tsconfig.base.json              # Shared compiler options
├── packages/
│   ├── core/                       # @ndaze/core — the library
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── src/
│   │   │   ├── index.ts            # Public API barrel export
│   │   │   ├── ndaze.ts            # Facade: wires components together
│   │   │   ├── config.ts           # Configuration schema + loading
│   │   │   ├── types.ts            # Shared types (CveRecord, ScoredCve, etc.)
│   │   │   │
│   │   │   ├── discovery/
│   │   │   │   ├── index.ts        # DiscoveryService implementation
│   │   │   │   ├── adapter.ts      # SourceAdapter interface
│   │   │   │   ├── registry.ts     # Adapter registration + lookup
│   │   │   │   ├── adapters/
│   │   │   │   │   ├── nvd.ts
│   │   │   │   │   ├── cisa-kev.ts
│   │   │   │   │   ├── ghsa.ts
│   │   │   │   │   ├── osv.ts
│   │   │   │   │   ├── epss.ts
│   │   │   │   │   ├── exploit-db.ts
│   │   │   │   │   └── kernel.ts
│   │   │   │   └── scheduler.ts    # Crawl scheduling
│   │   │   │
│   │   │   ├── ranking/
│   │   │   │   ├── index.ts        # RankingService implementation
│   │   │   │   ├── engine.ts       # Composite scoring logic
│   │   │   │   ├── cvss.ts         # CVSS vector parsing
│   │   │   │   └── heuristics.ts   # Configurable heuristic rules
│   │   │   │
│   │   │   ├── research/
│   │   │   │   ├── index.ts        # ResearchService implementation
│   │   │   │   ├── enrichment.ts   # Cross-source enrichment
│   │   │   │   ├── correlator.ts   # Find related CVEs, dedup
│   │   │   │   └── analysis.ts     # CWE categorization, patch status
│   │   │   │
│   │   │   ├── development/
│   │   │   │   ├── index.ts        # DevelopmentService implementation
│   │   │   │   ├── workspace.ts    # Scaffold exploit workspace dirs
│   │   │   │   └── tracker.ts      # Status tracking (proposed→done)
│   │   │   │
│   │   │   ├── storage/
│   │   │   │   ├── interfaces.ts   # Store interfaces (CveStore, etc.)
│   │   │   │   ├── sqlite.ts       # SQLite implementation
│   │   │   │   └── schema.ts       # Table definitions, migrations
│   │   │   │
│   │   │   └── util/
│   │   │       ├── http.ts         # Rate-limited HTTP client
│   │   │       ├── logger.ts       # Structured logging
│   │   │       └── events.ts       # Typed event emitter for component communication
│   │   │
│   │   └── tests/
│   │       ├── discovery/
│   │       ├── ranking/
│   │       ├── research/
│   │       ├── development/
│   │       └── storage/
│   │
│   └── cli/                        # @ndaze/cli — thin consumer
│       ├── package.json
│       ├── tsconfig.json
│       └── src/
│           ├── index.ts            # CLI entrypoint (commander)
│           ├── commands/
│           │   ├── sync.ts         # ndaze sync [--source nvd,cisa]
│           │   ├── list.ts         # ndaze list [--cwe --product --since]
│           │   ├── top.ts          # ndaze top [--limit 20]
│           │   ├── search.ts       # ndaze search <query>
│           │   ├── exploit.ts      # ndaze exploit init|list|status
│           │   └── sources.ts      # ndaze sources list|add|remove
│           └── format.ts           # Output formatting (table, json, etc.)
│
├── data/
│   └── ndaze.db                    # SQLite database (gitignored)
└── .gitignore
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

### Phase 1 — Core Library Foundation
- [ ] Monorepo scaffolding: Bun workspaces, `packages/core`, `packages/cli`, shared tsconfig
- [ ] Shared types: `CveRecord`, `ScoredCve`, `SourceAdapter` interface, config schema
- [ ] Storage layer: interfaces (`CveStore`, `ScoreStore`, etc.) + SQLite implementation + schema migrations
- [ ] Rate-limited HTTP client utility
- [ ] Event emitter for inter-component communication
- [ ] **Discovery component**: adapter interface, adapter registry, sync orchestrator
- [ ] First adapters: NVD + CISA KEV (proves the adapter model works end-to-end)
- [ ] `Ndaze` facade class: wires Discovery + Storage, exposes top-level API
- [ ] Thin CLI: `ndaze sync`, `ndaze list` — just calls the library

### Phase 2 — Ranking Component
- [ ] CVSS v3/v4 vector parser
- [ ] EPSS adapter (ingests into Discovery, feeds into Ranking)
- [ ] **Ranking component**: composite scoring engine with configurable weights
- [ ] Heuristic rules (recency, patch availability, CWE bonuses)
- [ ] Library API: `ranking.top(n)`, `ranking.score(cveId)`, `ranking.filter(opts)`
- [ ] CLI: `ndaze top`, `ndaze search <query>`, filtering flags

### Phase 3 — Research Component + More Adapters
- [ ] **Research component**: enrichment, cross-source correlation, deduplication
- [ ] New adapters: OSV, GHSA, Exploit-DB, Linux kernel security
- [ ] Adapters register through the registry — no code changes to Discovery needed
- [ ] Cross-reference deduplication (same CVE from multiple sources)
- [ ] Related CVE linking, CWE categorization, patch status tracking
- [ ] Nuclei template existence check as enrichment signal

### Phase 4 — Development Component
- [ ] **Development component**: PoC workspace scaffolding + status tracking
- [ ] `ndaze exploit init <CVE-ID>` — scaffolds workspace from CVE metadata via library
- [ ] Auto-populates: advisory text, affected versions, references, patches, related CVEs
- [ ] Status lifecycle: proposed → research → wip → done → abandoned
- [ ] `ndaze exploit list` — query tracked exploits through library API

### Phase 5 — Automation, Monitoring & Service Extraction
- [ ] Scheduled crawls via Discovery component (configurable per-source intervals)
- [ ] Watch lists (track specific products/vendors, boost their scores)
- [ ] Notifications on new high-priority CVEs (event-driven, webhook or stdout)
- [ ] Optional TUI dashboard (using `ink`)
- [ ] Documentation for extracting components into standalone services
- [ ] Example: Discovery as a standalone service with HTTP API + message queue output

---

## Source Adapter Plugin Model

Adding a new data source requires **one file** and **one registration call** — no modifications to existing code.

```typescript
// 1. Implement the SourceAdapter interface
import { SourceAdapter, CveRecord, SyncCursor } from "@ndaze/core";

export class MyNewSourceAdapter implements SourceAdapter {
  name = "my-source";

  // How often to crawl (optional, defaults to global config)
  defaultInterval = "6h";

  async *fetch(cursor?: SyncCursor): AsyncGenerator<CveRecord> {
    // Fetch from API/feed, yield normalized CveRecords
    // The cursor lets you resume from where you left off
  }
}

// 2. Register it
import { Ndaze } from "@ndaze/core";

const ndaze = new Ndaze();
ndaze.discovery.registerAdapter("my-source", new MyNewSourceAdapter());
// That's it. `ndaze sync` will now include this source.
```

The `SourceAdapter` interface:

```typescript
interface SourceAdapter {
  /** Unique name for this source */
  name: string;

  /** Default crawl interval (cron string or duration like "6h") */
  defaultInterval?: string;

  /** Fetch CVEs, optionally resuming from a cursor. Yields normalized records. */
  fetch(cursor?: SyncCursor): AsyncGenerator<CveRecord>;

  /** Optional: validate configuration (API keys, etc.) */
  validate?(): Promise<{ ok: boolean; error?: string }>;
}
```

---

## Key Design Decisions to Confirm

1. **Bun vs Node** — Plan uses Bun for speed and built-in SQLite. Fallback to Node + better-sqlite3 if needed.
2. **SQLite vs Postgres** — Starting with SQLite for zero-config. Storage abstraction makes Postgres migration straightforward later.
3. **Library-first** — `@ndaze/core` is the product. CLI is a thin consumer. Other consumers (web API, bots, scripts) can import the library directly.
4. **Component boundaries = future service boundaries** — Discovery, Ranking, Research, Development communicate through interfaces, not direct imports. This is the seam where you split into services.
5. **Adapter registry pattern** — New sources are added by implementing `SourceAdapter` and calling `registerAdapter()`. No modification to existing code required.
6. **NVD API key** — Optional but recommended. Free to request at https://nvd.nist.gov/developers/request-an-api-key. We'll support both keyed and unkeyed modes.
