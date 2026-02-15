/** Severity levels aligned with CVSS qualitative ratings */
export type Severity = "none" | "low" | "medium" | "high" | "critical";

/** Exploit development lifecycle status */
export type ExploitStatus =
  | "proposed"
  | "research"
  | "wip"
  | "done"
  | "abandoned";

/** Normalized CVE record — the canonical shape all adapters produce */
export interface CveRecord {
  cveId: string;
  summary: string;
  description?: string;
  publishedAt: string; // ISO 8601
  modifiedAt?: string;
  cvssV3Score?: number;
  cvssV3Vector?: string;
  cvssV4Score?: number;
  cvssV4Vector?: string;
  cweIds: string[];
  affectedProducts: string[]; // CPE strings
  references: string[];
  rawData?: unknown;
}

/** CVE with composite priority score attached */
export interface ScoredCve {
  cve: CveRecord;
  compositeScore: number; // 0–100
  breakdown: ScoreBreakdown;
  scoredAt: string;
}

/** Individual scoring signals that feed the composite score */
export interface ScoreBreakdown {
  cvssWeight: number;
  epssScore?: number;
  epssPercentile?: number;
  inCisaKev: boolean;
  hasPublicPoc: boolean;
  patchAvailable: boolean;
  recencyBonus: number;
}

/** Enriched CVE with research metadata */
export interface EnrichedCve {
  cve: CveRecord;
  sources: CveSource[];
  relatedCveIds: string[];
  cweCategories: string[];
  patchUrls: string[];
  nucleiTemplateExists: boolean;
}

/** Tracks which source reported a CVE */
export interface CveSource {
  cveId: string;
  sourceName: string;
  sourceId?: string;
  fetchedAt: string;
}

/** Exploit PoC tracking record */
export interface Exploit {
  id: number;
  cveId: string;
  status: ExploitStatus;
  notes?: string;
  workspace?: string;
  createdAt: string;
  updatedAt: string;
}

/** Workspace scaffolded for exploit development */
export interface Workspace {
  cveId: string;
  path: string;
  createdAt: string;
}

/** Per-source crawl state for resumable syncing */
export interface SyncState {
  sourceName: string;
  lastCursor?: string;
  lastRunAt?: string;
  status: "idle" | "running" | "error";
}

/** Opaque cursor for resumable fetching */
export type SyncCursor = string;

/** Options for querying CVEs */
export interface QueryOpts {
  cweIds?: string[];
  products?: string[];
  since?: string;
  until?: string;
  minCvss?: number;
  limit?: number;
  offset?: number;
  search?: string;
}

/** Options for filtering scored CVEs */
export interface FilterOpts extends QueryOpts {
  minScore?: number;
}

/** Options for filtering exploits */
export interface ExploitFilter {
  status?: ExploitStatus;
  cveId?: string;
  limit?: number;
  offset?: number;
}

/** Deduplication result */
export interface DedupeResult {
  merged: number;
  conflicts: Array<{ cveId: string; sources: string[] }>;
}

/** Severity from a CVSS score */
export function severityFromCvss(score: number): Severity {
  if (score === 0) return "none";
  if (score < 4) return "low";
  if (score < 7) return "medium";
  if (score < 9) return "high";
  return "critical";
}
