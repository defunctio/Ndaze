import type {
  CveRecord,
  CveSource,
  Exploit,
  ExploitFilter,
  ExploitStatus,
  QueryOpts,
  ScoreBreakdown,
  ScoredCve,
  SyncState,
} from "../types.js";

export interface CveStore {
  upsert(record: CveRecord): Promise<void>;
  get(cveId: string): Promise<CveRecord | null>;
  query(opts: QueryOpts): Promise<CveRecord[]>;
  count(opts?: QueryOpts): Promise<number>;
}

export interface CveSourceStore {
  upsert(source: CveSource): Promise<void>;
  getForCve(cveId: string): Promise<CveSource[]>;
}

export interface ScoreStore {
  upsert(cveId: string, compositeScore: number, breakdown: ScoreBreakdown): Promise<void>;
  get(cveId: string): Promise<ScoredCve | null>;
  top(limit: number, minScore?: number): Promise<ScoredCve[]>;
}

export interface ExploitStore {
  create(cveId: string): Promise<Exploit>;
  updateStatus(id: number, status: ExploitStatus, notes?: string): Promise<void>;
  setWorkspace(id: number, workspace: string): Promise<void>;
  get(id: number): Promise<Exploit | null>;
  getByCve(cveId: string): Promise<Exploit[]>;
  list(filter?: ExploitFilter): Promise<Exploit[]>;
}

export interface SyncStateStore {
  get(sourceName: string): Promise<SyncState | null>;
  upsert(state: SyncState): Promise<void>;
  getAll(): Promise<SyncState[]>;
}

/** Composite storage interface that components depend on */
export interface Storage {
  cves: CveStore;
  cveSources: CveSourceStore;
  scores: ScoreStore;
  exploits: ExploitStore;
  syncState: SyncStateStore;
  close(): void;
}
