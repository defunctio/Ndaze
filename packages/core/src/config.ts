import { resolve } from "path";

export interface NdazeConfig {
  /** Path to the SQLite database file */
  dbPath: string;

  /** NVD API key (optional, increases rate limit from 5/30s to 50/30s) */
  nvdApiKey?: string;

  /** GitHub token for GHSA GraphQL API */
  githubToken?: string;

  /** Default crawl interval for sources without their own override */
  defaultCrawlInterval: string;

  /** Directory where exploit workspaces are created */
  workspaceDir: string;

  /** Scoring weights — must sum to 1.0 */
  scoring: ScoringWeights;
}

export interface ScoringWeights {
  cvss: number;
  epss: number;
  cisaKev: number;
  publicPoc: number;
  recency: number;
  patchUnavailable: number;
}

const DEFAULT_SCORING: ScoringWeights = {
  cvss: 0.25,
  epss: 0.25,
  cisaKev: 0.2,
  publicPoc: 0.15,
  recency: 0.1,
  patchUnavailable: 0.05,
};

export function defaultConfig(overrides?: Partial<NdazeConfig>): NdazeConfig {
  return {
    dbPath: resolve(process.cwd(), "data", "ndaze.db"),
    defaultCrawlInterval: "6h",
    workspaceDir: resolve(process.cwd(), "workspaces"),
    scoring: DEFAULT_SCORING,
    ...overrides,
  };
}
