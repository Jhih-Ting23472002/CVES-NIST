/**
 * OSV.dev API 介面定義
 * 文件: https://osv.dev/docs/
 */

export interface OsvQueryRequest {
  package: {
    name: string;
    ecosystem: string;
  };
  version?: string;
}

export interface OsvBatchQueryRequest {
  queries: OsvQueryRequest[];
}

export interface OsvBatchQueryResponse {
  results: OsvBatchResult[];
}

export interface OsvBatchResult {
  vulns?: OsvVulnerability[];
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified: string;
  published?: string;
  withdrawn?: string;
  related?: string[];
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: OsvReference[];
  database_specific?: Record<string, unknown>;
}

export interface OsvSeverity {
  type: 'CVSS_V3' | 'CVSS_V2' | string;
  score: string; // CVSS 向量字串，如 "CVSS:3.1/AV:N/AC:L/..."
}

export interface OsvAffected {
  package: {
    name: string;
    ecosystem: string;
    purl?: string;
  };
  ranges?: OsvRange[];
  versions?: string[];
  ecosystem_specific?: Record<string, unknown>;
  database_specific?: Record<string, unknown>;
}

export interface OsvRange {
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
  events: OsvEvent[];
  repo?: string;
}

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvReference {
  type: 'ADVISORY' | 'ARTICLE' | 'REPORT' | 'FIX' | 'PACKAGE' | 'EVIDENCE' | 'WEB' | string;
  url: string;
}
