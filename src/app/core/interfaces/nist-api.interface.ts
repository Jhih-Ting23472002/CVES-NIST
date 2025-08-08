export interface NistApiResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  vulnerabilities: NistVulnerabilityItem[];
}

export interface NistVulnerabilityItem {
  cve: {
    id: string;
    sourceIdentifier: string;
    published: string;
    lastModified: string;
    vulnStatus: string;
    descriptions: NistDescription[];
    metrics?: {
      cvssMetricV31?: NistCvssV31[];
      cvssMetricV30?: NistCvssV30[];
      cvssMetricV2?: NistCvssV2[];
    };
    weaknesses: NistWeakness[];
    configurations: NistConfiguration[];
    references: NistReference[];
  };
}

export interface NistDescription {
  lang: string;
  value: string;
}

export interface NistCvssV31 {
  source: string;
  type: "Primary" | "Secondary";
  cvssData: {
    version: "3.1";
    vectorString: string;
    attackVector: string;
    attackComplexity: string;
    privilegesRequired: string;
    userInteraction: string;
    scope: string;
    confidentialityImpact: string;
    integrityImpact: string;
    availabilityImpact: string;
    baseScore: number;
    baseSeverity: string;
  };
  exploitabilityScore?: number;
  impactScore?: number;
}

export interface NistCvssV30 {
  source: string;
  type: "Primary" | "Secondary";
  cvssData: {
    version: "3.0";
    vectorString: string;
    attackVector: string;
    attackComplexity: string;
    privilegesRequired: string;
    userInteraction: string;
    scope: string;
    confidentialityImpact: string;
    integrityImpact: string;
    availabilityImpact: string;
    baseScore: number;
    baseSeverity: string;
  };
}

export interface NistCvssV2 {
  source: string;
  type: "Primary" | "Secondary";
  cvssData: {
    version: "2.0";
    vectorString: string;
    accessVector: string;
    accessComplexity: string;
    authentication: string;
    confidentialityImpact: string;
    integrityImpact: string;
    availabilityImpact: string;
    baseScore: number;
  };
}

export interface NistWeakness {
  source: string;
  type: string;
  description: NistDescription[];
}

export interface NistConfiguration {
  nodes: NistNode[];
}

export interface NistNode {
  operator: string;
  negate: boolean;
  cpeMatch: NistCpeMatch[];
}

export interface NistCpeMatch {
  vulnerable: boolean;
  criteria: string;
  matchCriteriaId: string;
  versionStartExcluding?: string;
  versionStartIncluding?: string;
  versionEndExcluding?: string;
  versionEndIncluding?: string;
}

export interface NistReference {
  url: string;
  source: string;
  tags?: string[];
}

export interface NistApiParams {
  keywordSearch?: string;
  cveId?: string;
  cpeName?: string;
  pubStartDate?: string;
  pubEndDate?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;
  cvssV3Severity?: string;
  cvssV3Metrics?: string;
  resultsPerPage?: number;
  startIndex?: number;
  noRejected?: boolean;
}


export interface RateLimitInfo {
  requestsRemaining: number;
  resetTime: Date;
  requestsMade: number;
  maxRequests: number;
  timeWindow: number;
}

// CPE API 相關介面
export interface CpeApiResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  products: CpeItem[];
}

export interface CpeItem {
  cpe: {
    cpeName: string;
    cpeNameId: string;
    lastModified: string;
    created: string;
    titles: CpeTitle[];
    refs: CpeReference[];
  };
}

export interface CpeTitle {
  title: string;
  lang: string;
}

export interface CpeReference {
  ref: string;
  type?: string;
}

export interface CpeApiParams {
  keywordSearch?: string;
  cpeMatchString?: string;
  matchCriteriaId?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;
  resultsPerPage?: number;
  startIndex?: number;
}