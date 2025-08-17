/**
 * NVD 本地資料庫相關介面定義
 */

// IndexedDB 資料庫結構
export interface NvdDatabaseSchema {
  cve: CveRecord;
  cpe: CpeRecord;
  metadata: MetadataRecord;
}

// CVE 記錄（NVD 2.0 優化版）
export interface CveRecord {
  id: string; // CVE-ID 作為主鍵
  published: string;
  lastModified: string;
  descriptions: CveDescription[];
  metrics?: CveMetrics;
  configurations: CveConfiguration[];
  references: CveReference[];
  
  // 搜尋索引欄位
  keywordSearchText: string; // 合併描述、產品名稱等的搜尋文本
  affectedProducts: string[]; // 受影響產品名稱列表
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  cvssScore: number;
  
  // 版本範圍資訊（預處理）
  versionRanges: VersionRange[];
  
  // NVD 2.0 特有欄位
  sourceIdentifier?: string; // CVE 來源標識符
  vulnStatus?: string; // 漏洞狀態 (Analyzed, Awaiting Analysis, etc.)
  weaknesses?: CveWeakness[]; // CWE 分類
  cveTags?: string[]; // CVE 標籤
  
  // 效能優化欄位（扁平化存取）
  primaryCvssVector?: string; // 主要 CVSS 向量（快速存取）
  cpeMatchCount: number; // CPE 匹配數量（用於排序和篩選）
  referenceCount: number; // 參考連結數量
  
  // 搜尋優化欄位
  vendorProducts: string[]; // 廠商-產品組合 ["vendor:product"]
  ecosystems: string[]; // 相關生態系統列表
  
  // 版本管理欄位
  dataVersion: string; // 資料版本標記 (格式: YYYY-MM-DD 或 incremental-YYYY-MM-DD)
  publishedYear: number; // 發布年份，用於快速篩選
  syncTimestamp: number; // 同步時間戳，用於清理舊資料
}

// CPE 記錄
export interface CpeRecord {
  cpeName: string; // 主鍵
  title: string;
  deprecated: boolean;
  lastModified: string;
  
  // 搜尋索引欄位
  vendor: string;
  product: string;
  version?: string;
  update?: string;
  edition?: string;
  language?: string;
  
  // 對應的套件名稱（預處理）
  mappedPackageNames: string[];
  
  // 版本管理欄位
  dataVersion: string; // 資料版本標記
  syncTimestamp: number; // 同步時間戳
}

// 版本範圍資訊
export interface VersionRange {
  cpeName: string;
  vulnerable: boolean;
  vendor: string; // 從 CPE 解析的廠商名稱
  product: string; // 從 CPE 解析的產品名稱
  ecosystem: string; // 生態系統 (npm, pypi, etc.)
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

// CVE 描述
export interface CveDescription {
  lang: string;
  value: string;
}

// CVE 指標
export interface CveMetrics {
  cvssMetricV31?: CvssMetric[];
  cvssMetricV30?: CvssMetric[];
  cvssMetricV2?: CvssMetric[];
}

// CVSS 指標
export interface CvssMetric {
  source: string;
  type: string;
  cvssData: CvssData;
}

// CVSS 資料
export interface CvssData {
  version: string;
  vectorString: string;
  baseScore: number;
  baseSeverity: string;
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
  scope?: string;
  confidentialityImpact?: string;
  integrityImpact?: string;
  availabilityImpact?: string;
}

// CVE 設定
export interface CveConfiguration {
  nodes: CveConfigurationNode[];
}

// CVE 設定節點
export interface CveConfigurationNode {
  operator: string;
  negate: boolean;
  cpeMatch: CpeCriterion[];
}

// CPE 符合條件
export interface CpeCriterion {
  vulnerable: boolean;
  criteria: string;
  matchCriteriaId: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

// CVE 參考
export interface CveReference {
  url: string;
  source?: string;
  tags?: string[];
}

// CVE 弱點分類（NVD 2.0 新增）
export interface CveWeakness {
  source: string;
  type: string; // Primary, Secondary
  description: CveDescription[];
}

// 元資料記錄（追蹤資料庫狀態）
export interface MetadataRecord {
  key: string; // 主鍵，如 'last_sync', 'version', 'years_downloaded'
  value: string;
  updatedAt: string;
}

// 資料庫版本資訊
export interface DatabaseVersion {
  version: number;
  lastSync: string;
  dataYears: number[]; // 已下載的年份
  totalCveCount: number;
  totalCpeCount: number;
}

// 套件查詢結果
export interface PackageVulnerabilityQuery {
  packageName: string;
  version?: string;
  searchType: 'exact' | 'fuzzy' | 'cpe';
}

// 查詢結果
export interface VulnerabilityQueryResult {
  cveId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  cvssScore: number;
  cvssVector?: string; // CVSS 向量字串
  description: string;
  publishedDate: string;
  lastModifiedDate: string;
  references: string[];
  affectedVersions: string[];
  fixedVersion?: string;
  matchReason: string; // 說明為什麼匹配到這個 CVE
  vendor?: string; // 廠商名稱
  product?: string; // 產品名稱
  ecosystem?: string; // 生態系統
}

// 批次處理進度
export interface BatchProcessProgress {
  type: 'download' | 'parse' | 'store';
  currentFile?: string;
  processed: number;
  total: number;
  percentage: number;
  message: string;
  startTime: Date;
  estimatedRemaining?: number; // 毫秒
}

// NVD 資料年度檔案資訊
export interface NvdDataFile {
  year: number;
  url: string;
  expectedSize: number; // 預期檔案大小（位元組）
  lastModified?: string;
  isIncremental: boolean; // 是否為增量更新檔案
}

// 增量更新資訊
export interface IncrementalUpdate {
  type: 'modified' | 'recent';
  url: string;
  lastSync: string;
  itemsUpdated: number;
  itemsAdded: number;
  itemsRemoved: number;
}