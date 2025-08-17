/**
 * 優化儲存格式介面定義
 * 用於更有效率地處理 CVE 物件的產品名稱和版本範圍提取
 */

// 優化的 CVE 記錄格式
export interface OptimizedCveRecord extends Omit<CveRecord, 'versionRanges' | 'affectedProducts'> {
  // 優化的產品資訊
  optimizedProductInfo: OptimizedProductInfo[];
  
  // 資料來源標記
  dataExtractionMethods: DataExtractionMethod[];
  
  // 處理時間戳
  processingTimestamp: number;
}

// 優化的產品資訊
export interface OptimizedProductInfo {
  // 產品識別
  productName: string; // 標準化的產品名稱
  vendor?: string; // 廠商名稱
  ecosystem: string; // 生態系統 (npm, pypi, etc.)
  
  // 版本範圍資訊
  versionRanges: OptimizedVersionRange[];
  
  // CPE 資訊（如果來自結構化資料）
  cpeInfo?: CpeExtractedInfo;
  
  // 描述提取資訊（如果來自非結構化描述）
  descriptionInfo?: DescriptionExtractedInfo;
  
  // 信心分數 (0.0 - 1.0)
  confidenceScore: number;
  
  // 別名和變體
  aliases: string[]; // 產品名稱的其他變體
}

// 優化的版本範圍
export interface OptimizedVersionRange {
  // 版本約束
  versionConstraints: VersionConstraint[];
  
  // 原始 CPE 名稱（如果來自結構化資料）
  originalCpeName?: string;
  
  // 是否為易受攻擊的版本
  vulnerable: boolean;
  
  // 提取來源
  source: 'cpe_configuration' | 'description_parsing';
}

// 版本約束
export interface VersionConstraint {
  type: 'lt' | 'lte' | 'gt' | 'gte' | 'eq' | 'range';
  version: string;
  // 對於 range 類型
  endVersion?: string;
  includeStart?: boolean;
  includeEnd?: boolean;
}

// 從 CPE 提取的資訊
export interface CpeExtractedInfo {
  cpeName: string;
  vendor: string;
  product: string;
  version?: string;
  update?: string;
  edition?: string;
  language?: string;
}

// 從描述提取的資訊
export interface DescriptionExtractedInfo {
  // 原始描述文字片段
  sourceText: string;
  
  // 提取的產品名稱（原始形式）
  extractedProductName: string;
  
  // 提取的版本範圍文字
  extractedVersionText: string;
  
  // 使用的正則表達式模式
  regexPattern: string;
  
  // 語言
  language: string; // 'en', 'zh', etc.
}

// 資料提取方法記錄
export interface DataExtractionMethod {
  method: 'structured_cpe' | 'description_regex' | 'fallback_analysis';
  success: boolean;
  extractedProductCount: number;
  confidenceLevel: 'high' | 'medium' | 'low';
  notes?: string;
}

// Web Worker 優化訊息類型
export interface OptimizationWorkerMessage {
  type: 'optimizeStorageFormat' | 'batchOptimizeRecords';
  data?: {
    cveRecords?: CveRecord[];
    batchSize?: number;
    enableDescriptionParsing?: boolean;
  };
  requestId?: string;
}

export interface OptimizationWorkerResponse {
  type: 'progress' | 'complete' | 'error' | 'optimized_record';
  data?: {
    optimizedRecords?: OptimizedCveRecord[];
    progress?: {
      processed: number;
      total: number;
      currentCveId?: string;
      phase: 'cpe_extraction' | 'description_parsing' | 'optimization' | 'complete';
    };
  };
  requestId?: string;
  error?: string;
}

// 產品名稱正規化配置
export interface ProductNormalizationConfig {
  // 通用清理規則
  commonCleanupPatterns: RegExp[];
  
  // 生態系統特定規則
  ecosystemRules: {
    [ecosystem: string]: {
      suffixesToRemove: string[];
      prefixesToRemove: string[];
      nameVariations: { [key: string]: string[] };
    };
  };
  
  // 已知產品映射
  knownProductMappings: {
    [cpeProduct: string]: {
      standardName: string;
      ecosystem: string;
      aliases: string[];
    };
  };
}

// 版本範圍解析配置
export interface VersionRangeParsingConfig {
  // 描述文字中的版本範圍模式
  versionRangePatterns: {
    // 基本模式：影響的套件和版本
    affectsPackagePattern: RegExp;
    
    // 版本約束模式
    versionConstraintPatterns: {
      lessThan: RegExp;
      lessThanOrEqual: RegExp;
      greaterThan: RegExp;
      greaterThanOrEqual: RegExp;
      range: RegExp;
      exactVersion: RegExp;
    };
    
    // 套件名稱模式
    packageNamePatterns: RegExp[];
  };
  
  // 信心分數權重
  confidenceWeights: {
    cpeStructuredData: number;
    descriptionDirectMatch: number;
    descriptionFuzzyMatch: number;
    fallbackGuess: number;
  };
}

// 引入原始介面
import { CveRecord } from './nvd-database.interface';