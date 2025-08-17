/**
 * 效能優化配置
 */

export const PERFORMANCE_CONFIG = {
  // 並行掃描配置
  parallelScan: {
    batchSize: 8,                    // 並行批次大小
    maxConcurrency: 16,              // 最大並行數量
    batchProcessingDelay: 10,        // 批次間的延遲（毫秒）
  },

  // 快取配置
  cache: {
    scanResultsTtl: 10 * 60 * 1000,  // 掃描結果快取 TTL：10分鐘
    queryResultsTtl: 5 * 60 * 1000,  // 查詢結果快取 TTL：5分鐘
    maxScanCacheSize: 1000,          // 掃描快取最大容量
    maxQueryCacheSize: 500,          // 查詢快取最大容量
    cleanupThreshold: 0.8,           // 清理閾值（當快取使用率超過80%時觸發清理）
  },

  // 資料庫查詢優化
  database: {
    enableBatchQuery: true,          // 啟用批次查詢
    batchQuerySize: 10,              // 批次查詢大小
    cursorBatchSize: 100,            // 游標批次大小
    enableIndexHints: true,          // 啟用索引提示
    optimizedRecordCheckInterval: 50, // 優化記錄檢查間隔
  },

  // 版本比較優化
  versionComparison: {
    enableCaching: true,             // 啟用版本比較快取
    cacheSize: 200,                  // 版本比較快取大小
    cacheTtl: 30 * 60 * 1000,       // 版本比較快取 TTL：30分鐘
  },

  // 記憶體使用優化
  memory: {
    enableGarbageCollection: true,   // 啟用垃圾收集提示
    gcInterval: 60 * 1000,          // 垃圾收集間隔：1分鐘
    maxMemoryUsage: 512 * 1024 * 1024, // 最大記憶體使用：512MB
  },

  // 效能監控
  monitoring: {
    enableProfiling: false,         // 啟用效能分析（開發環境使用）
    logSlowQueries: true,           // 記錄慢查詢
    slowQueryThreshold: 1000,       // 慢查詢閾值：1秒
    enableMetrics: true,            // 啟用效能指標收集
  }
};

// 預設的效能優化選項
export const DEFAULT_OPTIMIZATION_OPTIONS = {
  enableParallelScan: true,
  enableResultCaching: true,
  enableBatchQuery: true,
  enableVersionCache: true,
  enableMemoryOptimization: true,
};

// 效能級別配置
export const PERFORMANCE_LEVELS = {
  // 效能優先（適合高階裝置）
  HIGH_PERFORMANCE: {
    ...DEFAULT_OPTIMIZATION_OPTIONS,
    parallelScan: {
      batchSize: 12,
      maxConcurrency: 24,
      batchProcessingDelay: 5,
    },
    cache: {
      scanResultsTtl: 15 * 60 * 1000,
      queryResultsTtl: 10 * 60 * 1000,
      maxScanCacheSize: 2000,
      maxQueryCacheSize: 1000,
    }
  },

  // 平衡模式（預設）
  BALANCED: {
    ...DEFAULT_OPTIMIZATION_OPTIONS,
    parallelScan: PERFORMANCE_CONFIG.parallelScan,
    cache: PERFORMANCE_CONFIG.cache,
  },

  // 記憶體優先（適合低階裝置）
  MEMORY_OPTIMIZED: {
    ...DEFAULT_OPTIMIZATION_OPTIONS,
    enableParallelScan: false, // 關閉並行掃描節省記憶體
    parallelScan: {
      batchSize: 4,
      maxConcurrency: 4,
      batchProcessingDelay: 50,
    },
    cache: {
      scanResultsTtl: 5 * 60 * 1000,
      queryResultsTtl: 3 * 60 * 1000,
      maxScanCacheSize: 300,
      maxQueryCacheSize: 150,
    }
  }
};

// 動態效能調整配置
export const ADAPTIVE_PERFORMANCE_CONFIG = {
  // 裝置效能檢測閾值
  deviceDetection: {
    memoryThreshold: 4 * 1024 * 1024 * 1024, // 4GB
    concurrentWorkerThreshold: 8,             // 支援的最大 Worker 數量
    idbTransactionThreshold: 100,             // IndexedDB 事務處理能力
  },

  // 自動降級策略
  degradationStrategy: {
    enableAutoDegrade: true,
    memoryPressureThreshold: 0.8,    // 記憶體壓力閾值
    performanceScoreThreshold: 0.6,   // 效能分數閾值
    degradeSteps: [
      'disableParallelScan',
      'reduceCacheSize',
      'disableVersionCache',
      'enableMemoryMode'
    ]
  }
};