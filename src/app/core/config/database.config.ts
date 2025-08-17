/**
 * 資料庫配置
 */

export interface DatabaseConfig {
  /** 下載年限（年） */
  downloadYearsRange: number;
  
  /** 資料清理配置 */
  dataCleanup: {
    /** 啟用自動清理 */
    enableAutoCleanup: boolean;
    /** 保留年限（年） */
    retentionYears: number;
    /** 清理間隔（小時） */
    cleanupIntervalHours: number;
  };
  
  /** 同步配置 */
  sync: {
    /** 自動同步間隔（小時） */
    autoSyncIntervalHours: number;
    /** 最大重試次數 */
    maxRetryAttempts: number;
    /** 重試延遲（毫秒） */
    retryDelayMs: number;
  };
  
  /** 效能配置 */
  performance: {
    /** 批次大小 */
    batchSize: number;
    /** 最大並行下載數 */
    maxConcurrentDownloads: number;
    /** 下載間隔（毫秒） */
    downloadIntervalMs: number;
  };
}

/**
 * 預設資料庫配置
 */
export const DEFAULT_DATABASE_CONFIG: DatabaseConfig = {
  downloadYearsRange: 6, // 預設下載近六年資料
  
  dataCleanup: {
    enableAutoCleanup: true,
    retentionYears: 6, // 保留六年資料
    cleanupIntervalHours: 24, // 每24小時檢查一次
  },
  
  sync: {
    autoSyncIntervalHours: 24, // 每24小時自動同步
    maxRetryAttempts: 3,
    retryDelayMs: 5000, // 5秒
  },
  
  performance: {
    batchSize: 1000,
    maxConcurrentDownloads: 2,
    downloadIntervalMs: 1000, // 1秒間隔
  }
};

/**
 * 環境變數覆蓋配置
 * 允許透過環境變數或本地儲存覆蓋預設配置
 */
export function getDatabaseConfig(): DatabaseConfig {
  const config = { ...DEFAULT_DATABASE_CONFIG };
  
  // 從環境變數讀取配置（如果存在）
  if (typeof window !== 'undefined') {
    // 瀏覽器環境 - 從 localStorage 讀取
    const localConfig = localStorage.getItem('database_config');
    if (localConfig) {
      try {
        const parsedConfig = JSON.parse(localConfig);
        Object.assign(config, parsedConfig);
      } catch (error) {
        console.warn('解析本地資料庫配置失敗:', error);
      }
    }
    
    // 從 URL 參數讀取（用於測試）
    const urlParams = new URLSearchParams(window.location.search);
    const downloadYears = urlParams.get('downloadYears');
    if (downloadYears && !isNaN(Number(downloadYears))) {
      config.downloadYearsRange = Number(downloadYears);
      config.dataCleanup.retentionYears = Number(downloadYears);
    }
  }
  
  return config;
}

/**
 * 儲存資料庫配置到本地儲存
 */
export function saveDatabaseConfig(config: Partial<DatabaseConfig>): void {
  if (typeof window !== 'undefined') {
    const currentConfig = getDatabaseConfig();
    const updatedConfig = { ...currentConfig, ...config };
    localStorage.setItem('database_config', JSON.stringify(updatedConfig));
  }
}

/**
 * 重置為預設配置
 */
export function resetDatabaseConfig(): void {
  if (typeof window !== 'undefined') {
    localStorage.removeItem('database_config');
  }
}

/**
 * 取得年份清單（根據配置的年限）
 */
export function getYearsList(config?: DatabaseConfig): number[] {
  const dbConfig = config || getDatabaseConfig();
  const currentYear = new Date().getFullYear();
  const years: number[] = [];
  
  for (let i = 0; i < dbConfig.downloadYearsRange; i++) {
    years.push(currentYear - i);
  }
  
  return years.sort((a, b) => b - a); // 降序排列
}

/**
 * 檢查年份是否在配置範圍內
 */
export function isYearInRange(year: number, config?: DatabaseConfig): boolean {
  const dbConfig = config || getDatabaseConfig();
  const currentYear = new Date().getFullYear();
  const minYear = currentYear - dbConfig.downloadYearsRange + 1;
  
  return year >= minYear && year <= currentYear;
}

/**
 * 取得需要清理的年份清單
 */
export function getYearsToCleanup(config?: DatabaseConfig): number[] {
  const dbConfig = config || getDatabaseConfig();
  if (!dbConfig.dataCleanup.enableAutoCleanup) {
    return [];
  }
  
  const currentYear = new Date().getFullYear();
  const cutoffYear = currentYear - dbConfig.dataCleanup.retentionYears;
  const yearsToCleanup: number[] = [];
  
  // 假設最早可能的年份是 2000 年
  for (let year = 2000; year < cutoffYear; year++) {
    yearsToCleanup.push(year);
  }
  
  return yearsToCleanup;
}