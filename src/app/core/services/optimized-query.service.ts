import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { OptimizedCveRecord } from '../interfaces/optimized-storage.interface';
import {
  PackageVulnerabilityQuery,
  VulnerabilityQueryResult
} from '../interfaces/nvd-database.interface';
import { compareVersions } from '../../shared/utils/version-utils';

@Injectable({
  providedIn: 'root'
})
export class OptimizedQueryService {
  private readonly DB_NAME = 'NvdLocalDatabase';
  private readonly CVE_STORE = 'cve';
  private db: IDBDatabase | null = null;

  // 批次查詢快取
  private readonly batchQueryCache = new Map<string, VulnerabilityQueryResult[]>();
  private readonly cacheExpiry = 5 * 60 * 1000; // 5 分鐘
  private readonly cacheTimestamps = new Map<string, number>();

  constructor() {
    this.initDatabase();
  }

  /**
   * 初始化資料庫連線
   */
  private async initDatabase(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.DB_NAME);
      
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };
      
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * 批次查詢多個套件漏洞（優化版本）
   */
  batchQueryPackageVulnerabilities(queries: PackageVulnerabilityQuery[]): Observable<Map<string, VulnerabilityQueryResult[]>> {
    return new Observable(observer => {
      const executeQueries = async () => {
        try {
          if (!this.db) {
            await this.initDatabase();
          }

          if (!this.db) {
            observer.error(new Error('資料庫尚未準備好'));
            return;
          }

          const results = new Map<string, VulnerabilityQueryResult[]>();
          const cacheHits = new Set<string>();
          const cacheMisses: PackageVulnerabilityQuery[] = [];

          // 檢查快取
          for (const query of queries) {
            const cacheKey = `${query.packageName}@${query.version || 'latest'}:${query.searchType}`;
            if (this.isBatchCacheValid(cacheKey)) {
              const cachedResult = this.batchQueryCache.get(cacheKey);
              if (cachedResult) {
                results.set(cacheKey, cachedResult);
                cacheHits.add(cacheKey);
              }
            } else {
              cacheMisses.push(query);
            }
          }

          console.log(`[OptimizedQuery] 批次查詢：${cacheHits.size} 個快取命中，${cacheMisses.length} 個需要查詢`);

          // 如果所有查詢都有快取，直接返回
          if (cacheMisses.length === 0) {
            observer.next(results);
            observer.complete();
            return;
          }

          // 執行未快取的查詢
          await this.executeBatchQueries(cacheMisses, results);
          
          observer.next(results);
          observer.complete();

        } catch (error) {
          observer.error(error);
        }
      };

      executeQueries();
    });
  }

  /**
   * 執行批次查詢
   */
  private async executeBatchQueries(
    queries: PackageVulnerabilityQuery[], 
    results: Map<string, VulnerabilityQueryResult[]>
  ): Promise<void> {
    if (!this.db) return;

    const transaction = this.db.transaction([this.CVE_STORE], 'readonly');
    const store = transaction.objectStore(this.CVE_STORE);
    
    return new Promise((resolve, reject) => {
      const queryResults = new Map<string, VulnerabilityQueryResult[]>();
      
      // 初始化所有查詢結果
      for (const query of queries) {
        const cacheKey = `${query.packageName}@${query.version || 'latest'}:${query.searchType}`;
        queryResults.set(cacheKey, []);
      }

      const request = store.openCursor();

      request.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        if (!cursor) {
          // 完成時更新快取和結果
          for (const [cacheKey, queryResult] of queryResults) {
            results.set(cacheKey, queryResult);
            this.updateBatchCache(cacheKey, queryResult);
          }
          resolve();
          return;
        }

        const record = cursor.value;
        
        // 對每個查詢檢查當前記錄
        for (const query of queries) {
          const cacheKey = `${query.packageName}@${query.version || 'latest'}:${query.searchType}`;
          const matchResults = this.checkRecordForQuery(record, query);
          
          if (matchResults.length > 0) {
            const existingResults = queryResults.get(cacheKey) || [];
            queryResults.set(cacheKey, [...existingResults, ...matchResults]);
          }
        }

        cursor.continue();
      };

      request.onerror = () => reject(request.error);
      transaction.onerror = () => reject(transaction.error);
    });
  }

  /**
   * 檢查記錄是否符合查詢條件
   */
  private checkRecordForQuery(record: any, query: PackageVulnerabilityQuery): VulnerabilityQueryResult[] {
    const results: VulnerabilityQueryResult[] = [];

    if (this.isOptimizedRecord(record)) {
      const optimizedRecord = record as OptimizedCveRecord;
      
      for (const productInfo of optimizedRecord.optimizedProductInfo) {
        let isMatch = false;
        let matchType = '';

        switch (query.searchType) {
          case 'exact':
            if (this.isProductMatch(productInfo, query.packageName, 'exact')) {
              isMatch = true;
              matchType = 'exact_match';
            }
            break;
          case 'fuzzy':
            if (this.isProductMatch(productInfo, query.packageName, 'fuzzy')) {
              isMatch = true;
              matchType = 'fuzzy_match';
            }
            break;
          case 'cpe':
            if (productInfo.cpeInfo && this.isCpeMatch(productInfo.cpeInfo.cpeName, query.packageName)) {
              isMatch = true;
              matchType = 'cpe_match';
            }
            break;
          default:
            // 綜合搜尋
            if (this.isProductMatch(productInfo, query.packageName, 'exact')) {
              isMatch = true;
              matchType = 'exact_match';
            } else if (productInfo.cpeInfo && this.isCpeMatch(productInfo.cpeInfo.cpeName, query.packageName)) {
              isMatch = true;
              matchType = 'cpe_match';
            } else if (this.isProductMatch(productInfo, query.packageName, 'fuzzy')) {
              isMatch = true;
              matchType = 'fuzzy_match';
            }
        }

        // 生態系統過濾：若查詢指定了 ecosystem，排除不同生態系統的結果
        if (isMatch && query.ecosystem && productInfo.ecosystem &&
            productInfo.ecosystem !== 'unknown' &&
            productInfo.ecosystem !== query.ecosystem) {
          isMatch = false;
        }

        if (isMatch && this.isVersionAffectedOptimized(productInfo, query.version)) {
          results.push(this.transformOptimizedCveToResult(optimizedRecord, productInfo, matchType));
        }
      }
    } else {
      // 處理舊格式記錄
      this.handleLegacyRecordForBatch(record, query, results);
    }

    return results;
  }

  /**
   * 處理舊格式記錄（批次版本）
   */
  private handleLegacyRecordForBatch(
    record: any, 
    query: PackageVulnerabilityQuery, 
    results: VulnerabilityQueryResult[]
  ): void {
    if (record.affectedProducts && 
        record.affectedProducts.includes(query.packageName)) {
      
      const description = record.descriptions?.find((d: any) => d.lang === 'en')?.value || '';
      const fixedVersion = this.extractFixedVersionFromLegacy(record);

      results.push({
        cveId: record.id,
        severity: record.severity,
        cvssScore: record.cvssScore,
        cvssVector: record.primaryCvssVector,
        description,
        publishedDate: record.published,
        lastModifiedDate: record.lastModified,
        references: record.references?.map((ref: any) => ref.url) || [],
        affectedVersions: [],
        fixedVersion,
        matchReason: `legacy_batch_${query.searchType}`
      });
    }
  }

  /**
   * 檢查批次快取是否有效
   */
  private isBatchCacheValid(cacheKey: string): boolean {
    if (!this.batchQueryCache.has(cacheKey)) return false;
    
    const timestamp = this.cacheTimestamps.get(cacheKey);
    if (!timestamp) return false;
    
    const now = Date.now();
    return (now - timestamp) < this.cacheExpiry;
  }

  /**
   * 更新批次查詢快取
   */
  private updateBatchCache(cacheKey: string, results: VulnerabilityQueryResult[]): void {
    this.batchQueryCache.set(cacheKey, results);
    this.cacheTimestamps.set(cacheKey, Date.now());
  }

  /**
   * 查詢套件漏洞（支援新的優化格式）
   */
  queryPackageVulnerabilitiesOptimized(query: PackageVulnerabilityQuery): Observable<VulnerabilityQueryResult[]> {
    return new Observable(observer => {
      const executeQuery = async () => {
        try {
          if (!this.db) {
            await this.initDatabase();
          }

          if (!this.db) {
            observer.error(new Error('資料庫尚未準備好'));
            return;
          }

          const transaction = this.db.transaction([this.CVE_STORE], 'readonly');
          const cveStore = transaction.objectStore(this.CVE_STORE);
          const results: VulnerabilityQueryResult[] = [];

          // 根據搜尋類型選擇策略
          switch (query.searchType) {
            case 'exact':
              this.performOptimizedExactSearch(cveStore, query, results, observer);
              break;
            case 'fuzzy':
              this.performOptimizedFuzzySearch(cveStore, query, results, observer);
              break;
            case 'cpe':
              this.performOptimizedCpeSearch(cveStore, query, results, observer);
              break;
            default:
              this.performOptimizedCombinedSearch(cveStore, query, results, observer);
          }

          transaction.onerror = () => observer.error(transaction.error);
        } catch (error) {
          observer.error(error);
        }
      };

      executeQuery();
    });
  }

  /**
   * 優化的精確搜尋
   */
  private performOptimizedExactSearch(
    store: IDBObjectStore,
    query: PackageVulnerabilityQuery,
    results: VulnerabilityQueryResult[],
    observer: any
  ): void {
    // 使用 affectedProducts multiEntry 索引進行精確查詢，避免全表掃描
    const searchKey = query.packageName.toLowerCase();
    let index: IDBIndex;
    try {
      index = store.index('affectedProducts');
    } catch {
      // 索引不存在時回退到全表掃描
      this.performFullScanSearch(store, query, results, observer, 'exact');
      return;
    }

    const request = index.openCursor(IDBKeyRange.only(searchKey));

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (!cursor) {
        // affectedProducts 索引可能未包含所有記錄（Worker 優化路徑不重建索引），
        // 即使已有部分結果，仍需全表掃描以補齊未被索引的記錄
        this.performFullScanSearch(store, query, results, observer, 'exact');
        return;
      }

      const record = cursor.value;

      if (this.isOptimizedRecord(record)) {
        const optimizedRecord = record as OptimizedCveRecord;

        for (const productInfo of optimizedRecord.optimizedProductInfo) {
          if (this.isProductMatch(productInfo, query.packageName, 'exact')) {
            // 生態系統過濾
            if (query.ecosystem && productInfo.ecosystem &&
                productInfo.ecosystem !== 'unknown' &&
                productInfo.ecosystem !== query.ecosystem) {
              continue;
            }
            if (this.isVersionAffectedOptimized(productInfo, query.version)) {
              results.push(this.transformOptimizedCveToResult(
                optimizedRecord,
                productInfo,
                'exact_match'
              ));
              break;
            }
          }
        }
      } else {
        this.handleLegacyRecord(record, query, results, 'exact_match');
      }

      cursor.continue();
    };

    request.onerror = () => observer.error(request.error);
  }

  /**
   * 全表掃描回退方法（索引不可用時使用）
   */
  private performFullScanSearch(
    store: IDBObjectStore,
    query: PackageVulnerabilityQuery,
    results: VulnerabilityQueryResult[],
    observer: any,
    matchMode: 'exact' | 'fuzzy' | 'cpe' | 'combined'
  ): void {
    const request = store.openCursor();
    // 建立已有結果的 CVE ID 集合，避免重複
    const existingIds = new Set(results.map(r => r.cveId));

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (!cursor) {
        observer.next(results);
        observer.complete();
        return;
      }

      const matchResults = this.checkRecordForQuery(cursor.value, query);
      for (const result of matchResults) {
        if (!existingIds.has(result.cveId)) {
          existingIds.add(result.cveId);
          results.push(result);
        }
      }
      cursor.continue();
    };

    request.onerror = () => observer.error(request.error);
  }

  /**
   * 優化的模糊搜尋
   */
  private performOptimizedFuzzySearch(
    store: IDBObjectStore,
    query: PackageVulnerabilityQuery,
    results: VulnerabilityQueryResult[],
    observer: any
  ): void {
    // 模糊搜尋無法使用索引，回退到全表掃描
    this.performFullScanSearch(store, query, results, observer, 'fuzzy');
  }

  /**
   * 優化的 CPE 搜尋
   */
  private performOptimizedCpeSearch(
    store: IDBObjectStore,
    query: PackageVulnerabilityQuery,
    results: VulnerabilityQueryResult[],
    observer: any
  ): void {
    // CPE 搜尋需要 vendor/product 分解，索引鍵無法可靠覆蓋所有情況
    // （例如 @babel/core 在索引中存為 core，但查詢鍵為 @babel/core）
    // 因此嘗試多個候選索引鍵，全部未命中時回退全表掃描
    const searchKeys = this.deriveCpeSearchKeys(query.packageName);

    let index: IDBIndex;
    try {
      index = store.index('affectedProducts');
    } catch {
      this.performFullScanSearch(store, query, results, observer, 'cpe');
      return;
    }

    this.searchIndexWithMultipleKeys(index, store, searchKeys, 0, query, results, observer, 'cpe');
  }

  /**
   * 從套件名稱衍生多個 CPE 搜尋索引鍵
   */
  private deriveCpeSearchKeys(packageName: string): string[] {
    const keys = new Set<string>();
    const lowered = packageName.toLowerCase();
    keys.add(lowered);

    // scoped package: @scope/name → 也嘗試 name 和 scope
    const scopeMatch = packageName.match(/^@([^/]+)\/(.+)$/);
    if (scopeMatch) {
      keys.add(scopeMatch[2].toLowerCase()); // unscoped name
      keys.add(scopeMatch[1].toLowerCase()); // scope as vendor
    }

    // 分隔符號變體
    const normalized = this.normalizeName(lowered);
    if (normalized !== lowered) {
      keys.add(normalized);
    }

    return [...keys];
  }

  /**
   * 依序嘗試多個索引鍵，全部未命中時回退全表掃描
   */
  private searchIndexWithMultipleKeys(
    index: IDBIndex,
    store: IDBObjectStore,
    keys: string[],
    keyIdx: number,
    query: PackageVulnerabilityQuery,
    results: VulnerabilityQueryResult[],
    observer: any,
    matchMode: 'cpe' | 'combined'
  ): void {
    if (keyIdx >= keys.length) {
      // 所有索引鍵都試過，回退全表掃描以補齊未被索引的記錄
      // （Worker 優化路徑可能不重建 affectedProducts 索引，與精確搜尋邏輯一致）
      this.performFullScanSearch(store, query, results, observer, matchMode);
      return;
    }

    const seenCveIds = new Set(results.map(r => r.cveId));
    const request = index.openCursor(IDBKeyRange.only(keys[keyIdx]));

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (!cursor) {
        // 當前鍵用完，嘗試下一個鍵
        this.searchIndexWithMultipleKeys(index, store, keys, keyIdx + 1, query, results, observer, matchMode);
        return;
      }

      const record = cursor.value;

      if (this.isOptimizedRecord(record)) {
        const optimizedRecord = record as OptimizedCveRecord;

        if (!seenCveIds.has(optimizedRecord.id)) {
          for (const productInfo of optimizedRecord.optimizedProductInfo) {
            if (productInfo.cpeInfo && this.isCpeMatch(productInfo.cpeInfo.cpeName, query.packageName)) {
              if (query.ecosystem && productInfo.ecosystem &&
                  productInfo.ecosystem !== 'unknown' &&
                  productInfo.ecosystem !== query.ecosystem) {
                continue;
              }
              if (this.isVersionAffectedOptimized(productInfo, query.version)) {
                results.push(this.transformOptimizedCveToResult(
                  optimizedRecord,
                  productInfo,
                  'cpe_match'
                ));
                seenCveIds.add(optimizedRecord.id);
                break;
              }
            }
          }
        }
      } else {
        this.handleLegacyRecord(record, query, results, 'cpe_match');
      }

      cursor.continue();
    };

    request.onerror = () => observer.error(request.error);
  }

  /**
   * 優化的綜合搜尋
   */
  private performOptimizedCombinedSearch(
    store: IDBObjectStore,
    query: PackageVulnerabilityQuery,
    results: VulnerabilityQueryResult[],
    observer: any
  ): void {
    // 綜合搜尋：先用索引做精確+CPE（含 scoped 變體），無結果時回退全表掃描
    const searchKeys = this.deriveCpeSearchKeys(query.packageName);

    let index: IDBIndex;
    try {
      index = store.index('affectedProducts');
    } catch {
      this.performFullScanSearch(store, query, results, observer, 'combined');
      return;
    }

    this.searchIndexCombined(index, store, searchKeys, 0, query, results, observer);
  }

  /**
   * 綜合搜尋的多鍵索引查詢
   */
  private searchIndexCombined(
    index: IDBIndex,
    store: IDBObjectStore,
    keys: string[],
    keyIdx: number,
    query: PackageVulnerabilityQuery,
    results: VulnerabilityQueryResult[],
    observer: any
  ): void {
    if (keyIdx >= keys.length) {
      if (results.length === 0) {
        // 索引全部未命中，回退全表掃描（含模糊匹配）
        this.performFullScanSearch(store, query, results, observer, 'combined');
      } else {
        observer.next(results);
        observer.complete();
      }
      return;
    }

    const seenCveIds = new Set(results.map(r => r.cveId));
    const indexRequest = index.openCursor(IDBKeyRange.only(keys[keyIdx]));

    indexRequest.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (!cursor) {
        this.searchIndexCombined(index, store, keys, keyIdx + 1, query, results, observer);
        return;
      }

      const record = cursor.value;

      if (this.isOptimizedRecord(record)) {
        const optimizedRecord = record as OptimizedCveRecord;

        if (!seenCveIds.has(optimizedRecord.id)) {
          for (const productInfo of optimizedRecord.optimizedProductInfo) {
            let matchType = '';
            let isMatch = false;

            if (this.isProductMatch(productInfo, query.packageName, 'exact')) {
              isMatch = true;
              matchType = 'exact_match';
            } else if (productInfo.cpeInfo && this.isCpeMatch(productInfo.cpeInfo.cpeName, query.packageName)) {
              isMatch = true;
              matchType = 'cpe_match';
            }

            if (isMatch && query.ecosystem && productInfo.ecosystem &&
                productInfo.ecosystem !== 'unknown' &&
                productInfo.ecosystem !== query.ecosystem) {
              isMatch = false;
            }

            if (isMatch && this.isVersionAffectedOptimized(productInfo, query.version)) {
              results.push(this.transformOptimizedCveToResult(
                optimizedRecord,
                productInfo,
                matchType
              ));
              seenCveIds.add(optimizedRecord.id);
              break;
            }
          }
        }
      } else {
        this.handleLegacyRecord(record, query, results, 'combined_match');
      }

      cursor.continue();
    };

    indexRequest.onerror = () => observer.error(indexRequest.error);
  }

  /**
   * 檢查是否為優化記錄格式
   */
  private isOptimizedRecord(record: any): boolean {
    return record && 
           record.optimizedProductInfo && 
           Array.isArray(record.optimizedProductInfo) &&
           record.processingTimestamp;
  }

  /**
   * 檢查產品是否匹配
   */
  private isProductMatch(productInfo: any, packageName: string, matchType: 'exact' | 'fuzzy'): boolean {
    const searchName = packageName.toLowerCase();
    const productName = productInfo.productName.toLowerCase();

    if (matchType === 'exact') {
      // 精確匹配產品名稱或別名
      if (productName === searchName) return true;
      
      if (productInfo.aliases) {
        return productInfo.aliases.some((alias: string) => 
          alias.toLowerCase() === searchName
        );
      }
    } else {
      // 模糊匹配
      if (productName.includes(searchName) || searchName.includes(productName)) {
        return true;
      }
      
      if (productInfo.aliases) {
        return productInfo.aliases.some((alias: string) => {
          const aliasLower = alias.toLowerCase();
          return aliasLower.includes(searchName) || searchName.includes(aliasLower);
        });
      }
    }

    return false;
  }

  /**
   * 檢查版本是否受影響（優化格式）
   */
  private isVersionAffectedOptimized(productInfo: any, version?: string): boolean {
    if (!version) return true;
    
    if (!productInfo.versionRanges || productInfo.versionRanges.length === 0) {
      return true; // 沒有版本限制，預設為受影響
    }

    // 檢查所有版本範圍
    for (const versionRange of productInfo.versionRanges) {
      if (this.isVersionInOptimizedRange(version, versionRange)) {
        return true;
      }
    }

    return false;
  }

  /**
   * 檢查版本是否在優化範圍內
   */
  private isVersionInOptimizedRange(version: string, versionRange: any): boolean {
    try {
      // 處理新的版本約束格式
      for (const constraint of versionRange.versionConstraints) {
        if (!this.satisfiesConstraint(version, constraint)) {
          return false;
        }
      }
      return true;
    } catch (error) {
      console.warn('優化版本比較失敗:', error);
      return true;
    }
  }

  /**
   * 檢查版本是否滿足約束
   */
  private satisfiesConstraint(version: string, constraint: any): boolean {
    const cmp = compareVersions(version, constraint.version);

    switch (constraint.type) {
      case 'lt':
        return cmp < 0;
      case 'lte':
        return cmp <= 0;
      case 'gt':
        return cmp > 0;
      case 'gte':
        return cmp >= 0;
      case 'eq':
        return cmp === 0;
      case 'range': {
        const startCmp = compareVersions(version, constraint.version);
        const endCmp = compareVersions(version, constraint.endVersion);

        const startSatisfied = constraint.includeStart ? startCmp >= 0 : startCmp > 0;
        const endSatisfied = constraint.includeEnd ? endCmp <= 0 : endCmp < 0;

        return startSatisfied && endSatisfied;
      }
      default:
        return true;
    }
  }

  /**
   * 檢查 CPE 是否匹配
   */
  private isCpeMatch(cpeName: string, packageName: string): boolean {
    if (!cpeName) return false;

    // CPE 2.3 格式: cpe:2.3:a:vendor:product:version:...
    const cpeParts = cpeName.toLowerCase().split(':');
    const cpeProduct = cpeParts[4] || '';
    const cpeVendor = cpeParts[3] || '';

    const normalizedPackage = this.normalizeName(packageName.toLowerCase());

    // 精確匹配 product 欄位
    if (this.normalizeName(cpeProduct) === normalizedPackage) return true;

    // 處理 scoped packages (如 @babel/helpers → helpers)
    const unscopedName = packageName.replace(/^@[^/]+\//, '').toLowerCase();
    const normalizedUnscoped = this.normalizeName(unscopedName);
    if (this.normalizeName(cpeProduct) === normalizedUnscoped) return true;

    // 檢查 vendor:product 組合是否匹配 scoped package (如 @babel/core → vendor=babel, product=core)
    if (packageName.startsWith('@')) {
      const scopeMatch = packageName.match(/^@([^/]+)\/(.+)$/);
      if (scopeMatch) {
        const scope = this.normalizeName(scopeMatch[1].toLowerCase());
        const name = this.normalizeName(scopeMatch[2].toLowerCase());
        if (this.normalizeName(cpeVendor) === scope && this.normalizeName(cpeProduct) === name) {
          return true;
        }
      }
    }

    // 降級匹配：product 欄位的受控模糊比對（處理 moment/momentjs 等後綴變體）
    const normalizedCpeProduct = this.normalizeName(cpeProduct);
    const lenDiff = Math.abs(normalizedCpeProduct.length - normalizedPackage.length);
    if (lenDiff > 0 && lenDiff <= 3 &&
        (normalizedCpeProduct.includes(normalizedPackage) || normalizedPackage.includes(normalizedCpeProduct))) {
      return true;
    }

    return false;
  }

  /**
   * 正規化名稱：統一分隔符號以便比較
   */
  private normalizeName(name: string): string {
    return name.replace(/[-_.]/g, '').toLowerCase();
  }

  /**
   * 轉換優化 CVE 記錄為查詢結果
   */
  private transformOptimizedCveToResult(
    record: OptimizedCveRecord, 
    productInfo: any, 
    matchReason: string
  ): VulnerabilityQueryResult {
    const description = record.descriptions?.find(d => d.lang === 'en')?.value || 
                       record.descriptions?.[0]?.value || 
                       '';

    // 提取受影響版本
    const affectedVersions = this.extractAffectedVersionsFromOptimized(productInfo);

    return {
      cveId: record.id,
      severity: record.severity,
      cvssScore: record.cvssScore,
      cvssVector: record.primaryCvssVector,
      description,
      publishedDate: record.published,
      lastModifiedDate: record.lastModified,
      references: record.references?.map(ref => ref.url) || [],
      affectedVersions,
      fixedVersion: this.extractFixedVersionFromOptimized(productInfo),
      matchReason,
      vendor: productInfo.vendor,
      product: productInfo.productName,
      ecosystem: productInfo.ecosystem
    };
  }

  /**
   * 從優化產品資訊提取受影響版本
   */
  private extractAffectedVersionsFromOptimized(productInfo: any): string[] {
    const versions: string[] = [];

    if (productInfo.versionRanges) {
      for (const range of productInfo.versionRanges) {
        for (const constraint of range.versionConstraints) {
          switch (constraint.type) {
            case 'lt':
              versions.push(`<${constraint.version}`);
              break;
            case 'lte':
              versions.push(`<=${constraint.version}`);
              break;
            case 'gt':
              versions.push(`>${constraint.version}`);
              break;
            case 'gte':
              versions.push(`>=${constraint.version}`);
              break;
            case 'range': {
              const start = constraint.includeStart ? '>=' : '>';
              const end = constraint.includeEnd ? '<=' : '<';
              versions.push(`${start}${constraint.version} ${end}${constraint.endVersion}`);
              break;
            }
            case 'eq':
              versions.push(constraint.version);
              break;
          }
        }
      }
    }

    return versions;
  }

  /**
   * 從優化產品資訊提取修復版本
   */
  private extractFixedVersionFromOptimized(productInfo: any): string | undefined {
    const candidates: string[] = [];

    if (productInfo.versionRanges) {
      for (const range of productInfo.versionRanges) {
        for (const constraint of range.versionConstraints) {
          if (constraint.type === 'lt') {
            // < x.y.z：x.y.z 本身就是第一個安全版本
            candidates.push(constraint.version);
          } else if (constraint.type === 'lte') {
            // <= x.y.z：x.y.z 仍受影響，安全版本是下一個 patch
            const next = this.getNextPatchVersion(constraint.version);
            if (next) {
              candidates.push(next);
            }
          } else if (constraint.type === 'range' && constraint.endVersion) {
            if (constraint.includeEnd) {
              // 包含 endVersion → endVersion 仍受影響
              const next = this.getNextPatchVersion(constraint.endVersion);
              if (next) {
                candidates.push(next);
              }
            } else {
              // 不包含 endVersion → endVersion 就是安全版本
              candidates.push(constraint.endVersion);
            }
          }
        }
      }
    }

    // 回傳最低的修復版本
    return this.getLowestVersion(candidates);
  }

  /**
   * 取得下一個補丁版本 (簡化實作)
   */
  private getNextPatchVersion(version: string): string | undefined {
    try {
      const parts = version.split('.');
      if (parts.length >= 3) {
        const patch = parseInt(parts[2], 10) + 1;
        return `${parts[0]}.${parts[1]}.${patch}`;
      } else if (parts.length === 2) {
        return `${parts[0]}.${parts[1]}.1`;
      } else if (parts.length === 1) {
        return `${parts[0]}.0.1`;
      }
    } catch (error) {
      console.warn(`無法解析版本號: ${version}`, error);
    }
    return undefined;
  }

  /**
   * 取得最低版本
   */
  private getLowestVersion(versions: string[]): string | undefined {
    if (versions.length === 0) return undefined;
    return versions.reduce((lowest, current) => {
      return compareVersions(current, lowest) < 0 ? current : lowest;
    });
  }

  /**
   * 處理舊格式記錄（向後相容）
   */
  private handleLegacyRecord(
    record: any, 
    query: PackageVulnerabilityQuery, 
    results: VulnerabilityQueryResult[], 
    matchType: string
  ): void {
    // 簡化的舊格式處理邏輯
    if (record.affectedProducts && 
        record.affectedProducts.includes(query.packageName)) {
      
      const description = record.descriptions?.find((d: any) => d.lang === 'en')?.value || '';
      const fixedVersion = this.extractFixedVersionFromLegacy(record);

      results.push({
        cveId: record.id,
        severity: record.severity,
        cvssScore: record.cvssScore,
        cvssVector: record.primaryCvssVector,
        description,
        publishedDate: record.published,
        lastModifiedDate: record.lastModified,
        references: record.references?.map((ref: any) => ref.url) || [],
        affectedVersions: [],
        fixedVersion,
        matchReason: `legacy_${matchType}`
      });
    }
  }

  private extractFixedVersionFromLegacy(record: any): string | undefined {
    if (record.versionRanges) {
      for (const range of record.versionRanges) {
        if (range.versionEndExcluding) {
          return range.versionEndExcluding;
        }
        if (range.versionEndIncluding) {
          return range.versionEndIncluding;
        }
      }
    }
    return undefined;
  }

}