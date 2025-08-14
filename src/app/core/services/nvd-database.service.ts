import { Injectable } from '@angular/core';
import { Observable, BehaviorSubject, from } from 'rxjs';
import { map, switchMap, catchError, tap } from 'rxjs/operators';
import {
  CveRecord,
  CpeRecord,
  MetadataRecord,
  DatabaseVersion,
  VulnerabilityQueryResult,
  PackageVulnerabilityQuery,
  BatchProcessProgress
} from '../interfaces/nvd-database.interface';
import { Vulnerability } from '../models/vulnerability.model';
import { DatabaseWorkerService } from './database-worker.service';

@Injectable({
  providedIn: 'root'
})
export class NvdDatabaseService {
  private readonly DB_NAME = 'NvdLocalDatabase';
  private readonly DB_VERSION = 2; // 升級版本以支援 NVD 2.0 優化
  private readonly CVE_STORE = 'cve';
  private readonly CPE_STORE = 'cpe';
  private readonly METADATA_STORE = 'metadata';
  
  private db: IDBDatabase | null = null;
  private readonly isReady$ = new BehaviorSubject<boolean>(false);
  private readonly storeProgress$ = new BehaviorSubject<BatchProcessProgress | null>(null);

  constructor(private workerService: DatabaseWorkerService) {
    this.initDatabase();
  }

  /**
   * 取得資料庫準備狀態
   */
  isReady(): Observable<boolean> {
    return this.isReady$.asObservable();
  }

  /**
   * 取得儲存進度
   */
  getStoreProgress(): Observable<BatchProcessProgress | null> {
    return this.storeProgress$.asObservable();
  }

  /**
   * 初始化 IndexedDB
   */
  private initDatabase(): void {
    if (!('indexedDB' in window)) {
      console.error('此瀏覽器不支援 IndexedDB');
      this.isReady$.next(false);
      return;
    }

    const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);

    request.onerror = () => {
      console.error('IndexedDB 開啟失敗:', request.error);
      this.isReady$.next(false);
    };

    request.onsuccess = () => {
      this.db = request.result;
      
      // 確保所有 store 都存在
      if (this.validateStores(this.db)) {
        this.isReady$.next(true);
        console.log('IndexedDB 初始化成功');
      } else {
        console.error('資料庫 stores 驗證失敗');
        this.isReady$.next(false);
      }
    };

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      this.createStores(db);
    };
  }

  /**
   * 驗證資料庫 stores 是否正確建立
   */
  private validateStores(db: IDBDatabase): boolean {
    const requiredStores = [this.CVE_STORE, this.CPE_STORE, this.METADATA_STORE];
    
    for (const storeName of requiredStores) {
      if (!db.objectStoreNames.contains(storeName)) {
        console.error(`缺少必要的 store: ${storeName}`);
        return false;
      }
    }
    
    return true;
  }

  /**
   * 建立 IndexedDB stores（NVD 2.0 優化版）
   */
  private createStores(db: IDBDatabase): void {
    // CVE store
    if (!db.objectStoreNames.contains(this.CVE_STORE)) {
      const cveStore = db.createObjectStore(this.CVE_STORE, { keyPath: 'id' });
      
      // 基本搜尋索引
      cveStore.createIndex('severity', 'severity');
      cveStore.createIndex('cvssScore', 'cvssScore');
      cveStore.createIndex('lastModified', 'lastModified');
      cveStore.createIndex('published', 'published');
      cveStore.createIndex('publishedYear', 'publishedYear'); // 年份快速篩選
      
      // 產品搜尋索引（多值）
      cveStore.createIndex('affectedProducts', 'affectedProducts', { multiEntry: true });
      cveStore.createIndex('vendorProducts', 'vendorProducts', { multiEntry: true }); // 新增：廠商-產品組合
      cveStore.createIndex('ecosystems', 'ecosystems', { multiEntry: true }); // 新增：生態系統
      
      // 文字搜尋索引
      cveStore.createIndex('keywordSearchText', 'keywordSearchText');
      
      // NVD 2.0 特有索引
      cveStore.createIndex('vulnStatus', 'vulnStatus'); // 新增：漏洞狀態
      cveStore.createIndex('sourceIdentifier', 'sourceIdentifier'); // 新增：來源標識符
      cveStore.createIndex('cveTags', 'cveTags', { multiEntry: true }); // 新增：CVE 標籤
      
      // 效能優化索引
      cveStore.createIndex('cpeMatchCount', 'cpeMatchCount'); // 新增：CPE 匹配數量
      cveStore.createIndex('referenceCount', 'referenceCount'); // 新增：參考連結數量
      cveStore.createIndex('primaryCvssVector', 'primaryCvssVector'); // 新增：主要 CVSS 向量
      
      // 複合索引（提升複雜查詢效能）
      cveStore.createIndex('severity_cvssScore', ['severity', 'cvssScore']); // 嚴重程度+分數
      cveStore.createIndex('publishedYear_severity', ['publishedYear', 'severity']); // 年份+嚴重程度
      cveStore.createIndex('lastModified_vulnStatus', ['lastModified', 'vulnStatus']); // 修改日期+狀態
      
      // 版本管理索引
      cveStore.createIndex('dataVersion', 'dataVersion');
      cveStore.createIndex('syncTimestamp', 'syncTimestamp');
      cveStore.createIndex('lastModified_dataVersion', ['lastModified', 'dataVersion']);
    }

    // CPE store
    if (!db.objectStoreNames.contains(this.CPE_STORE)) {
      const cpeStore = db.createObjectStore(this.CPE_STORE, { keyPath: 'cpeName' });
      
      // 建立索引
      cpeStore.createIndex('vendor', 'vendor');
      cpeStore.createIndex('product', 'product');
      cpeStore.createIndex('mappedPackageNames', 'mappedPackageNames', { multiEntry: true });
      cpeStore.createIndex('lastModified', 'lastModified'); // 版本管理索引
      cpeStore.createIndex('dataVersion', 'dataVersion'); // 資料版本標記
      cpeStore.createIndex('syncTimestamp', 'syncTimestamp'); // 同步時間戳索引
    }

    // 元資料 store
    if (!db.objectStoreNames.contains(this.METADATA_STORE)) {
      db.createObjectStore(this.METADATA_STORE, { keyPath: 'key' });
    }
  }

  /**
   * 批次儲存 CVE 記錄（改用多事務模式避免超時）
   */
  storeCveRecords(records: CveRecord[]): Observable<BatchProcessProgress> {
    return new Observable(observer => {
      if (!this.db) {
        observer.error(new Error('資料庫尚未準備好'));
        return;
      }

      let processed = 0;
      const total = records.length;
      const batchSize = 500; // 減少批次大小避免事務超時
      let currentBatch = 0;
      const maxRetries = 3; // 最大重試次數

      const processBatch = (retryCount = 0) => {
        const start = currentBatch * batchSize;
        const end = Math.min(start + batchSize, total);
        const batch = records.slice(start, end);

        if (batch.length === 0) {
          observer.complete();
          return;
        }

        // 為每個批次創建新的事務
        try {
          const transaction = this.db!.transaction([this.CVE_STORE], 'readwrite');
          const store = transaction.objectStore(this.CVE_STORE);
          
          let batchProcessed = 0;
          let hasError = false;

          // 處理當前批次的所有記錄
          for (const record of batch) {
            if (hasError) break;
            
            try {
              const request = store.put(record);
              
              request.onsuccess = () => {
                batchProcessed++;
                processed++;
                
                // 當此批次完成時
                if (batchProcessed === batch.length) {
                  const progress: BatchProcessProgress = {
                    type: 'store',
                    processed: processed,
                    total: total,
                    percentage: (processed / total) * 100,
                    message: `已儲存 ${processed}/${total} 筆 CVE 記錄`,
                    startTime: new Date()
                  };

                  this.storeProgress$.next(progress);
                  observer.next(progress);

                  if (processed >= total) {
                    observer.complete();
                  } else {
                    // 短暫延遲後處理下一批次，讓 UI 更新
                    currentBatch++;
                    setTimeout(processBatch, 5);
                  }
                }
              };

              request.onerror = () => {
                if (!hasError) {
                  hasError = true;
                  console.error('儲存 CVE 記錄失敗:', request.error);
                  
                  // 嘗試重試當前批次
                  if (retryCount < maxRetries) {
                    console.log(`重試第 ${retryCount + 1} 次儲存批次 ${currentBatch}`);
                    setTimeout(() => processBatch(retryCount + 1), 1000);
                  } else {
                    observer.error(request.error);
                  }
                }
              };
            } catch (error) {
              if (!hasError) {
                hasError = true;
                console.error('建立儲存請求失敗:', error);
                observer.error(error);
              }
              break;
            }
          }

          transaction.onerror = () => {
            if (!hasError) {
              hasError = true;
              console.error('事務失敗:', transaction.error);
              
              // 嘗試重試當前批次
              if (retryCount < maxRetries) {
                console.log(`重試第 ${retryCount + 1} 次儲存批次 ${currentBatch}`);
                setTimeout(() => processBatch(retryCount + 1), 1000);
              } else {
                observer.error(transaction.error);
              }
            }
          };

          transaction.onabort = () => {
            if (!hasError) {
              hasError = true;
              console.error('事務被中止');
              
              // 嘗試重試當前批次
              if (retryCount < maxRetries) {
                console.log(`重試第 ${retryCount + 1} 次儲存批次 ${currentBatch}`);
                setTimeout(() => processBatch(retryCount + 1), 1000);
              } else {
                observer.error(new Error('事務被中止'));
              }
            }
          };

        } catch (error) {
          console.error('建立事務失敗:', error);
          
          // 嘗試重試當前批次
          if (retryCount < maxRetries) {
            console.log(`重試第 ${retryCount + 1} 次儲存批次 ${currentBatch}`);
            setTimeout(() => processBatch(retryCount + 1), 1000);
          } else {
            observer.error(error);
          }
          return;
        }
      };

      // 開始處理第一個批次
      processBatch();
    });
  }

  /**
   * 批次儲存 CPE 記錄（改用多事務模式避免超時）
   */
  storeCpeRecords(records: CpeRecord[]): Observable<BatchProcessProgress> {
    return new Observable(observer => {
      if (!this.db) {
        observer.error(new Error('資料庫尚未準備好'));
        return;
      }

      let processed = 0;
      const total = records.length;
      const batchSize = 500; // 減少批次大小避免事務超時
      let currentBatch = 0;

      const processBatch = () => {
        const start = currentBatch * batchSize;
        const end = Math.min(start + batchSize, total);
        const batch = records.slice(start, end);

        if (batch.length === 0) {
          const finalProgress: BatchProcessProgress = {
            type: 'store',
            processed: total,
            total: total,
            percentage: 100,
            message: `所有 CPE 記錄儲存完成 (${total} 筆)`,
            startTime: new Date()
          };
          this.storeProgress$.next(finalProgress);
          observer.next(finalProgress);
          observer.complete();
          return;
        }

        // 為每個批次創建新的事務
        try {
          const transaction = this.db!.transaction([this.CPE_STORE], 'readwrite');
          const store = transaction.objectStore(this.CPE_STORE);
          
          let batchProcessed = 0;
          let hasError = false;

          // 處理當前批次的所有記錄
          for (const record of batch) {
            if (hasError) break;
            
            try {
              const request = store.put(record);
              
              request.onsuccess = () => {
                batchProcessed++;
                processed++;
                
                // 當此批次完成時
                if (batchProcessed === batch.length) {
                  const progress: BatchProcessProgress = {
                    type: 'store',
                    processed: processed,
                    total: total,
                    percentage: (processed / total) * 100,
                    message: `已儲存 ${processed}/${total} 筆 CPE 記錄`,
                    startTime: new Date()
                  };

                  this.storeProgress$.next(progress);
                  observer.next(progress);

                  if (processed >= total) {
                    const finalProgress: BatchProcessProgress = {
                      type: 'store',
                      processed: total,
                      total: total,
                      percentage: 100,
                      message: `所有 CPE 記錄儲存完成 (${total} 筆)`,
                      startTime: new Date()
                    };
                    this.storeProgress$.next(finalProgress);
                    observer.next(finalProgress);
                    observer.complete();
                  } else {
                    // 短暫延遲後處理下一批次
                    currentBatch++;
                    setTimeout(processBatch, 5);
                  }
                }
              };

              request.onerror = () => {
                if (!hasError) {
                  hasError = true;
                  console.error('儲存 CPE 記錄失敗:', request.error);
                  observer.error(request.error);
                }
              };
            } catch (error) {
              if (!hasError) {
                hasError = true;
                console.error('建立儲存請求失敗:', error);
                observer.error(error);
              }
              break;
            }
          }

          transaction.onerror = () => {
            if (!hasError) {
              hasError = true;
              console.error('事務失敗:', transaction.error);
              observer.error(transaction.error);
            }
          };

          transaction.onabort = () => {
            if (!hasError) {
              hasError = true;
              console.error('事務被中止');
              observer.error(new Error('事務被中止'));
            }
          };

        } catch (error) {
          console.error('建立事務失敗:', error);
          observer.error(error);
          return;
        }
      };

      // 開始處理第一個批次
      processBatch();
    });
  }

  /**
   * 查詢套件漏洞
   */
  queryPackageVulnerabilities(query: PackageVulnerabilityQuery): Observable<VulnerabilityQueryResult[]> {
    return new Observable(observer => {
      if (!this.db) {
        observer.error(new Error('資料庫尚未準備好'));
        return;
      }

      const transaction = this.db.transaction([this.CVE_STORE, this.CPE_STORE], 'readonly');
      const cveStore = transaction.objectStore(this.CVE_STORE);
      const results: VulnerabilityQueryResult[] = [];

      // 使用不同的查詢策略
      switch (query.searchType) {
        case 'exact':
          this.performExactSearch(cveStore, query, results, observer);
          break;
        case 'fuzzy':
          this.performFuzzySearch(cveStore, query, results, observer);
          break;
        case 'cpe':
          this.performCpeSearch(transaction, query, results, observer);
          break;
        default:
          this.performCombinedSearch(transaction, query, results, observer);
      }

      transaction.onerror = () => {
        observer.error(transaction.error);
      };
    });
  }

  /**
   * 精確搜尋
   */
  private performExactSearch(
    store: IDBObjectStore,
    query: PackageVulnerabilityQuery,
    results: VulnerabilityQueryResult[],
    observer: any
  ): void {
    const index = store.index('affectedProducts');
    const request = index.getAll(query.packageName);

    request.onsuccess = () => {
      const records: CveRecord[] = request.result;
      
      for (const record of records) {
        if (this.isVersionAffected(record, query.version)) {
          results.push(this.transformCveToResult(record, 'exact_match'));
        }
      }

      observer.next(results);
      observer.complete();
    };

    request.onerror = () => {
      observer.error(request.error);
    };
  }

  /**
   * 模糊搜尋
   */
  private performFuzzySearch(
    store: IDBObjectStore,
    query: PackageVulnerabilityQuery,
    results: VulnerabilityQueryResult[],
    observer: any
  ): void {
    const index = store.index('keywordSearchText');
    const request = index.openCursor();

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (!cursor) {
        observer.next(results);
        observer.complete();
        return;
      }

      const record: CveRecord = cursor.value;
      if (this.isKeywordMatch(record.keywordSearchText, query.packageName)) {
        if (this.isVersionAffected(record, query.version)) {
          results.push(this.transformCveToResult(record, 'keyword_match'));
        }
      }

      cursor.continue();
    };

    request.onerror = () => {
      observer.error(request.error);
    };
  }

  /**
   * CPE 搜尋
   */
  private performCpeSearch(
    transaction: IDBTransaction,
    query: PackageVulnerabilityQuery,
    results: VulnerabilityQueryResult[],
    observer: any
  ): void {
    const cpeStore = transaction.objectStore(this.CPE_STORE);
    const cveStore = transaction.objectStore(this.CVE_STORE);
    
    // 先在 CPE store 中尋找對應的 CPE 名稱
    const cpeIndex = cpeStore.index('mappedPackageNames');
    const cpeRequest = cpeIndex.getAll(query.packageName);

    cpeRequest.onsuccess = () => {
      const cpeRecords: CpeRecord[] = cpeRequest.result;
      
      if (cpeRecords.length === 0) {
        observer.next(results);
        observer.complete();
        return;
      }

      // 用找到的 CPE 名稱查詢 CVE
      let processedCpes = 0;
      const totalCpes = cpeRecords.length;

      for (const cpeRecord of cpeRecords) {
        const cveRequest = cveStore.openCursor();
        
        cveRequest.onsuccess = (event) => {
          const cursor = (event.target as IDBRequest).result;
          if (!cursor) {
            processedCpes++;
            if (processedCpes >= totalCpes) {
              observer.next(results);
              observer.complete();
            }
            return;
          }

          const cveRecord: CveRecord = cursor.value;
          if (this.isCpeMatch(cveRecord, cpeRecord.cpeName) && 
              this.isVersionAffected(cveRecord, query.version)) {
            results.push(this.transformCveToResult(cveRecord, 'cpe_match'));
          }

          cursor.continue();
        };
      }
    };

    cpeRequest.onerror = () => {
      observer.error(cpeRequest.error);
    };
  }

  /**
   * 組合搜尋（預設）
   */
  private performCombinedSearch(
    transaction: IDBTransaction,
    query: PackageVulnerabilityQuery,
    results: VulnerabilityQueryResult[],
    observer: any
  ): void {
    // 先嘗試精確搜尋，再進行模糊搜尋
    const cveStore = transaction.objectStore(this.CVE_STORE);
    
    // Step 1: 精確匹配
    const exactIndex = cveStore.index('affectedProducts');
    const exactRequest = exactIndex.getAll(query.packageName);

    exactRequest.onsuccess = () => {
      const exactResults: CveRecord[] = exactRequest.result;
      const exactCveIds = new Set<string>();

      for (const record of exactResults) {
        if (this.isVersionAffected(record, query.version)) {
          results.push(this.transformCveToResult(record, 'exact_match'));
          exactCveIds.add(record.id);
        }
      }

      // Step 2: 模糊匹配（排除已找到的精確匹配）
      const fuzzyIndex = cveStore.index('keywordSearchText');
      const fuzzyRequest = fuzzyIndex.openCursor();

      fuzzyRequest.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        if (!cursor) {
          observer.next(results);
          observer.complete();
          return;
        }

        const record: CveRecord = cursor.value;
        
        // 避免重複
        if (!exactCveIds.has(record.id) && 
            this.isKeywordMatch(record.keywordSearchText, query.packageName) &&
            this.isVersionAffected(record, query.version)) {
          results.push(this.transformCveToResult(record, 'fuzzy_match'));
        }

        cursor.continue();
      };
    };
  }

  /**
   * 檢查版本是否受影響
   */
  private isVersionAffected(cveRecord: CveRecord, version?: string): boolean {
    if (!version) return true; // 沒有指定版本，回傳所有結果
    
    // 檢查 versionRanges
    for (const range of cveRecord.versionRanges) {
      if (this.versionInRange(version, range)) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * 檢查版本是否在指定範圍內
   */
  private versionInRange(version: string, range: any): boolean {
    // 這裡應該使用 semver 來比較版本，簡化實作
    try {
      const versionParts = this.parseVersion(version);
      
      if (range.versionStartIncluding) {
        const startParts = this.parseVersion(range.versionStartIncluding);
        if (this.compareVersions(versionParts, startParts) < 0) return false;
      }
      
      if (range.versionStartExcluding) {
        const startParts = this.parseVersion(range.versionStartExcluding);
        if (this.compareVersions(versionParts, startParts) <= 0) return false;
      }
      
      if (range.versionEndIncluding) {
        const endParts = this.parseVersion(range.versionEndIncluding);
        if (this.compareVersions(versionParts, endParts) > 0) return false;
      }
      
      if (range.versionEndExcluding) {
        const endParts = this.parseVersion(range.versionEndExcluding);
        if (this.compareVersions(versionParts, endParts) >= 0) return false;
      }
      
      return true;
    } catch (error) {
      console.warn('版本比較失敗:', error);
      return true; // 無法比較時預設為受影響
    }
  }

  /**
   * 解析版本號
   */
  private parseVersion(version: string): number[] {
    return version.split(/[.-]/).map(part => {
      const num = parseInt(part, 10);
      return isNaN(num) ? 0 : num;
    });
  }

  /**
   * 比較版本號
   */
  private compareVersions(a: number[], b: number[]): number {
    const maxLength = Math.max(a.length, b.length);
    
    for (let i = 0; i < maxLength; i++) {
      const aPart = a[i] || 0;
      const bPart = b[i] || 0;
      
      if (aPart !== bPart) {
        return aPart - bPart;
      }
    }
    
    return 0;
  }

  /**
   * 檢查關鍵字是否匹配
   */
  private isKeywordMatch(searchText: string, packageName: string): boolean {
    const lowerSearchText = searchText.toLowerCase();
    const lowerPackageName = packageName.toLowerCase();
    
    return lowerSearchText.includes(lowerPackageName) ||
           lowerPackageName.includes(lowerSearchText) ||
           this.fuzzyStringMatch(lowerSearchText, lowerPackageName);
  }

  /**
   * 模糊字串匹配
   */
  private fuzzyStringMatch(text: string, pattern: string): boolean {
    const words = pattern.split(/[-_\s]/);
    return words.some(word => text.includes(word) && word.length > 2);
  }

  /**
   * 檢查 CPE 是否匹配
   */
  private isCpeMatch(cveRecord: CveRecord, cpeName: string): boolean {
    return cveRecord.versionRanges.some(range => range.cpeName === cpeName);
  }

  /**
   * 轉換 CVE 記錄為查詢結果（與 API 掃描保持一致）
   */
  private transformCveToResult(cveRecord: CveRecord, matchReason: string): VulnerabilityQueryResult {
    const description = cveRecord.descriptions.find(d => d.lang === 'en')?.value ||
                       cveRecord.descriptions[0]?.value ||
                       'No description available';

    // 提取 CVSS Vector
    const cvssVector = this.extractCvssVectorFromMetrics(cveRecord.metrics);
    
    // 提取主要廠商和產品資訊
    const primaryVersionRange = cveRecord.versionRanges.find(range => range.vulnerable) || cveRecord.versionRanges[0];

    return {
      cveId: cveRecord.id,
      severity: cveRecord.severity,
      cvssScore: cveRecord.cvssScore,
      cvssVector: cvssVector,
      description: description,
      publishedDate: cveRecord.published,
      lastModifiedDate: cveRecord.lastModified,
      references: cveRecord.references.map(ref => ref.url),
      affectedVersions: cveRecord.versionRanges.map(range => this.formatVersionRange(range)),
      fixedVersion: this.extractFixedVersion(cveRecord.versionRanges),
      matchReason: matchReason,
      vendor: primaryVersionRange?.vendor,
      product: primaryVersionRange?.product,
      ecosystem: primaryVersionRange?.ecosystem
    };
  }

  /**
   * 格式化版本範圍
   */
  private formatVersionRange(range: any): string {
    const parts: string[] = [];
    
    if (range.versionStartIncluding) {
      parts.push(`>= ${range.versionStartIncluding}`);
    }
    if (range.versionStartExcluding) {
      parts.push(`> ${range.versionStartExcluding}`);
    }
    if (range.versionEndIncluding) {
      parts.push(`<= ${range.versionEndIncluding}`);
    }
    if (range.versionEndExcluding) {
      parts.push(`< ${range.versionEndExcluding}`);
    }
    
    return parts.join(' && ') || 'all versions';
  }

  /**
   * 從 CVE metrics 中提取 CVSS Vector
   */
  private extractCvssVectorFromMetrics(metrics: any): string {
    if (!metrics) return '';
    
    // 優先使用 CVSS v3.1
    if (metrics.cvssMetricV31?.[0]?.cvssData?.vectorString) {
      return metrics.cvssMetricV31[0].cvssData.vectorString;
    }
    
    // 其次使用 CVSS v3.0
    if (metrics.cvssMetricV30?.[0]?.cvssData?.vectorString) {
      return metrics.cvssMetricV30[0].cvssData.vectorString;
    }
    
    // 最後使用 CVSS v2（可能沒有 vectorString）
    if (metrics.cvssMetricV2?.[0]?.cvssData?.vectorString) {
      return metrics.cvssMetricV2[0].cvssData.vectorString;
    }
    
    return '';
  }

  /**
   * 提取修復版本
   */
  private extractFixedVersion(ranges: any[]): string | undefined {
    for (const range of ranges) {
      if (range.versionEndExcluding) {
        return range.versionEndExcluding;
      }
    }
    return undefined;
  }

  /**
   * 取得資料庫統計資訊（含動態年份查詢）
   */
  getDatabaseStats(): Observable<DatabaseVersion> {
    return this.isReady().pipe(
      switchMap(isReady => {
        if (!isReady || !this.db) {
          // 如果資料庫未準備好，回傳預設統計值
          const defaultStats: DatabaseVersion = {
            version: this.DB_VERSION,
            lastSync: 'Never',
            dataYears: [],
            totalCveCount: 0,
            totalCpeCount: 0
          };
          return [defaultStats];
        }

        return new Observable<DatabaseVersion>(observer => {
          try {
            const transaction = this.db!.transaction([this.CVE_STORE, this.CPE_STORE, this.METADATA_STORE], 'readonly');
            
            const cveCountRequest = transaction.objectStore(this.CVE_STORE).count();
            const cpeCountRequest = transaction.objectStore(this.CPE_STORE).count();
            const lastSyncRequest = transaction.objectStore(this.METADATA_STORE).get('last_sync');

            // 動態查詢年份資料
            const dataYearsPromise = this.queryDataYears(transaction);

            Promise.all([
              new Promise<number>((resolve, reject) => { 
                cveCountRequest.onsuccess = () => resolve(cveCountRequest.result);
                cveCountRequest.onerror = () => reject(cveCountRequest.error);
              }),
              new Promise<number>((resolve, reject) => { 
                cpeCountRequest.onsuccess = () => resolve(cpeCountRequest.result);
                cpeCountRequest.onerror = () => reject(cpeCountRequest.error);
              }),
              new Promise<any>((resolve, reject) => { 
                lastSyncRequest.onsuccess = () => resolve(lastSyncRequest.result);
                lastSyncRequest.onerror = () => resolve(null); // 沒有資料時不算錯誤
              }),
              dataYearsPromise
            ]).then(([cveCount, cpeCount, lastSyncRecord, dataYears]) => {
              const stats: DatabaseVersion = {
                version: this.DB_VERSION,
                lastSync: lastSyncRecord?.value || 'Never',
                dataYears: dataYears,
                totalCveCount: cveCount,
                totalCpeCount: cpeCount
              };
              
              observer.next(stats);
              observer.complete();
            }).catch(error => {
              console.warn('取得統計資訊失敗，回傳預設值:', error);
              // 即使出錯也回傳基本統計
              observer.next({
                version: this.DB_VERSION,
                lastSync: 'Never',
                dataYears: [],
                totalCveCount: 0,
                totalCpeCount: 0
              });
              observer.complete();
            });

            transaction.onerror = () => {
              console.warn('Transaction 錯誤，回傳預設值:', transaction.error);
              observer.next({
                version: this.DB_VERSION,
                lastSync: 'Never',
                dataYears: [],
                totalCveCount: 0,
                totalCpeCount: 0
              });
              observer.complete();
            };
          } catch (error) {
            console.warn('建立 transaction 失敗，回傳預設值:', error);
            observer.next({
              version: this.DB_VERSION,
              lastSync: 'Never',
              dataYears: [],
              totalCveCount: 0,
              totalCpeCount: 0
            });
            observer.complete();
          }
        });
      })
    );
  }

  /**
   * 動態查詢資料庫中存在的年份
   */
  private queryDataYears(transaction: IDBTransaction): Promise<number[]> {
    return new Promise((resolve, reject) => {
      try {
        const cveStore = transaction.objectStore(this.CVE_STORE);
        
        // 檢查索引是否存在，優先使用 published_year 索引
        let indexName: string;
        if (cveStore.indexNames.contains('published_year')) {
          indexName = 'published_year';
        } else if (cveStore.indexNames.contains('publishedYear')) {
          indexName = 'publishedYear';
        } else {
          // 沒有年份索引，使用 cursor 遍歷所有記錄
          this.queryDataYearsFromRecords(cveStore, resolve);
          return;
        }
        
        const publishedYearIndex = cveStore.index(indexName);
        const request = publishedYearIndex.openKeyCursor();
        
        const years = new Set<number>();
        
        request.onsuccess = (event) => {
          const cursor = (event.target as IDBRequest).result;
          if (!cursor) {
            // 查詢完成，回傳排序後的年份陣列
            const sortedYears = Array.from(years).sort((a, b) => b - a); // 由新到舊排序
            resolve(sortedYears);
            return;
          }
          
          const year = cursor.key as number;
          if (year && year > 0) {
            years.add(year);
          }
          
          cursor.continue();
        };
        
        request.onerror = () => {
          console.warn('索引查詢失敗，使用記錄遍歷方式:', request.error);
          this.queryDataYearsFromRecords(cveStore, resolve);
        };
        
      } catch (error) {
        console.warn('查詢年份資料時發生錯誤，回傳預期年份:', error);
        this.fallbackToExpectedYears(resolve);
      }
    });
  }
  
  /**
   * 從記錄中提取年份（無索引時的備用方案）
   */
  private queryDataYearsFromRecords(cveStore: IDBObjectStore, resolve: (years: number[]) => void): void {
    const request = cveStore.openCursor();
    const years = new Set<number>();
    let processed = 0;
    
    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (!cursor) {
        const sortedYears = Array.from(years).sort((a, b) => b - a);
        console.log(`完成年份查詢，處理了 ${processed} 筆記錄，找到 ${years.size} 個年份:`, sortedYears);
        resolve(sortedYears);
        return;
      }
      
      const record = cursor.value;
      if (record.publishedYear && record.publishedYear > 0) {
        years.add(record.publishedYear);
      } else if (record.published) {
        // 如果沒有 publishedYear 欄位，從 published 日期解析
        const year = new Date(record.published).getFullYear();
        if (year > 0) {
          years.add(year);
        }
      }
      
      processed++;
      
      // 每處理 10000 筆記錄輸出一次進度
      if (processed % 10000 === 0) {
        console.log(`年份查詢進度: 已處理 ${processed} 筆記錄，目前找到 ${years.size} 個年份`);
      }
      
      cursor.continue();
    };
    
    request.onerror = () => {
      console.warn('記錄遍歷失敗:', request.error);
      this.fallbackToExpectedYears(resolve);
    };
  }
  
  /**
   * 回退到預期年份
   */
  private fallbackToExpectedYears(resolve: (years: number[]) => void): void {
    const currentYear = new Date().getFullYear();
    const expectedYears = [];
    for (let i = 0; i < 4; i++) { // 近四年
      expectedYears.push(currentYear - i);
    }
    resolve(expectedYears);
  }

  /**
   * 清除所有資料
   */
  clearAllData(): Observable<void> {
    return new Observable(observer => {
      if (!this.db) {
        observer.error(new Error('資料庫尚未準備好'));
        return;
      }

      const transaction = this.db.transaction([this.CVE_STORE, this.CPE_STORE, this.METADATA_STORE], 'readwrite');
      
      const cveRequest = transaction.objectStore(this.CVE_STORE).clear();
      const cpeRequest = transaction.objectStore(this.CPE_STORE).clear();
      const metadataRequest = transaction.objectStore(this.METADATA_STORE).clear();

      transaction.oncomplete = () => {
        console.log('所有資料已清除');
        observer.next();
        observer.complete();
      };

      transaction.onerror = () => {
        observer.error(transaction.error);
      };
    });
  }

  /**
   * 儲存元資料
   */
  storeMetadata(key: string, value: string): Observable<void> {
    return new Observable(observer => {
      if (!this.db) {
        observer.error(new Error('資料庫尚未準備好'));
        return;
      }

      const transaction = this.db.transaction([this.METADATA_STORE], 'readwrite');
      const store = transaction.objectStore(this.METADATA_STORE);
      
      const record: MetadataRecord = {
        key,
        value,
        updatedAt: new Date().toISOString()
      };

      const request = store.put(record);
      
      request.onsuccess = () => {
        observer.next();
        observer.complete();
      };

      request.onerror = () => {
        observer.error(request.error);
      };
    });
  }

  /**
   * 智慧資料更新 - 載入前先清理舊資料
   */
  smartDataUpdate(options: {
    cveRecords: CveRecord[];
    cpeRecords: CpeRecord[];
    newVersion: string;
    keepRecentDays?: number;
  }): Observable<BatchProcessProgress> {
    const { cveRecords, cpeRecords, newVersion, keepRecentDays = 7 } = options;

    return new Observable(observer => {
      // 檢查是否可用 Web Worker
      if (this.workerService.isWorkerAvailable()) {
        this.performWorkerBasedUpdate(options, observer);
      } else {
        this.performMainThreadUpdate(options, observer);
      }
    });
  }

  /**
   * 使用 Web Worker 進行更新
   */
  private performWorkerBasedUpdate(
    options: {
      cveRecords: CveRecord[];
      cpeRecords: CpeRecord[];
      newVersion: string;
      keepRecentDays?: number;
    },
    observer: any
  ): void {
    const { cveRecords, cpeRecords, newVersion, keepRecentDays = 7 } = options;

    // 步驟 1: 準備資料庫（清理舊資料）
    observer.next({
      type: 'store',
      processed: 0,
      total: cveRecords.length + cpeRecords.length,
      percentage: 0,
      message: '正在準備資料庫...',
      startTime: new Date()
    });

    this.workerService.prepareForNewData({
      newDataVersion: newVersion,
      keepRecentDays
    }).subscribe({
      next: (prepareResult) => {
        if (prepareResult.phase === 'complete') {
          // 步驟 2: 載入新資料
          this.workerService.bulkInsert({
            cveRecords: this.addVersionInfo(cveRecords, newVersion),
            cpeRecords: this.addVersionInfoToCpe(cpeRecords, newVersion),
            batchSize: 1000
          }).subscribe({
            next: (insertResult) => {
              observer.next({
                type: 'store',
                processed: insertResult.cveInserted + insertResult.cpeInserted,
                total: cveRecords.length + cpeRecords.length,
                percentage: 100,
                message: `資料載入完成：${insertResult.cveInserted} CVE + ${insertResult.cpeInserted} CPE`,
                startTime: new Date()
              });
              observer.complete();
            },
            error: (error) => observer.error(error)
          });
        } else {
          observer.next({
            type: 'store',
            processed: 0,
            total: 1,
            percentage: 50,
            message: prepareResult.message,
            startTime: new Date()
          });
        }
      },
      error: (error) => observer.error(error)
    });

    // 訂閱 Worker 進度
    this.workerService.getProgress().subscribe(progress => {
      if (progress) {
        observer.next({
          type: 'store',
          processed: progress.processed || 0,
          total: progress.total || 1,
          percentage: progress.percentage || 0,
          message: progress.message,
          startTime: new Date()
        });
      }
    });
  }

  /**
   * 在主執行緒進行更新（回退方案）
   */
  private performMainThreadUpdate(
    options: {
      cveRecords: CveRecord[];
      cpeRecords: CpeRecord[];
      newVersion: string;
      keepRecentDays?: number;
    },
    observer: any
  ): void {
    const { cveRecords, cpeRecords, newVersion, keepRecentDays = 7 } = options;

    // 步驟 1: 清理過期資料
    observer.next({
      type: 'store',
      processed: 0,
      total: cveRecords.length + cpeRecords.length,
      percentage: 0,
      message: '正在清理過期資料...',
      startTime: new Date()
    });

    this.cleanupOldDataMainThread(keepRecentDays).then(() => {
      // 步驟 2: 儲存新資料
      const cveWithVersion = this.addVersionInfo(cveRecords, newVersion);
      const cpeWithVersion = this.addVersionInfoToCpe(cpeRecords, newVersion);

      this.storeCveRecords(cveWithVersion).subscribe({
        next: (progress) => {
          observer.next(progress);
        },
        complete: () => {
          this.storeCpeRecords(cpeWithVersion).subscribe({
            next: (progress) => {
              observer.next(progress);
            },
            complete: () => {
              observer.complete();
            },
            error: (error) => observer.error(error)
          });
        },
        error: (error) => observer.error(error)
      });
    }).catch(error => observer.error(error));
  }

  /**
   * 為 CVE 記錄加入版本資訊
   */
  private addVersionInfo(records: CveRecord[], version: string): CveRecord[] {
    const syncTimestamp = Date.now();
    
    return records.map(record => ({
      ...record,
      dataVersion: version,
      publishedYear: new Date(record.published).getFullYear(),
      syncTimestamp
    }));
  }

  /**
   * 為 CPE 記錄加入版本資訊
   */
  private addVersionInfoToCpe(records: CpeRecord[], version: string): CpeRecord[] {
    const syncTimestamp = Date.now();
    
    return records.map(record => ({
      ...record,
      dataVersion: version,
      syncTimestamp
    }));
  }

  /**
   * 主執行緒清理過期資料
   */
  private async cleanupOldDataMainThread(keepDays: number): Promise<void> {
    if (!this.db) throw new Error('資料庫尚未準備好');

    const cutoffTime = Date.now() - (keepDays * 24 * 60 * 60 * 1000);
    const transaction = this.db.transaction([this.CVE_STORE, this.CPE_STORE], 'readwrite');

    // 使用 Promise.all 並行清理
    await Promise.all([
      this.cleanupStoreByTimestamp(transaction.objectStore(this.CVE_STORE), cutoffTime),
      this.cleanupStoreByTimestamp(transaction.objectStore(this.CPE_STORE), cutoffTime)
    ]);
  }

  /**
   * 按時間戳清理 store 資料
   */
  private cleanupStoreByTimestamp(store: IDBObjectStore, cutoffTime: number): Promise<number> {
    return new Promise((resolve, reject) => {
      let deletedCount = 0;
      const index = store.index('syncTimestamp');
      const range = IDBKeyRange.upperBound(cutoffTime);
      const request = index.openCursor(range);

      request.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        if (!cursor) {
          resolve(deletedCount);
          return;
        }

        cursor.delete();
        deletedCount++;
        cursor.continue();
      };

      request.onerror = () => reject(request.error);
    });
  }

  /**
   * 按版本清理資料
   */
  clearDataByVersion(version: string): Observable<{ deletedCount: number }> {
    if (this.workerService.isWorkerAvailable()) {
      return this.workerService.deleteByVersion(version);
    } else {
      return this.clearDataByVersionMainThread(version);
    }
  }

  /**
   * 主執行緒按版本清理資料
   */
  private clearDataByVersionMainThread(version: string): Observable<{ deletedCount: number }> {
    return new Observable(observer => {
      if (!this.db) {
        observer.error(new Error('資料庫尚未準備好'));
        return;
      }

      const transaction = this.db.transaction([this.CVE_STORE, this.CPE_STORE], 'readwrite');
      let totalDeleted = 0;

      const stores = [
        { name: 'CVE', store: transaction.objectStore(this.CVE_STORE) },
        { name: 'CPE', store: transaction.objectStore(this.CPE_STORE) }
      ];

      let completedStores = 0;

      stores.forEach(({ name, store }) => {
        const index = store.index('dataVersion');
        const request = index.openCursor(IDBKeyRange.only(version));
        let storeDeleted = 0;

        request.onsuccess = (event) => {
          const cursor = (event.target as IDBRequest).result;
          if (!cursor) {
            totalDeleted += storeDeleted;
            completedStores++;
            
            if (completedStores === stores.length) {
              observer.next({ deletedCount: totalDeleted });
              observer.complete();
            }
            return;
          }

          cursor.delete();
          storeDeleted++;
          cursor.continue();
        };

        request.onerror = () => observer.error(request.error);
      });
    });
  }

  /**
   * 取得版本資訊清單
   */
  getDataVersions(): Observable<{ version: string; count: number; syncTime: number }[]> {
    return new Observable(observer => {
      if (!this.db) {
        observer.error(new Error('資料庫尚未準備好'));
        return;
      }

      const transaction = this.db.transaction([this.CVE_STORE], 'readonly');
      const store = transaction.objectStore(this.CVE_STORE);
      const index = store.index('dataVersion');
      const request = index.openCursor();

      const versions = new Map<string, { count: number; syncTime: number }>();

      request.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        if (!cursor) {
          const result = Array.from(versions.entries()).map(([version, info]) => ({
            version,
            count: info.count,
            syncTime: info.syncTime
          }));
          observer.next(result);
          observer.complete();
          return;
        }

        const record = cursor.value as CveRecord;
        const existing = versions.get(record.dataVersion);
        
        if (existing) {
          existing.count++;
          existing.syncTime = Math.max(existing.syncTime, record.syncTimestamp);
        } else {
          versions.set(record.dataVersion, {
            count: 1,
            syncTime: record.syncTimestamp
          });
        }

        cursor.continue();
      };

      request.onerror = () => observer.error(request.error);
    });
  }
}