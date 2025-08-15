import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { OptimizedCveRecord } from '../interfaces/optimized-storage.interface';
import { 
  PackageVulnerabilityQuery,
  VulnerabilityQueryResult 
} from '../interfaces/nvd-database.interface';

@Injectable({
  providedIn: 'root'
})
export class OptimizedQueryService {
  private readonly DB_NAME = 'NvdLocalDatabase';
  private readonly CVE_STORE = 'cve';
  private db: IDBDatabase | null = null;

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
    const request = store.openCursor();

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (!cursor) {
        observer.next(results);
        observer.complete();
        return;
      }

      const record = cursor.value;
      
      // 檢查是否為優化格式
      if (this.isOptimizedRecord(record)) {
        const optimizedRecord = record as OptimizedCveRecord;
        
        // 在優化產品資訊中搜尋
        for (const productInfo of optimizedRecord.optimizedProductInfo) {
          if (this.isProductMatch(productInfo, query.packageName, 'exact')) {
            if (this.isVersionAffectedOptimized(productInfo, query.version)) {
              results.push(this.transformOptimizedCveToResult(
                optimizedRecord, 
                productInfo, 
                'exact_match'
              ));
              break; // 避免重複加入同一個 CVE
            }
          }
        }
      } else {
        // 回退到舊格式處理
        this.handleLegacyRecord(record, query, results, 'exact_match');
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
    const request = store.openCursor();

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (!cursor) {
        observer.next(results);
        observer.complete();
        return;
      }

      const record = cursor.value;
      
      if (this.isOptimizedRecord(record)) {
        const optimizedRecord = record as OptimizedCveRecord;
        
        for (const productInfo of optimizedRecord.optimizedProductInfo) {
          if (this.isProductMatch(productInfo, query.packageName, 'fuzzy')) {
            if (this.isVersionAffectedOptimized(productInfo, query.version)) {
              results.push(this.transformOptimizedCveToResult(
                optimizedRecord, 
                productInfo, 
                'fuzzy_match'
              ));
              break;
            }
          }
        }
      } else {
        this.handleLegacyRecord(record, query, results, 'fuzzy_match');
      }

      cursor.continue();
    };

    request.onerror = () => observer.error(request.error);
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
    const request = store.openCursor();

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (!cursor) {
        observer.next(results);
        observer.complete();
        return;
      }

      const record = cursor.value;
      
      if (this.isOptimizedRecord(record)) {
        const optimizedRecord = record as OptimizedCveRecord;
        
        for (const productInfo of optimizedRecord.optimizedProductInfo) {
          // 檢查 CPE 資訊
          if (productInfo.cpeInfo && this.isCpeMatch(productInfo.cpeInfo.cpeName, query.packageName)) {
            if (this.isVersionAffectedOptimized(productInfo, query.version)) {
              results.push(this.transformOptimizedCveToResult(
                optimizedRecord, 
                productInfo, 
                'cpe_match'
              ));
              break;
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
    const request = store.openCursor();

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;
      if (!cursor) {
        observer.next(results);
        observer.complete();
        return;
      }

      const record = cursor.value;
      
      if (this.isOptimizedRecord(record)) {
        const optimizedRecord = record as OptimizedCveRecord;
        
        for (const productInfo of optimizedRecord.optimizedProductInfo) {
          let matchType = '';
          let isMatch = false;

          // 嘗試多種匹配方式
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

          if (isMatch && this.isVersionAffectedOptimized(productInfo, query.version)) {
            results.push(this.transformOptimizedCveToResult(
              optimizedRecord, 
              productInfo, 
              matchType
            ));
            break;
          }
        }
      } else {
        this.handleLegacyRecord(record, query, results, 'combined_match');
      }

      cursor.continue();
    };

    request.onerror = () => observer.error(request.error);
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
    const versionParts = this.parseVersion(version);
    const constraintParts = this.parseVersion(constraint.version);
    const comparison = this.compareVersions(versionParts, constraintParts);

    switch (constraint.type) {
      case 'lt':
        return comparison < 0;
      case 'lte':
        return comparison <= 0;
      case 'gt':
        return comparison > 0;
      case 'gte':
        return comparison >= 0;
      case 'eq':
        return comparison === 0;
      case 'range':
        const startComparison = this.compareVersions(versionParts, this.parseVersion(constraint.version));
        const endComparison = this.compareVersions(versionParts, this.parseVersion(constraint.endVersion));
        
        const startSatisfied = constraint.includeStart ? startComparison >= 0 : startComparison > 0;
        const endSatisfied = constraint.includeEnd ? endComparison <= 0 : endComparison < 0;
        
        return startSatisfied && endSatisfied;
      default:
        return true;
    }
  }

  /**
   * 檢查 CPE 是否匹配
   */
  private isCpeMatch(cpeName: string, packageName: string): boolean {
    if (!cpeName) return false;
    
    const lowerCpeName = cpeName.toLowerCase();
    const lowerPackageName = packageName.toLowerCase();
    
    return lowerCpeName.includes(lowerPackageName);
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
          if (constraint.type === 'lt' || constraint.type === 'lte') {
            versions.push(`< ${constraint.version}`);
          } else if (constraint.type === 'range') {
            versions.push(`${constraint.version} - ${constraint.endVersion}`);
          } else if (constraint.type === 'eq') {
            versions.push(constraint.version);
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
    if (productInfo.versionRanges) {
      for (const range of productInfo.versionRanges) {
        for (const constraint of range.versionConstraints) {
          if (constraint.type === 'lt' || constraint.type === 'lte') {
            return constraint.version; // < x.y.z or <= x.y.z indicates x.y.z is a fixed version
          }
        }
      }
    }
    
    return undefined;
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

  // 重用現有的版本解析和比較方法
  private parseVersion(version: string): number[] {
    return version.split(/[.-]/).map(part => {
      const num = parseInt(part, 10);
      return isNaN(num) ? 0 : num;
    });
  }

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
}