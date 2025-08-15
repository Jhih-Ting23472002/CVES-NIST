import { Injectable } from '@angular/core';
import { Observable, BehaviorSubject, forkJoin, of } from 'rxjs';
import { map, switchMap, catchError, tap } from 'rxjs/operators';
import { NvdDatabaseService } from './nvd-database.service';
import { OptimizedQueryService } from './optimized-query.service';
import { NvdSyncService } from './nvd-sync.service';
import { 
  PackageInfo, 
  Vulnerability, 
  ScanProgress 
} from '../models/vulnerability.model';
import {
  PackageVulnerabilityQuery,
  VulnerabilityQueryResult
} from '../interfaces/nvd-database.interface';
import { isVulnerabilityFixed } from '../../shared/utils/version-utils';

@Injectable({
  providedIn: 'root'
})
export class LocalScanService {
  private readonly scanProgress$ = new BehaviorSubject<ScanProgress>({
    current: 0,
    total: 0,
    percentage: 0,
    currentPackage: ''
  });

  // 快取機制
  private readonly scanCache = new Map<string, Vulnerability[]>();
  private readonly maxCacheSize = 1000;
  private readonly cacheExpiry = 10 * 60 * 1000; // 10 分鐘過期
  private readonly cacheTimestamps = new Map<string, number>();

  // 版本比較快取
  private readonly versionComparisonCache = new Map<string, boolean>();
  private readonly versionCacheTimestamps = new Map<string, number>();
  private readonly versionCacheExpiry = 30 * 60 * 1000; // 30 分鐘過期
  private readonly maxVersionCacheSize = 200;

  // 效能統計
  private scanMetrics = {
    totalScans: 0,
    cacheHits: 0,
    cacheMisses: 0,
    versionCacheHits: 0,
    versionCacheMisses: 0,
    parallelBatches: 0,
    totalScanTime: 0,
    averageScanTime: 0,
    lastScanTime: 0,
  };

  constructor(
    private databaseService: NvdDatabaseService,
    private optimizedQueryService: OptimizedQueryService,
    private syncService: NvdSyncService
  ) {}

  /**
   * 取得掃描進度
   */
  getScanProgress(): Observable<ScanProgress> {
    return this.scanProgress$.asObservable();
  }

  /**
   * 帶快取的套件掃描方法
   */
  scanPackageWithCache(packageName: string, version?: string): Observable<Vulnerability[]> {
    const startTime = Date.now();
    const cacheKey = `${packageName}@${version || 'latest'}`;
    
    // 檢查快取
    if (this.isCacheValid(cacheKey)) {
      const cachedResult = this.scanCache.get(cacheKey);
      if (cachedResult) {
        console.log(`[LocalScan] 快取命中: ${cacheKey}`);
        this.scanMetrics.cacheHits++;
        this.scanMetrics.totalScans++;
        return of(cachedResult);
      }
    }

    // 快取未命中，執行實際掃描
    this.scanMetrics.cacheMisses++;
    this.scanMetrics.totalScans++;
    
    return this.scanPackage(packageName, version).pipe(
      tap(vulnerabilities => {
        // 更新快取
        this.updateCache(cacheKey, vulnerabilities);
        
        // 更新效能統計
        const scanTime = Date.now() - startTime;
        this.scanMetrics.lastScanTime = scanTime;
        this.scanMetrics.totalScanTime += scanTime;
        this.scanMetrics.averageScanTime = this.scanMetrics.totalScanTime / this.scanMetrics.totalScans;
      })
    );
  }

  /**
   * 檢查快取是否有效
   */
  private isCacheValid(cacheKey: string): boolean {
    if (!this.scanCache.has(cacheKey)) return false;
    
    const timestamp = this.cacheTimestamps.get(cacheKey);
    if (!timestamp) return false;
    
    const now = Date.now();
    return (now - timestamp) < this.cacheExpiry;
  }

  /**
   * 更新快取
   */
  private updateCache(cacheKey: string, vulnerabilities: Vulnerability[]): void {
    // 如果快取已滿，清理最舊的項目
    if (this.scanCache.size >= this.maxCacheSize) {
      this.cleanupOldCacheEntries();
    }

    this.scanCache.set(cacheKey, vulnerabilities);
    this.cacheTimestamps.set(cacheKey, Date.now());
  }

  /**
   * 清理過期的快取項目
   */
  private cleanupOldCacheEntries(): void {
    const now = Date.now();
    const entriesToRemove: string[] = [];
    
    for (const [key, timestamp] of this.cacheTimestamps.entries()) {
      if ((now - timestamp) > this.cacheExpiry) {
        entriesToRemove.push(key);
      }
    }
    
    // 如果沒有過期項目，移除最舊的項目
    if (entriesToRemove.length === 0) {
      const sortedEntries = Array.from(this.cacheTimestamps.entries())
        .sort(([,a], [,b]) => a - b);
      
      const removeCount = Math.floor(this.maxCacheSize * 0.1); // 移除 10% 最舊的項目
      for (let i = 0; i < removeCount && i < sortedEntries.length; i++) {
        entriesToRemove.push(sortedEntries[i][0]);
      }
    }
    
    // 清理項目
    for (const key of entriesToRemove) {
      this.scanCache.delete(key);
      this.cacheTimestamps.delete(key);
    }
    
    if (entriesToRemove.length > 0) {
      console.log(`[LocalScan] 清理了 ${entriesToRemove.length} 個過期快取項目`);
    }
  }

  /**
   * 清除所有快取
   */
  clearCache(): void {
    this.scanCache.clear();
    this.cacheTimestamps.clear();
    this.versionComparisonCache.clear();
    this.versionCacheTimestamps.clear();
    console.log('[LocalScan] 已清除所有快取');
  }

  /**
   * 快取版本比較結果
   */
  private checkVersionWithCache(
    packageVersion: string,
    affectedVersions: string[],
    fixedVersion?: string
  ): boolean {
    const cacheKey = `${packageVersion}:${JSON.stringify(affectedVersions)}:${fixedVersion || 'none'}`;
    
    // 檢查快取
    if (this.isVersionCacheValid(cacheKey)) {
      const cachedResult = this.versionComparisonCache.get(cacheKey);
      if (cachedResult !== undefined) {
        this.scanMetrics.versionCacheHits++;
        return cachedResult;
      }
    }

    // 執行實際比較
    this.scanMetrics.versionCacheMisses++;
    const result = isVulnerabilityFixed(packageVersion, affectedVersions, fixedVersion);
    
    // 更新快取
    this.updateVersionCache(cacheKey, result);
    
    return result;
  }

  /**
   * 檢查版本比較快取是否有效
   */
  private isVersionCacheValid(cacheKey: string): boolean {
    if (!this.versionComparisonCache.has(cacheKey)) return false;
    
    const timestamp = this.versionCacheTimestamps.get(cacheKey);
    if (!timestamp) return false;
    
    const now = Date.now();
    return (now - timestamp) < this.versionCacheExpiry;
  }

  /**
   * 更新版本比較快取
   */
  private updateVersionCache(cacheKey: string, result: boolean): void {
    // 如果快取已滿，清理最舊的項目
    if (this.versionComparisonCache.size >= this.maxVersionCacheSize) {
      this.cleanupOldVersionCacheEntries();
    }

    this.versionComparisonCache.set(cacheKey, result);
    this.versionCacheTimestamps.set(cacheKey, Date.now());
  }

  /**
   * 清理過期的版本比較快取項目
   */
  private cleanupOldVersionCacheEntries(): void {
    const now = Date.now();
    const entriesToRemove: string[] = [];
    
    for (const [key, timestamp] of this.versionCacheTimestamps.entries()) {
      if ((now - timestamp) > this.versionCacheExpiry) {
        entriesToRemove.push(key);
      }
    }
    
    // 如果沒有過期項目，移除最舊的項目
    if (entriesToRemove.length === 0) {
      const sortedEntries = Array.from(this.versionCacheTimestamps.entries())
        .sort(([,a], [,b]) => a - b);
      
      const removeCount = Math.floor(this.maxVersionCacheSize * 0.2); // 移除 20% 最舊的項目
      for (let i = 0; i < removeCount && i < sortedEntries.length; i++) {
        entriesToRemove.push(sortedEntries[i][0]);
      }
    }
    
    // 清理項目
    for (const key of entriesToRemove) {
      this.versionComparisonCache.delete(key);
      this.versionCacheTimestamps.delete(key);
    }
    
    if (entriesToRemove.length > 0) {
      console.log(`[LocalScan] 清理了 ${entriesToRemove.length} 個過期版本比較快取項目`);
    }
  }

  /**
   * 掃描單一套件漏洞（支援優化格式和舊格式）
   */
  scanPackage(packageName: string, version?: string): Observable<Vulnerability[]> {
    const query: PackageVulnerabilityQuery = {
      packageName,
      version,
      searchType: 'exact' // 預設使用精確搜尋
    };

    console.log(`[LocalScan] 開始掃描套件: ${packageName}@${version || 'latest'}`);

    // 優先使用優化查詢服務
    return this.optimizedQueryService.queryPackageVulnerabilitiesOptimized(query).pipe(
      map(results => {
        console.log(`[LocalScan] 優化查詢找到 ${results.length} 個結果`);
        return this.transformQueryResults(results, version);
      }),
      catchError(error => {
        console.warn(`[LocalScan] 優化查詢失敗，回退到傳統查詢:`, error);
        
        // 回退到傳統查詢服務
        return this.databaseService.queryPackageVulnerabilities(query).pipe(
          map(results => {
            console.log(`[LocalScan] 傳統查詢找到 ${results.length} 個結果`);
            return this.transformQueryResults(results, version);
          }),
          catchError(fallbackError => {
            console.error(`[LocalScan] 掃描套件 ${packageName} 失敗:`, fallbackError);
            return [];
          })
        );
      })
    );
  }

  /**
   * 批次掃描多個套件（優化版本 - 支援並行處理和快取）
   */
  scanMultiplePackages(packages: PackageInfo[]): Observable<{
    packageName: string;
    vulnerabilities: Vulnerability[];
  }[]> {
    const results: { packageName: string; vulnerabilities: Vulnerability[] }[] = [];
    const total = packages.length;

    return new Observable(observer => {
      // 更新初始進度
      this.updateScanProgress(0, total, '準備開始並行掃描...');

      // 優化：使用並行掃描取代序列掃描
      this.scanMultiplePackagesOptimized(packages).subscribe({
        next: (batchResults) => {
          results.push(...batchResults);
          observer.next(results);
          observer.complete();
        },
        error: (error) => {
          console.error('批次掃描失敗:', error);
          observer.error(error);
        }
      });
    });
  }

  /**
   * 優化的並行掃描實作
   */
  private scanMultiplePackagesOptimized(packages: PackageInfo[]): Observable<{
    packageName: string;
    vulnerabilities: Vulnerability[];
  }[]> {
    return new Observable(observer => {
      const batchSize = 8; // 並行批次大小，避免過度並行造成資源競爭
      const batches: PackageInfo[][] = [];
      
      // 將套件分組為批次
      for (let i = 0; i < packages.length; i += batchSize) {
        batches.push(packages.slice(i, i + batchSize));
      }

      console.log(`[LocalScan] 將 ${packages.length} 個套件分為 ${batches.length} 個批次進行並行掃描`);
      this.scanMetrics.parallelBatches = batches.length;

      // 依序處理每個批次（批次內並行，批次間序列）
      this.processBatchesSequentially(batches, 0, []).subscribe({
        next: (results) => {
          observer.next(results);
          observer.complete();
        },
        error: (error) => observer.error(error)
      });
    });
  }

  /**
   * 依序處理批次（批次內並行處理）
   */
  private processBatchesSequentially(
    batches: PackageInfo[][],
    batchIndex: number,
    accumulatedResults: { packageName: string; vulnerabilities: Vulnerability[] }[]
  ): Observable<{ packageName: string; vulnerabilities: Vulnerability[] }[]> {
    return new Observable(observer => {
      if (batchIndex >= batches.length) {
        observer.next(accumulatedResults);
        observer.complete();
        return;
      }

      const currentBatch = batches[batchIndex];
      const startIndex = batchIndex * 8;
      
      console.log(`[LocalScan] 處理批次 ${batchIndex + 1}/${batches.length}，包含 ${currentBatch.length} 個套件`);

      // 更新進度
      this.updateScanProgress(
        startIndex, 
        batches.length * 8, 
        `批次 ${batchIndex + 1}/${batches.length}：並行掃描 ${currentBatch.length} 個套件`
      );

      // 批次內並行處理
      const scanObservables = currentBatch.map(pkg => {
        const packageKey = pkg.packageKey || `${pkg.name}@${pkg.version}`;
        return this.scanPackageWithCache(pkg.name, pkg.version).pipe(
          map(vulnerabilities => ({
            packageName: packageKey,
            vulnerabilities
          })),
          catchError(error => {
            console.error(`掃描 ${pkg.name} 失敗:`, error);
            return [{
              packageName: packageKey,
              vulnerabilities: []
            }];
          })
        );
      });

      // 等待當前批次完成
      forkJoin(scanObservables).subscribe({
        next: (batchResults) => {
          const newAccumulatedResults = [...accumulatedResults, ...batchResults];
          
          // 處理下一個批次
          this.processBatchesSequentially(batches, batchIndex + 1, newAccumulatedResults).subscribe({
            next: (finalResults) => observer.next(finalResults),
            error: (error) => observer.error(error)
          });
        },
        error: (error) => {
          console.error(`批次 ${batchIndex + 1} 處理失敗:`, error);
          observer.error(error);
        }
      });
    });
  }

  /**
   * 批次掃描多個套件（支援進度回報）
   */
  scanMultiplePackagesWithProgress(packages: PackageInfo[]): Observable<{
    type: 'progress' | 'result' | 'error';
    progress?: ScanProgress;
    results?: { packageName: string; vulnerabilities: Vulnerability[] }[];
    error?: string;
  }> {
    const results: { packageName: string; vulnerabilities: Vulnerability[] }[] = [];
    const total = packages.length;

    return new Observable(observer => {
      const scanPackage = (index: number) => {
        if (index >= packages.length) {
          observer.next({
            type: 'result',
            results: results
          });
          observer.complete();
          return;
        }

        const pkg = packages[index];
        const packageKey = pkg.packageKey || `${pkg.name}@${pkg.version}`;
        
        // 發送進度更新
        const progress: ScanProgress = {
          current: index,
          total: total,
          percentage: (index / total) * 100,
          currentPackage: pkg.name
        };

        this.updateScanProgress(index, total, `正在掃描: ${pkg.name}`);
        
        observer.next({
          type: 'progress',
          progress: progress
        });

        this.scanPackage(pkg.name, pkg.version).subscribe({
          next: (vulnerabilities) => {
            results.push({
              packageName: packageKey,
              vulnerabilities
            });

            // 本地掃描很快，可以立即處理下一個
            scanPackage(index + 1);
          },
          error: (error) => {
            console.error(`掃描 ${pkg.name} 失敗:`, error);
            results.push({
              packageName: packageKey,
              vulnerabilities: []
            });

            observer.next({
              type: 'error',
              error: `掃描 ${pkg.name} 失敗: ${error.message}`
            });

            scanPackage(index + 1);
          }
        });
      };

      scanPackage(0);
    });
  }

  /**
   * 進階掃描（使用多種搜尋策略，支援優化格式）
   */
  advancedScanPackage(packageName: string, version?: string): Observable<Vulnerability[]> {
    const queries: PackageVulnerabilityQuery[] = [
      { packageName, version, searchType: 'exact' },
      { packageName, version, searchType: 'fuzzy' },
      { packageName, version, searchType: 'cpe' }
    ];

    console.log(`[LocalScan] 開始進階掃描套件: ${packageName}@${version || 'latest'}`);

    // 優先使用優化查詢服務進行多策略搜尋
    const optimizedQueryObservables = queries.map(query =>
      this.optimizedQueryService.queryPackageVulnerabilitiesOptimized(query).pipe(
        catchError(error => {
          console.warn(`[LocalScan] 優化查詢策略 ${query.searchType} 失敗:`, error);
          // 回退到傳統查詢
          return this.databaseService.queryPackageVulnerabilities(query).pipe(
            catchError(() => [])
          );
        })
      )
    );

    return forkJoin(optimizedQueryObservables).pipe(
      map(allResults => {
        // 合併所有搜尋結果，去重
        const combinedResults = new Map<string, VulnerabilityQueryResult>();
        
        allResults.forEach((results, index) => {
          console.log(`[LocalScan] 策略 ${queries[index].searchType} 找到 ${results.length} 個結果`);
          results.forEach(result => {
            const existingResult = combinedResults.get(result.cveId);
            if (!existingResult || this.shouldReplaceResult(existingResult, result)) {
              combinedResults.set(result.cveId, result);
            }
          });
        });

        const finalResults = Array.from(combinedResults.values());
        console.log(`[LocalScan] 進階掃描總共找到 ${finalResults.length} 個去重後的結果`);
        
        return this.transformQueryResults(finalResults, version);
      })
    );
  }

  /**
   * 判斷是否應該替換現有結果（優先選擇信心分數更高的結果）
   */
  private shouldReplaceResult(existing: VulnerabilityQueryResult, newResult: VulnerabilityQueryResult): boolean {
    // 優先選擇精確匹配
    if (newResult.matchReason.includes('exact') && !existing.matchReason.includes('exact')) {
      return true;
    }
    
    // 優先選擇 CPE 匹配
    if (newResult.matchReason.includes('cpe') && existing.matchReason.includes('fuzzy')) {
      return true;
    }
    
    return false;
  }

  /**
   * 檢查本地資料庫是否準備好
   */
  isDatabaseReady(): Observable<boolean> {
    return this.databaseService.isReady().pipe(
      switchMap(isReady => {
        console.log('資料庫連線狀態:', isReady);
        if (!isReady) return [false];
        
        // 檢查是否有資料
        return this.databaseService.getDatabaseStats().pipe(
          map(stats => {
            console.log('資料庫統計:', stats);
            // 資料庫準備好且有資料才算可用
            const hasData = stats.totalCveCount > 0 || stats.totalCpeCount > 0;
            console.log('本地資料庫可用:', hasData);
            return hasData;
          }),
          catchError(error => {
            console.warn('檢查資料庫狀態失敗:', error);
            return [false];
          })
        );
      }),
      catchError(error => {
        console.warn('檢查資料庫準備狀態失敗:', error);
        return [false];
      })
    );
  }

  /**
   * 取得資料庫統計資訊
   */
  getDatabaseStats() {
    return this.syncService.getDatabaseStats();
  }

  /**
   * 強制同步資料庫
   */
  syncDatabase() {
    return this.syncService.forceSyncNow();
  }

  /**
   * 取得同步狀態
   */
  getSyncStatus() {
    return this.syncService.getSyncStatus();
  }


  /**
   * 轉換查詢結果為內部格式（與 API 掃描保持一致）
   * 加入版本比較邏輯，過濾已修復的漏洞
   */
  private transformQueryResults(results: VulnerabilityQueryResult[], packageVersion?: string): Vulnerability[] {
    const vulnerabilities = results.map(result => ({
      cveId: result.cveId,
      description: result.description,
      severity: result.severity,
      cvssScore: result.cvssScore,
      cvssVector: this.extractCvssVector(result), // 從資料庫提取 CVSS Vector
      publishedDate: result.publishedDate,
      lastModifiedDate: result.lastModifiedDate,
      references: result.references,
      affectedVersions: result.affectedVersions,
      fixedVersion: result.fixedVersion,
      // 新增欄位以支援本地掃描的額外資訊
      matchReason: result.matchReason
    } as Vulnerability & { matchReason: string }));

    // 如果提供了套件版本，過濾已修復的漏洞（使用快取優化）
    if (packageVersion) {
      return vulnerabilities.filter(vuln => {
        const isFixed = this.checkVersionWithCache(
          packageVersion,
          vuln.affectedVersions,
          vuln.fixedVersion
        );
        
        // 記錄過濾資訊
        if (isFixed) {
          console.log(`漏洞 ${vuln.cveId} 在版本 ${packageVersion} 中已修復`);
        }
        
        return !isFixed; // 只返回尚未修復的漏洞
      });
    }

    return vulnerabilities;
  }

  /**
   * 更新掃描進度
   */
  private updateScanProgress(current: number, total: number, currentPackage: string): void {
    const progress: ScanProgress = {
      current,
      total,
      percentage: total > 0 ? (current / total) * 100 : 0,
      currentPackage
    };
    
    this.scanProgress$.next(progress);
  }

  /**
   * 從查詢結果提取 CVSS Vector（如果有的話）
   */
  private extractCvssVector(result: VulnerabilityQueryResult): string {
    // 現在 VulnerabilityQueryResult 已經包含 cvssVector 欄位
    return result.cvssVector || '';
  }

  /**
   * 比較本地掃描與 API 掃描結果（測試用）
   */
  compareWithApiScan(packageName: string, apiResults: Vulnerability[]): Observable<{
    localOnly: Vulnerability[];
    apiOnly: Vulnerability[];
    common: Vulnerability[];
    accuracy: number;
  }> {
    return this.scanPackage(packageName).pipe(
      map(localResults => {
        const localCveIds = new Set(localResults.map(v => v.cveId));
        const apiCveIds = new Set(apiResults.map(v => v.cveId));
        
        const localOnly = localResults.filter(v => !apiCveIds.has(v.cveId));
        const apiOnly = apiResults.filter(v => !localCveIds.has(v.cveId));
        const common = localResults.filter(v => apiCveIds.has(v.cveId));
        
        // 計算準確度（共同發現的 / 總數）
        const totalUnique = new Set([...localCveIds, ...apiCveIds]).size;
        const accuracy = totalUnique > 0 ? (common.length / totalUnique) * 100 : 0;
        
        return { localOnly, apiOnly, common, accuracy };
      })
    );
  }

  /**
   * 取得效能統計資訊
   */
  getPerformanceMetrics() {
    return {
      ...this.scanMetrics,
      cacheHitRate: this.scanMetrics.totalScans > 0 ? 
        (this.scanMetrics.cacheHits / this.scanMetrics.totalScans * 100).toFixed(2) + '%' : '0%',
      versionCacheHitRate: (this.scanMetrics.versionCacheHits + this.scanMetrics.versionCacheMisses) > 0 ?
        (this.scanMetrics.versionCacheHits / (this.scanMetrics.versionCacheHits + this.scanMetrics.versionCacheMisses) * 100).toFixed(2) + '%' : '0%',
      cacheStatus: {
        scanCacheSize: this.scanCache.size,
        maxScanCacheSize: this.maxCacheSize,
        versionCacheSize: this.versionComparisonCache.size,
        maxVersionCacheSize: this.maxVersionCacheSize,
      }
    };
  }

  /**
   * 重置效能統計
   */
  resetPerformanceMetrics(): void {
    this.scanMetrics = {
      totalScans: 0,
      cacheHits: 0,
      cacheMisses: 0,
      versionCacheHits: 0,
      versionCacheMisses: 0,
      parallelBatches: 0,
      totalScanTime: 0,
      averageScanTime: 0,
      lastScanTime: 0,
    };
    console.log('[LocalScan] 效能統計已重置');
  }

  /**
   * 取得套件的風險評估
   */
  getPackageRiskAssessment(packageName: string, version?: string): Observable<{
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    riskScore: number;
    vulnerabilityCount: number;
    highestSeverity: string;
    recommendedActions: string[];
  }> {
    return this.scanPackage(packageName, version).pipe(
      map(vulnerabilities => {
        const severityCounts = {
          CRITICAL: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
          HIGH: vulnerabilities.filter(v => v.severity === 'HIGH').length,
          MEDIUM: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
          LOW: vulnerabilities.filter(v => v.severity === 'LOW').length
        };

        // 計算風險分數 (0-100)
        let riskScore = 0;
        riskScore += severityCounts.CRITICAL * 25;
        riskScore += severityCounts.HIGH * 15;
        riskScore += severityCounts.MEDIUM * 8;
        riskScore += severityCounts.LOW * 3;
        riskScore = Math.min(100, riskScore); // 最高 100

        // 決定風險等級
        let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
        if (severityCounts.CRITICAL > 0 || riskScore >= 80) {
          riskLevel = 'CRITICAL';
        } else if (severityCounts.HIGH > 0 || riskScore >= 50) {
          riskLevel = 'HIGH';
        } else if (severityCounts.MEDIUM > 0 || riskScore >= 20) {
          riskLevel = 'MEDIUM';
        } else {
          riskLevel = 'LOW';
        }

        // 取得最高嚴重程度
        const highestSeverity = severityCounts.CRITICAL > 0 ? 'CRITICAL' :
                               severityCounts.HIGH > 0 ? 'HIGH' :
                               severityCounts.MEDIUM > 0 ? 'MEDIUM' :
                               severityCounts.LOW > 0 ? 'LOW' : 'NONE';

        // 建議行動
        const recommendedActions: string[] = [];
        if (severityCounts.CRITICAL > 0) {
          recommendedActions.push('立即更新套件到安全版本');
          recommendedActions.push('考慮尋找替代套件');
        }
        if (severityCounts.HIGH > 0) {
          recommendedActions.push('儘快更新套件');
          recommendedActions.push('檢查是否有安全補丁');
        }
        if (severityCounts.MEDIUM > 0) {
          recommendedActions.push('計劃更新套件');
        }
        if (vulnerabilities.length === 0) {
          recommendedActions.push('繼續監控安全更新');
        }

        return {
          riskLevel,
          riskScore,
          vulnerabilityCount: vulnerabilities.length,
          highestSeverity,
          recommendedActions
        };
      })
    );
  }
}

// 測試用
function testLocalScan() {
  const mockDatabaseService = {
    queryPackageVulnerabilities: (query: any) => {
      console.log('Mock DB 查詢:', query);
      return new Observable(obs => {
        setTimeout(() => {
          if (query.packageName === 'react') {
            obs.next([
              { cveId: 'CVE-2023-1234', description: 'XSS in React', severity: 'HIGH', cvssScore: 7.5, affectedVersions: ['<18.0.0'], fixedVersion: '18.0.0' },
              { cveId: 'CVE-2023-5678', description: 'DoS in React', severity: 'MEDIUM', cvssScore: 5.3, affectedVersions: ['<17.0.2'], fixedVersion: '17.0.2' }
            ]);
          } else {
            obs.next([]);
          }
          obs.complete();
        }, 500);
      });
    },
    isReady: () => new Observable(obs => { obs.next(true); obs.complete(); }),
    getDatabaseStats: () => new Observable(obs => { obs.next({ totalCveCount: 1000, totalCpeCount: 2000 }); obs.complete(); })
  } as any;

  const mockOptimizedQueryService = {
    queryPackageVulnerabilitiesOptimized: (query: any) => {
      console.log('Mock Optimized Query:', query);
      return new Observable(obs => {
        setTimeout(() => {
          if (query.packageName === 'react') {
            obs.next([
              { cveId: 'CVE-2023-1234', description: 'XSS in React', severity: 'HIGH', cvssScore: 7.5, affectedVersions: ['<18.0.0'], fixedVersion: '18.0.0', matchReason: 'exact' },
              { cveId: 'CVE-2023-5678', description: 'DoS in React', severity: 'MEDIUM', cvssScore: 5.3, affectedVersions: ['<17.0.2'], fixedVersion: '17.0.2', matchReason: 'exact' }
            ]);
          } else {
            obs.next([]);
          }
          obs.complete();
        }, 200);
      });
    }
  } as any;

  const mockSyncService = {
    getDatabaseStats: () => new Observable(obs => { obs.next({ totalCveCount: 1000, totalCpeCount: 2000, lastSyncTime: new Date() }); obs.complete(); }),
    forceSyncNow: () => new Observable(obs => { obs.next({ status: 'completed', message: 'Sync successful' }); obs.complete(); }),
    getSyncStatus: () => new Observable(obs => { obs.next({ status: 'idle', lastSyncTime: new Date() }); obs.complete(); })
  } as any;

  const scanService = new LocalScanService(mockDatabaseService, mockOptimizedQueryService, mockSyncService);

  // 測試單一套件掃描
  scanService.scanPackage('react', '16.8.0').subscribe(results => {
    console.log('React 16.8.0 掃描結果:', results);
  });

  // 測試批次掃描
  const packagesToScan: PackageInfo[] = [
    { name: 'react', version: '17.0.1', type: 'dependency' },
    { name: 'angular', version: '12.0.0', type: 'dependency' }
  ];
  scanService.scanMultiplePackages(packagesToScan).subscribe(results => {
    console.log('批次掃描結果:', results);
  });

  // 測試進階掃描
  scanService.advancedScanPackage('react', '17.0.1').subscribe(results => {
    console.log('進階掃描結果:', results);
  });

  // 測試風險評估
  scanService.getPackageRiskAssessment('react', '16.8.0').subscribe(assessment => {
    console.log('React 16.8.0 風險評估:', assessment);
  });
}

// testLocalScan();