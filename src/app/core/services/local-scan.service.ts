import { Injectable } from '@angular/core';
import { Observable, BehaviorSubject, forkJoin } from 'rxjs';
import { map, switchMap, catchError, tap } from 'rxjs/operators';
import { NvdDatabaseService } from './nvd-database.service';
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

  constructor(
    private databaseService: NvdDatabaseService,
    private syncService: NvdSyncService
  ) {}

  /**
   * 取得掃描進度
   */
  getScanProgress(): Observable<ScanProgress> {
    return this.scanProgress$.asObservable();
  }

  /**
   * 掃描單一套件漏洞
   */
  scanPackage(packageName: string, version?: string): Observable<Vulnerability[]> {
    const query: PackageVulnerabilityQuery = {
      packageName,
      version,
      searchType: 'exact' // 預設使用精確搜尋
    };

    return this.databaseService.queryPackageVulnerabilities(query).pipe(
      map(results => this.transformQueryResults(results, version)),
      catchError(error => {
        console.error(`掃描套件 ${packageName} 時發生錯誤:`, error);
        // 如果本地掃描失敗，可以選擇回退到 API 掃描
        return [];
      })
    );
  }

  /**
   * 批次掃描多個套件
   */
  scanMultiplePackages(packages: PackageInfo[]): Observable<{
    packageName: string;
    vulnerabilities: Vulnerability[];
  }[]> {
    const results: { packageName: string; vulnerabilities: Vulnerability[] }[] = [];
    const total = packages.length;
    let processed = 0;

    return new Observable(observer => {
      // 更新初始進度
      this.updateScanProgress(0, total, '準備開始掃描...');

      const scanPackage = (index: number) => {
        if (index >= packages.length) {
          observer.next(results);
          observer.complete();
          return;
        }

        const pkg = packages[index];
        const packageKey = pkg.packageKey || `${pkg.name}@${pkg.version}`;
        
        // 更新進度
        this.updateScanProgress(
          index, 
          total, 
          `正在掃描: ${pkg.name}`
        );

        this.scanPackage(pkg.name, pkg.version).subscribe({
          next: (vulnerabilities) => {
            results.push({
              packageName: packageKey,
              vulnerabilities
            });
            
            processed++;
            
            // 立即處理下一個套件（本地掃描無需延遲）
            scanPackage(index + 1);
          },
          error: (error) => {
            console.error(`掃描 ${pkg.name} 失敗:`, error);
            results.push({
              packageName: packageKey,
              vulnerabilities: []
            });
            
            processed++;
            scanPackage(index + 1);
          }
        });
      };

      scanPackage(0);
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
   * 進階掃描（使用多種搜尋策略）
   */
  advancedScanPackage(packageName: string, version?: string): Observable<Vulnerability[]> {
    const queries: PackageVulnerabilityQuery[] = [
      { packageName, version, searchType: 'exact' },
      { packageName, version, searchType: 'fuzzy' },
      { packageName, version, searchType: 'cpe' }
    ];

    const queryObservables = queries.map(query =>
      this.databaseService.queryPackageVulnerabilities(query).pipe(
        catchError(() => []) // 如果某個查詢失敗，回傳空陣列
      )
    );

    return forkJoin(queryObservables).pipe(
      map(allResults => {
        // 合併所有搜尋結果，去重
        const combinedResults = new Map<string, VulnerabilityQueryResult>();
        
        allResults.forEach(results => {
          results.forEach(result => {
            if (!combinedResults.has(result.cveId)) {
              combinedResults.set(result.cveId, result);
            }
          });
        });

        return this.transformQueryResults(Array.from(combinedResults.values()), version);
      })
    );
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

    // 如果提供了套件版本，過濾已修復的漏洞
    if (packageVersion) {
      return vulnerabilities.filter(vuln => {
        const isFixed = isVulnerabilityFixed(
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