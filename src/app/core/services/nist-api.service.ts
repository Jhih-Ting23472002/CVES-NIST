import { Injectable, OnDestroy } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable, throwError, of } from 'rxjs';
import { map, catchError, tap, switchMap } from 'rxjs/operators';
import {
  NistApiResponse,
  NistApiParams,
  RateLimitInfo,
  CpeApiResponse,
  CpeApiParams,
  CpeItem
} from '../interfaces/nist-api.interface';
import { Vulnerability, PackageInfo } from '../models/vulnerability.model';
import { CacheService } from './cache.service';
import { LocalScanService } from './local-scan.service';

@Injectable({
  providedIn: 'root'
})
export class NistApiService implements OnDestroy {
  private readonly NIST_CVE_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private readonly NIST_CPE_API_URL = 'https://services.nvd.nist.gov/rest/json/cpes/2.0';
  private readonly REQUEST_DELAY = 12000; // 12秒延遲確保符合 NIST API 限制 (每個套件需要2個API請求，所以6*2=12秒)
  private readonly MAX_REQUESTS_PER_MINUTE = 10;
  private readonly RATE_LIMIT_WINDOW = 60000; // 1分鐘窗口

  private requestQueue: Date[] = []; // 追蹤最近的請求時間
  private cleanupInterval: any; // 定期清理過期請求的定時器
  private cpeCache: Map<string, string[]> = new Map(); // CPE 名稱快取

  constructor(
    private http: HttpClient,
    private cacheService: CacheService,
    private localScanService: LocalScanService
  ) {
    // 每30秒清理一次過期請求記錄
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredRequests();
    }, 30000);
  }

  /**
   * 搜尋特定套件的 CVE 漏洞（自動選擇本地或 API 掃描）
   */
  searchVulnerabilities(packageName: string, version?: string): Observable<Vulnerability[]> {
    console.log(`[NIST API] 開始掃描套件: ${packageName}@${version || '*'}`);
    
    // 優先使用本地資料庫掃描
    return this.localScanService.isDatabaseReady().pipe(
      switchMap(isLocalReady => {
        console.log(`[NIST API] 本地資料庫可用性檢查結果: ${isLocalReady}`);
        
        if (isLocalReady) {
          console.log(`[NIST API] ✅ 使用本地資料庫掃描 ${packageName}`);
          return this.localScanService.scanPackage(packageName, version).pipe(
            tap(results => {
              console.log(`[NIST API] 本地掃描結果: 找到 ${results.length} 個漏洞`);
            }),
            catchError(localError => {
              console.warn(`[NIST API] ⚠️ 本地掃描失敗，回退到 API 掃描:`, localError);
              return this.performApiScan(packageName, version);
            })
          );
        } else {
          console.log(`[NIST API] ⚠️ 本地資料庫未就緒，使用 API 掃描 ${packageName}`);
          return this.performApiScan(packageName, version);
        }
      })
    );
  }

  /**
   * 執行 API 掃描（原有邏輯）
   */
  private performApiScan(packageName: string, version?: string): Observable<Vulnerability[]> {
    // 檢查快取
    const cacheKey = CacheService.createVulnerabilityKey(packageName, version || '', true);
    const cachedResult = this.cacheService.get<Vulnerability[]>(cacheKey);

    if (cachedResult) {
      console.log(`從快取取得 ${packageName} 的漏洞資料`);
      return new Observable(observer => {
        observer.next(cachedResult);
        observer.complete();
      });
    }

    // 步驟 1: 先查詢 CPE API 獲取正確的 CPE 名稱
    return this.searchCpeNames(packageName, version).pipe(
      switchMap(cpeNames => {
        if (cpeNames.length === 0) {
          console.log(`未找到 ${packageName} 的 CPE 名稱，使用關鍵字搜尋`);
          // 如果找不到 CPE，則使用關鍵字搜尋
          const searchKeyword = version ? `${packageName} ${version}` : packageName;
          return this.searchVulnerabilitiesByKeyword(searchKeyword);
        }
        
        console.log(`找到 ${cpeNames.length} 個 CPE 名稱，開始查詢 CVE`);
        // 步驟 2: 使用 CPE 名稱查詢 CVE API
        return this.searchVulnerabilitiesByCpe(cpeNames);
      }),
      tap(vulnerabilities => {
        // 快取結果
        this.cacheService.set(cacheKey, vulnerabilities, 24 * 60 * 60 * 1000); // 24小時
        console.log(`快取 ${packageName} 的 ${vulnerabilities.length} 個漏洞資料`);
      }),
      catchError(error => {
        console.error(`搜尋 ${packageName} 漏洞時發生錯誤:`, error);
        return throwError(() => new Error(`無法取得 ${packageName} 的漏洞資訊: ${error.message}`));
      })
    );
  }

  /**
   * 批次搜尋多個套件的漏洞
   */
  searchMultiplePackages(packages: PackageInfo[]): Observable<{packageName: string, vulnerabilities: Vulnerability[]}[]> {
    const results: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];

    return new Observable(observer => {
      const processPackage = (index: number) => {
        if (index >= packages.length) {
          observer.next(results);
          observer.complete();
          return;
        }

        const pkg = packages[index];
        console.log(`正在掃描套件 ${index + 1}/${packages.length}: ${pkg.name}`);

        this.searchVulnerabilities(pkg.name, pkg.version).subscribe({
          next: (vulnerabilities) => {
            results.push({
              packageName: pkg.packageKey || `${pkg.name}@${pkg.version}`,
              vulnerabilities
            });

            // 延遲後處理下一個套件以符合 API 限制
            setTimeout(() => processPackage(index + 1), this.REQUEST_DELAY);
          },
          error: (error) => {
            console.error(`掃描 ${pkg.name} 失敗:`, error);
            results.push({
              packageName: pkg.packageKey || `${pkg.name}@${pkg.version}`,
              vulnerabilities: []
            });

            // 即使發生錯誤也繼續處理下一個套件
            setTimeout(() => processPackage(index + 1), this.REQUEST_DELAY);
          }
        });
      };

      processPackage(0);
    });
  }

  /**
   * 批次搜尋多個套件的漏洞，支援進度回報（自動選擇本地或 API 掃描）
   */
  searchMultiplePackagesWithProgress(packages: PackageInfo[]): Observable<{
    type: 'progress' | 'result' | 'error',
    progress?: { current: number, total: number, currentPackage: string },
    results?: {packageName: string, vulnerabilities: Vulnerability[]}[],
    error?: string
  }> {
    // 檢查是否可以使用本地掃描
    return this.localScanService.isDatabaseReady().pipe(
      switchMap(isLocalReady => {
        if (isLocalReady) {
          console.log('使用本地資料庫批次掃描');
          return this.localScanService.scanMultiplePackagesWithProgress(packages).pipe(
            catchError(localError => {
              console.warn('本地批次掃描失敗，回退到 API 掃描:', localError);
              return this.performApiBatchScan(packages);
            })
          );
        } else {
          console.log('本地資料庫未就緒，使用 API 批次掃描');
          return this.performApiBatchScan(packages);
        }
      })
    );
  }

  /**
   * 執行 API 批次掃描（原有邏輯）
   */
  private performApiBatchScan(packages: PackageInfo[]): Observable<{
    type: 'progress' | 'result' | 'error',
    progress?: { current: number, total: number, currentPackage: string },
    results?: {packageName: string, vulnerabilities: Vulnerability[]}[],
    error?: string
  }> {
    const results: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];

    return new Observable(observer => {
      let timeoutIds: any[] = []; // 記錄所有的 timeout ID
      let cancelled = false; // 取消標誌

      const processPackage = (index: number, retryCount: number = 0) => {
        // 檢查是否已取消
        if (cancelled) {
          observer.complete();
          return;
        }
        if (index >= packages.length) {
          observer.next({
            type: 'result',
            results: results
          });
          observer.complete();
          return;
        }

        const pkg = packages[index];

        // 發送進度更新
        observer.next({
          type: 'progress',
          progress: {
            current: index,
            total: packages.length,
            currentPackage: pkg.name
          }
        });

        console.log(`正在掃描套件 ${index + 1}/${packages.length}: ${pkg.name}`);

        this.performApiScan(pkg.name, pkg.version).subscribe({
          next: (vulnerabilities) => {
            results.push({
              packageName: pkg.packageKey || `${pkg.name}@${pkg.version}`,
              vulnerabilities
            });

            // 延遲後處理下一個套件以符合 API 限制
            const timeoutId = setTimeout(() => processPackage(index + 1), this.REQUEST_DELAY);
            timeoutIds.push(timeoutId);
          },
          error: (error) => {
            const errorMessage = error.message || error.toString();
            console.error(`掃描 ${pkg.name} 失敗:`, errorMessage);

            // 如果是 API 限制錯誤且重試次數少於 3 次，則重試
            if (errorMessage.includes('API 請求限制已達上限') && retryCount < 3) {
              const waitTime = this.extractWaitTimeFromError(errorMessage);
              console.log(`等待 ${waitTime} 秒後重試 ${pkg.name}...`);

              observer.next({
                type: 'progress',
                progress: {
                  current: index,
                  total: packages.length,
                  currentPackage: `等待 API 限制重置中... (${waitTime}秒)`
                }
              });

              const retryTimeoutId = setTimeout(() => {
                processPackage(index, retryCount + 1);
              }, waitTime * 1000);
              timeoutIds.push(retryTimeoutId);
              return;
            }

            // 其他錯誤或重試次數過多，記錄為空結果並繼續
            results.push({
              packageName: pkg.packageKey || `${pkg.name}@${pkg.version}`,
              vulnerabilities: []
            });

            // 繼續處理下一個套件
            const continueTimeoutId = setTimeout(() => processPackage(index + 1), this.REQUEST_DELAY);
            timeoutIds.push(continueTimeoutId);
          }
        });
      };

      processPackage(0);

      // 返回清理函數，當 Observable 被取消時執行
      return () => {
        cancelled = true;
        // 清理所有的 timeout
        timeoutIds.forEach(id => clearTimeout(id));
        timeoutIds = [];
        console.log('掃描已暫停，清理所有待處理的請求');
      };
    });
  }

  /**
   * 從錯誤訊息中提取等待時間
   */
  private extractWaitTimeFromError(errorMessage: string): number {
    const match = errorMessage.match(/請等待 (\d+) 秒後重試/);
    return match ? parseInt(match[1], 10) : 30; // 預設等待 30 秒
  }

  /**
   * 取得 API 限制資訊
   */
  getRateLimitInfo(): RateLimitInfo {
    this.cleanupExpiredRequests();

    let resetTime = new Date();
    if (this.requestQueue.length > 0) {
      // 使用最舊請求的時間加上窗口時間來計算重置時間
      const oldestRequest = Math.min(...this.requestQueue.map(t => t.getTime()));
      resetTime = new Date(oldestRequest + this.RATE_LIMIT_WINDOW);
    }

    return {
      requestsRemaining: Math.max(0, this.MAX_REQUESTS_PER_MINUTE - this.requestQueue.length),
      resetTime: resetTime,
      requestsMade: this.requestQueue.length,
      maxRequests: this.MAX_REQUESTS_PER_MINUTE,
      timeWindow: this.RATE_LIMIT_WINDOW
    };
  }

  /**
   * 清理過期的請求記錄
   */
  private cleanupExpiredRequests(): void {
    const now = new Date();
    const cutoff = new Date(now.getTime() - this.RATE_LIMIT_WINDOW);
    this.requestQueue = this.requestQueue.filter(time => time > cutoff);
  }

  /**
   * 查詢 CPE API 獲取 CPE 名稱 (加入快取)
   */
  private searchCpeNames(packageName: string, version?: string): Observable<string[]> {
    const searchKeyword = version ? `${packageName} ${version}` : packageName;
    const cacheKey = `cpe_${packageName}_${version || 'all'}`;
    
    // 檢查 CPE 快取
    if (this.cpeCache.has(cacheKey)) {
      console.log(`從 CPE 快取取得 ${packageName} 的 CPE 名稱`);
      return of(this.cpeCache.get(cacheKey)!);
    }
    
    const params: CpeApiParams = {
      keywordSearch: searchKeyword,
      resultsPerPage: 50 // 限制結果數量
    };

    return this.makeCpeApiRequest(params).pipe(
      map(response => {
        console.log(`CPE API 回應: 找到 ${response.totalResults} 筆 CPE 記錄`);
        const cpeNames = response.products
          .map(item => item.cpe.cpeName)
          .filter(cpeName => this.isCpeRelevant(cpeName, packageName));
        
        // 快取 CPE 名稱 
        this.cpeCache.set(cacheKey, cpeNames);
        return cpeNames;
      }),
      catchError(error => {
        console.error(`CPE API 查詢失敗:`, error);
        return of([]); // 返回空陣列而不是錯誤
      })
    );
  }

  /**
   * 使用 CPE 名稱查詢 CVE
   */
  private searchVulnerabilitiesByCpe(cpeNames: string[]): Observable<Vulnerability[]> {
    // 使用第一個 CPE 名稱查詢（或者可以合併多個查詢）
    const primaryCpe = cpeNames[0];
    
    const params: NistApiParams = {
      cpeName: primaryCpe,
      resultsPerPage: 2000,
      noRejected: true
    };

    return this.makeApiRequest(params).pipe(
      map(response => this.transformNistResponse(response))
    );
  }

  /**
   * 使用關鍵字查詢 CVE（後備方案）
   */
  private searchVulnerabilitiesByKeyword(searchKeyword: string): Observable<Vulnerability[]> {
    const params: NistApiParams = {
      keywordSearch: searchKeyword,
      resultsPerPage: 2000,
      noRejected: true
    };

    return this.makeApiRequest(params).pipe(
      map(response => this.transformNistResponse(response))
    );
  }

  /**
   * 建立 API 請求
   */
  private buildApiRequest(baseUrl: string, params: NistApiParams | CpeApiParams): { url: string; httpParams: HttpParams } {
    // 建立 HTTP 參數
    let httpParams = new HttpParams();

    // CVE API 參數
    if ('keywordSearch' in params && params.keywordSearch) {
      httpParams = httpParams.set('keywordSearch', params.keywordSearch);
    }
    if ('cveId' in params && params.cveId) {
      httpParams = httpParams.set('cveId', params.cveId);
    }
    if ('pubStartDate' in params && params.pubStartDate) {
      httpParams = httpParams.set('pubStartDate', params.pubStartDate);
    }
    if ('pubEndDate' in params && params.pubEndDate) {
      httpParams = httpParams.set('pubEndDate', params.pubEndDate);
    }
    if ('cvssV3Severity' in params && params.cvssV3Severity) {
      httpParams = httpParams.set('cvssV3Severity', params.cvssV3Severity);
    }
    if ('cvssV3Metrics' in params && params.cvssV3Metrics) {
      httpParams = httpParams.set('cvssV3Metrics', params.cvssV3Metrics);
    }
    if ('cpeName' in params && params.cpeName) {
      httpParams = httpParams.set('cpeName', params.cpeName);
    }
    if ('lastModStartDate' in params && params.lastModStartDate) {
      httpParams = httpParams.set('lastModStartDate', params.lastModStartDate);
    }
    if ('lastModEndDate' in params && params.lastModEndDate) {
      httpParams = httpParams.set('lastModEndDate', params.lastModEndDate);
    }
    
    // CPE API 參數
    if ('cpeMatchString' in params && params.cpeMatchString) {
      httpParams = httpParams.set('cpeMatchString', params.cpeMatchString);
    }
    if ('matchCriteriaId' in params && params.matchCriteriaId) {
      httpParams = httpParams.set('matchCriteriaId', params.matchCriteriaId);
    }

    // 共用參數
    if (params.resultsPerPage) {
      httpParams = httpParams.set('resultsPerPage', params.resultsPerPage.toString());
    }
    if (params.startIndex) {
      httpParams = httpParams.set('startIndex', params.startIndex.toString());
    }

    // 處理 noRejected 參數 - 需要特殊處理以避免等號
    let finalUrl = baseUrl;
    const paramString = httpParams.toString();
    if (paramString) {
      finalUrl += '?' + paramString;
      if ('noRejected' in params && params.noRejected) {
        finalUrl += '&noRejected';
      }
    } else if ('noRejected' in params && params.noRejected) {
      finalUrl += '?noRejected';
    }

    return { url: finalUrl, httpParams };
  }

  /**
   * 發送 CPE API 請求
   */
  private makeCpeApiRequest(params: CpeApiParams): Observable<CpeApiResponse> {
    return new Observable(observer => {
      // 檢查速率限制
      const rateLimitInfo = this.getRateLimitInfo();

      if (rateLimitInfo.requestsRemaining <= 0) {
        const timeToReset = Math.max(0, rateLimitInfo.resetTime.getTime() - Date.now());

        if (timeToReset > 0) {
          observer.error(new Error(`API 請求限制已達上限，請等待 ${Math.ceil(timeToReset / 1000)} 秒後重試`));
          return;
        }
      }

      // 記錄這次請求時間
      this.requestQueue.push(new Date());

      const { url } = this.buildApiRequest(this.NIST_CPE_API_URL, params);

      // 發送請求
      this.http.get<CpeApiResponse>(url).pipe(
        tap(response => {
          console.log(`CPE API 回應: 找到 ${response.totalResults} 筆結果`);
        }),
        catchError(error => {
          // 移除失敗的請求記錄
          this.requestQueue.pop();
          return throwError(() => error);
        })
      ).subscribe({
        next: (response) => {
          observer.next(response);
          observer.complete();
        },
        error: (error) => {
          observer.error(error);
        }
      });
    });
  }

  /**
   * 判斷 CPE 名稱是否與套件相關
   */
  private isCpeRelevant(cpeName: string, packageName: string): boolean {
    const lowerCpeName = cpeName.toLowerCase();
    const lowerPackageName = packageName.toLowerCase();
    
    // 基本匹配：檢查 CPE 名稱中是否包含套件名稱
    return lowerCpeName.includes(lowerPackageName) ||
           lowerPackageName.includes(lowerCpeName.split(':')[4] || '') ||
           this.fuzzyMatch(lowerCpeName, lowerPackageName);
  }

  /**
   * 模糊匹配函數
   */
  private fuzzyMatch(cpe: string, packageName: string): boolean {
    // 簡單的模糊匹配，可以根據需要優化
    const cpeWords = cpe.split(/[:\-_\s]/);
    const packageWords = packageName.split(/[\-_\s]/);
    
    return packageWords.some(word => 
      cpeWords.some(cpeWord => 
        cpeWord.includes(word) || word.includes(cpeWord)
      )
    );
  }

  /**
   * 原來的 makeApiRequest 方法重新實作
   */
  private makeApiRequest(params: NistApiParams): Observable<NistApiResponse> {
    return new Observable(observer => {
      // 檢查速率限制
      const rateLimitInfo = this.getRateLimitInfo();

      if (rateLimitInfo.requestsRemaining <= 0) {
        const timeToReset = Math.max(0, rateLimitInfo.resetTime.getTime() - Date.now());

        if (timeToReset > 0) {
          observer.error(new Error(`API 請求限制已達上限，請等待 ${Math.ceil(timeToReset / 1000)} 秒後重試`));
          return;
        }
      }

      // 記錄這次請求時間
      this.requestQueue.push(new Date());

      const { url } = this.buildApiRequest(this.NIST_CVE_API_URL, params);

      // 發送請求
      this.http.get<NistApiResponse>(url).pipe(
        tap(response => {
          console.log(`NIST API 回應: 找到 ${response.totalResults} 筆結果`);
        }),
        catchError(error => {
          // 移除失敗的請求記錄
          this.requestQueue.pop();
          return throwError(() => error);
        })
      ).subscribe({
        next: (response) => {
          observer.next(response);
          observer.complete();
        },
        error: (error) => {
          observer.error(error);
        }
      });
    });
  }

  /**
   * 轉換 NIST API 回應為內部漏洞格式
   */
  private transformNistResponse(response: NistApiResponse): Vulnerability[] {
    return response.vulnerabilities.map(item => {
      const cve = item.cve;

      // 取得 CVSS 分數和嚴重程度
      let cvssScore = 0;
      let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' = 'NONE';
      let cvssVector = '';

      if (cve.metrics?.cvssMetricV31?.[0]) {
        const cvss = cve.metrics.cvssMetricV31[0];
        cvssScore = cvss.cvssData.baseScore;
        severity = this.mapCvssSeverity(cvss.cvssData.baseSeverity);
        cvssVector = cvss.cvssData.vectorString;
      } else if (cve.metrics?.cvssMetricV30?.[0]) {
        const cvss = cve.metrics.cvssMetricV30[0];
        cvssScore = cvss.cvssData.baseScore;
        severity = this.mapCvssSeverity(cvss.cvssData.baseSeverity);
        cvssVector = cvss.cvssData.vectorString;
      } else if (cve.metrics?.cvssMetricV2?.[0]) {
        const cvss = cve.metrics.cvssMetricV2[0];
        cvssScore = cvss.cvssData.baseScore;
        severity = this.mapCvssV2Severity(cvssScore);
      }

      // 取得描述
      const description = cve.descriptions.find(desc => desc.lang === 'en')?.value ||
                         cve.descriptions[0]?.value ||
                         'No description available';

      // 取得參考連結
      const references = cve.references.map(ref => ref.url);

      // 從 configurations 解析受影響版本和修復版本
      const versionInfo = this.parseVersionInfoFromConfigurations(cve.configurations || []);

      return {
        cveId: cve.id,
        description,
        severity,
        cvssScore,
        cvssVector,
        publishedDate: cve.published,
        lastModifiedDate: cve.lastModified,
        references,
        affectedVersions: versionInfo.affectedVersions,
        fixedVersion: versionInfo.fixedVersion
      };
    });
  }

  /**
   * 對應 CVSS v3 嚴重程度
   */
  private mapCvssSeverity(severity: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'CRITICAL';
      case 'HIGH': return 'HIGH';
      case 'MEDIUM': return 'MEDIUM';
      case 'LOW': return 'LOW';
      default: return 'NONE';
    }
  }

  /**
   * 對應 CVSS v2 分數到嚴重程度
   */
  private mapCvssV2Severity(score: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0) return 'LOW';
    return 'NONE';
  }

  /**
   * 從 CVE configurations 解析版本資訊
   */
  private parseVersionInfoFromConfigurations(configurations: any[]): {
    affectedVersions: string[];
    fixedVersion?: string;
  } {
    const affectedVersions: string[] = [];
    const fixedVersionCandidates: string[] = [];

    for (const config of configurations) {
      const nodes = config.nodes || [];
      for (const node of nodes) {
        const matches = (node.cpeMatch || []).filter((m: any) => m.vulnerable);
        for (const match of matches) {
          const versionEndExcluding = match.versionEndExcluding;
          const versionEndIncluding = match.versionEndIncluding;
          const versionStartIncluding = match.versionStartIncluding;
          const versionStartExcluding = match.versionStartExcluding;

          // 建構受影響版本範圍字串
          let versionRange = '';
          if (versionStartIncluding && versionEndExcluding) {
            versionRange = `>=${versionStartIncluding} <${versionEndExcluding}`;
          } else if (versionStartIncluding && versionEndIncluding) {
            versionRange = `>=${versionStartIncluding} <=${versionEndIncluding}`;
          } else if (versionStartExcluding && versionEndExcluding) {
            versionRange = `>${versionStartExcluding} <${versionEndExcluding}`;
          } else if (versionStartExcluding && versionEndIncluding) {
            versionRange = `>${versionStartExcluding} <=${versionEndIncluding}`;
          } else if (versionEndExcluding) {
            versionRange = `<${versionEndExcluding}`;
          } else if (versionEndIncluding) {
            versionRange = `<=${versionEndIncluding}`;
          } else if (versionStartIncluding) {
            versionRange = `>=${versionStartIncluding}`;
          } else if (versionStartExcluding) {
            versionRange = `>${versionStartExcluding}`;
          }

          if (versionRange) {
            affectedVersions.push(versionRange);
          }

          // 推斷修復版本
          if (versionEndExcluding) {
            // versionEndExcluding: 第一個安全版本就是 versionEndExcluding
            fixedVersionCandidates.push(versionEndExcluding);
          } else if (versionEndIncluding) {
            // versionEndIncluding: 安全版本是 > versionEndIncluding
            // 這裡簡化處理，實際應該使用 semver 來計算下一個版本
            const nextVersion = this.getNextPatchVersion(versionEndIncluding);
            if (nextVersion) {
              fixedVersionCandidates.push(nextVersion);
            }
          }
        }
      }
    }

    // 去重並選擇最低的修復版本
    const uniqueAffectedVersions = [...new Set(affectedVersions)];
    const uniqueFixedVersions = [...new Set(fixedVersionCandidates)];
    const lowestFixedVersion = this.getLowestVersion(uniqueFixedVersions);

    return {
      affectedVersions: uniqueAffectedVersions,
      fixedVersion: lowestFixedVersion
    };
  }

  /**
   * 取得下一個補丁版本 (簡化實作)
   */
  private getNextPatchVersion(version: string): string | undefined {
    try {
      // 簡單的版本遞增邏輯
      const parts = version.split('.');
      if (parts.length >= 3) {
        const patch = parseInt(parts[2]) + 1;
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
   * 取得最低版本 (簡化實作)
   */
  private getLowestVersion(versions: string[]): string | undefined {
    if (versions.length === 0) return undefined;
    
    // 簡單排序，實際應該使用 semver 比較
    return versions.sort((a, b) => {
      const aParts = a.split('.').map(n => parseInt(n) || 0);
      const bParts = b.split('.').map(n => parseInt(n) || 0);
      
      for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
        const aPart = aParts[i] || 0;
        const bPart = bParts[i] || 0;
        if (aPart !== bPart) {
          return aPart - bPart;
        }
      }
      return 0;
    })[0];
  }



  /**
   * 測試 API 連線
   */
  testConnection(): Observable<boolean> {
    const params: NistApiParams = {
      keywordSearch: 'test',
      resultsPerPage: 1,
      noRejected: true
    };

    return this.makeApiRequest(params).pipe(
      map(() => true),
      catchError(() => {
        return new Observable<boolean>(observer => {
          observer.next(false);
          observer.complete();
        });
      })
    );
  }

  /**
   * 清理資源 (用於服務銷毀時)
   */
  ngOnDestroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.requestQueue = [];
    this.cpeCache.clear();
  }
}
