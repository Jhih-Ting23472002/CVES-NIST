import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { map, catchError, tap } from 'rxjs/operators';
import {
  NistApiResponse,
  NistApiParams,
  RateLimitInfo
} from '../interfaces/nist-api.interface';
import { Vulnerability, PackageInfo } from '../models/vulnerability.model';
import { CacheService } from './cache.service';

@Injectable({
  providedIn: 'root'
})
export class NistApiService {
  private readonly NIST_API_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private readonly REQUEST_DELAY = 7000; // 7秒延遲確保符合 NIST API 限制 (每分鐘最多10次請求)
  private readonly MAX_REQUESTS_PER_MINUTE = 10;

  private requestQueue: Date[] = []; // 追蹤最近的請求時間

  constructor(
    private http: HttpClient,
    private cacheService: CacheService
  ) {}

  /**
   * 搜尋特定套件的 CVE 漏洞
   */
  searchVulnerabilities(packageName: string, version?: string): Observable<Vulnerability[]> {
    // 檢查快取 (包含 noRejected 參數)
    const cacheKey = CacheService.createVulnerabilityKey(packageName, version || '', true);
    const cachedResult = this.cacheService.get<Vulnerability[]>(cacheKey);

    if (cachedResult) {
      console.log(`從快取取得 ${packageName} 的漏洞資料`);
      return new Observable(observer => {
        observer.next(cachedResult);
        observer.complete();
      });
    }

    // 建立搜尋關鍵字
    const searchKeyword = version ? `${packageName} ${version}` : packageName;

    const params: NistApiParams = {
      keywordSearch: searchKeyword,
      resultsPerPage: 100,
      noRejected: true // 預設過濾已拒絕的 CVE
    };

    return this.makeApiRequest(params).pipe(
      map(response => this.transformNistResponse(response)),
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
              packageName: pkg.name,
              vulnerabilities
            });

            // 延遲後處理下一個套件以符合 API 限制
            setTimeout(() => processPackage(index + 1), this.REQUEST_DELAY);
          },
          error: (error) => {
            console.error(`掃描 ${pkg.name} 失敗:`, error);
            results.push({
              packageName: pkg.name,
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
   * 批次搜尋多個套件的漏洞，支援進度回報
   */
  searchMultiplePackagesWithProgress(packages: PackageInfo[]): Observable<{
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

        this.searchVulnerabilities(pkg.name, pkg.version).subscribe({
          next: (vulnerabilities) => {
            results.push({
              packageName: pkg.name,
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
              packageName: pkg.name,
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
    const now = new Date();
    const oneMinuteAgo = new Date(now.getTime() - 60000);

    // 清理超過一分鐘的請求記錄
    this.requestQueue = this.requestQueue.filter(time => time > oneMinuteAgo);

    return {
      requestsRemaining: Math.max(0, this.MAX_REQUESTS_PER_MINUTE - this.requestQueue.length),
      resetTime: new Date(Math.min(...this.requestQueue.map(t => t.getTime())) + 60000),
      requestsMade: this.requestQueue.length,
      maxRequests: this.MAX_REQUESTS_PER_MINUTE,
      timeWindow: 60000
    };
  }

  /**
   * 發送 API 請求
   */
  private makeApiRequest(params: NistApiParams): Observable<NistApiResponse> {
    return new Observable(observer => {
      // 檢查速率限制
      const rateLimitInfo = this.getRateLimitInfo();

      if (rateLimitInfo.requestsRemaining <= 0) {
        const oldestRequest = Math.min(...this.requestQueue.map(t => t.getTime()));
        const timeToReset = Math.max(0, (oldestRequest + 60000) - Date.now());

        if (timeToReset > 0) {
          observer.error(new Error(`API 請求限制已達上限，請等待 ${Math.ceil(timeToReset / 1000)} 秒後重試`));
          return;
        }
      }

      // 記錄這次請求時間
      this.requestQueue.push(new Date());

      // 建立 HTTP 參數
      let httpParams = new HttpParams();

      if (params.keywordSearch) {
        httpParams = httpParams.set('keywordSearch', params.keywordSearch);
      }
      if (params.cveId) {
        httpParams = httpParams.set('cveId', params.cveId);
      }
      if (params.pubStartDate) {
        httpParams = httpParams.set('pubStartDate', params.pubStartDate);
      }
      if (params.pubEndDate) {
        httpParams = httpParams.set('pubEndDate', params.pubEndDate);
      }
      if (params.cvssV3Severity) {
        httpParams = httpParams.set('cvssV3Severity', params.cvssV3Severity);
      }
      if (params.resultsPerPage) {
        httpParams = httpParams.set('resultsPerPage', params.resultsPerPage.toString());
      }
      if (params.startIndex) {
        httpParams = httpParams.set('startIndex', params.startIndex.toString());
      }

      // 處理 noRejected 參數 - 需要特殊處理以避免等號
      let finalUrl = this.NIST_API_BASE_URL;
      const paramString = httpParams.toString();
      if (paramString) {
        finalUrl += '?' + paramString;
        if (params.noRejected) {
          finalUrl += '&noRejected';
        }
      } else if (params.noRejected) {
        finalUrl += '?noRejected';
      }

      // 發送請求
      this.http.get<NistApiResponse>(finalUrl).pipe(
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

      return {
        cveId: cve.id,
        description,
        severity,
        cvssScore,
        cvssVector,
        publishedDate: cve.published,
        lastModifiedDate: cve.lastModified,
        references,
        affectedVersions: [], // 需要從 configurations 解析
        fixedVersion: undefined
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
}
