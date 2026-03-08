import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of, forkJoin } from 'rxjs';
import { map, catchError, tap } from 'rxjs/operators';
import {
  OsvQueryRequest,
  OsvBatchQueryRequest,
  OsvBatchQueryResponse,
  OsvVulnerability,
  OsvSeverity,
  OsvAffected,
  OsvRange,
  OsvEvent
} from '../interfaces/osv-api.interface';
import { Vulnerability, VulnerabilitySeverity, PackageInfo } from '../models/vulnerability.model';
import { CacheService } from './cache.service';
import { IVulnerabilityProvider } from '../interfaces/services.interface';

@Injectable({
  providedIn: 'root'
})
export class OsvApiService implements IVulnerabilityProvider {
  readonly name = 'OSV.dev';
  readonly priority = 2; // NIST 為 1（優先），OSV 為 2（補充）

  private readonly OSV_API_URL = 'https://api.osv.dev/v1';
  private readonly BATCH_SIZE = 1000; // OSV 批次查詢上限
  private readonly CACHE_PREFIX = 'osv:';

  constructor(
    private http: HttpClient,
    private cacheService: CacheService
  ) {}

  /**
   * 檢查 OSV API 是否可用
   */
  isAvailable(): Observable<boolean> {
    return this.http.post<OsvBatchQueryResponse>(
      `${this.OSV_API_URL}/querybatch`,
      { queries: [{ package: { name: 'test', ecosystem: 'npm' } }] }
    ).pipe(
      map(() => true),
      catchError(() => of(false))
    );
  }

  /**
   * 搜尋單一套件的漏洞
   */
  searchVulnerabilities(packageName: string, version?: string): Observable<Vulnerability[]> {
    const cacheKey = `${this.CACHE_PREFIX}${packageName}@${version || '*'}`;
    const cached = this.cacheService.get<Vulnerability[]>(cacheKey);
    if (cached) {
      return of(cached);
    }

    const query: OsvQueryRequest = {
      package: {
        name: this.normalizePackageName(packageName),
        ecosystem: 'npm'
      }
    };

    if (version) {
      query.version = version;
    }

    return this.http.post<{ vulns?: OsvVulnerability[] }>(
      `${this.OSV_API_URL}/query`,
      query
    ).pipe(
      map(response => {
        const vulns = (response.vulns || []).map(v => this.transformOsvToVulnerability(v));
        return vulns;
      }),
      tap(vulns => {
        this.cacheService.set(cacheKey, vulns, 24 * 60 * 60 * 1000);
      }),
      catchError(error => {
        console.warn(`[OSV] 查詢 ${packageName} 失敗:`, error.message);
        return of([]);
      })
    );
  }

  /**
   * 批次查詢多個套件的漏洞
   */
  searchBatch(packages: PackageInfo[]): Observable<Map<string, Vulnerability[]>> {
    if (packages.length === 0) {
      return of(new Map());
    }

    // 檢查快取，分離需要查詢的套件
    const resultMap = new Map<string, Vulnerability[]>();
    const uncachedPackages: PackageInfo[] = [];

    for (const pkg of packages) {
      const cacheKey = `${this.CACHE_PREFIX}${pkg.name}@${pkg.version}`;
      const cached = this.cacheService.get<Vulnerability[]>(cacheKey);
      if (cached) {
        resultMap.set(pkg.packageKey || `${pkg.name}@${pkg.version}`, cached);
      } else {
        uncachedPackages.push(pkg);
      }
    }

    if (uncachedPackages.length === 0) {
      return of(resultMap);
    }

    // 分批查詢
    const batches: PackageInfo[][] = [];
    for (let i = 0; i < uncachedPackages.length; i += this.BATCH_SIZE) {
      batches.push(uncachedPackages.slice(i, i + this.BATCH_SIZE));
    }

    const batchRequests = batches.map(batch => this.executeBatchQuery(batch));

    return forkJoin(batchRequests).pipe(
      map(batchResults => {
        for (const batchMap of batchResults) {
          batchMap.forEach((vulns, key) => resultMap.set(key, vulns));
        }
        return resultMap;
      }),
      catchError(error => {
        console.warn('[OSV] 批次查詢失敗:', error.message);
        return of(resultMap); // 返回已有的快取結果
      })
    );
  }

  /**
   * 帶進度回報的批次掃描
   */
  searchMultiplePackagesWithProgress(packages: PackageInfo[]): Observable<{
    type: 'progress' | 'result',
    progress?: { current: number, total: number, currentPackage: string },
    results?: Map<string, Vulnerability[]>
  }> {
    return new Observable(observer => {
      observer.next({
        type: 'progress',
        progress: { current: 0, total: packages.length, currentPackage: '正在查詢 OSV.dev...' }
      });

      this.searchBatch(packages).subscribe({
        next: (resultMap) => {
          observer.next({
            type: 'progress',
            progress: { current: packages.length, total: packages.length, currentPackage: 'OSV 查詢完成' }
          });
          observer.next({ type: 'result', results: resultMap });
          observer.complete();
        },
        error: (error) => {
          console.warn('[OSV] 進度掃描失敗:', error.message);
          observer.next({ type: 'result', results: new Map() });
          observer.complete();
        }
      });
    });
  }

  /**
   * 執行單批次查詢
   */
  private executeBatchQuery(packages: PackageInfo[]): Observable<Map<string, Vulnerability[]>> {
    const request: OsvBatchQueryRequest = {
      queries: packages.map(pkg => ({
        package: {
          name: this.normalizePackageName(pkg.name),
          ecosystem: 'npm'
        },
        version: pkg.version
      }))
    };

    return this.http.post<OsvBatchQueryResponse>(
      `${this.OSV_API_URL}/querybatch`,
      request
    ).pipe(
      map(response => {
        const resultMap = new Map<string, Vulnerability[]>();

        response.results.forEach((result, index) => {
          const pkg = packages[index];
          const packageKey = pkg.packageKey || `${pkg.name}@${pkg.version}`;
          const vulns = (result.vulns || []).map(v => this.transformOsvToVulnerability(v));

          resultMap.set(packageKey, vulns);

          // 快取個別套件結果
          const cacheKey = `${this.CACHE_PREFIX}${pkg.name}@${pkg.version}`;
          this.cacheService.set(cacheKey, vulns, 24 * 60 * 60 * 1000);
        });

        return resultMap;
      }),
      catchError(error => {
        console.warn('[OSV] 批次查詢失敗:', error.message);
        return of(new Map<string, Vulnerability[]>());
      })
    );
  }

  /**
   * 將 OSV 漏洞轉換為內部 Vulnerability 格式
   */
  transformOsvToVulnerability(osv: OsvVulnerability): Vulnerability {
    // 從 aliases 中取 CVE ID，沒有則用 OSV ID
    const cveId = this.extractCveId(osv);

    // 解析 CVSS 分數和嚴重程度
    const { cvssScore, severity, cvssVector } = this.parseSeverity(osv.severity);

    // 解析受影響版本和修復版本
    const { affectedVersions, fixedVersion } = this.parseAffectedVersions(osv.affected);

    // 取得參考連結
    const references = (osv.references || []).map(ref => ref.url);

    // 描述
    const description = osv.summary || osv.details || 'No description available';

    return {
      cveId,
      description,
      severity,
      cvssScore,
      cvssVector,
      publishedDate: osv.published || osv.modified,
      lastModifiedDate: osv.modified,
      references,
      affectedVersions,
      fixedVersion,
      dataSource: 'osv'
    };
  }

  /**
   * 從 OSV 漏洞中提取 CVE ID
   */
  private extractCveId(osv: OsvVulnerability): string {
    if (osv.aliases) {
      const cve = osv.aliases.find(alias => alias.startsWith('CVE-'));
      if (cve) return cve;
    }
    return osv.id; // 使用 OSV ID（如 GHSA-xxxx）
  }

  /**
   * 解析 CVSS 嚴重程度
   */
  private parseSeverity(severities?: OsvSeverity[]): {
    cvssScore: number;
    severity: VulnerabilitySeverity;
    cvssVector: string;
  } {
    if (!severities || severities.length === 0) {
      return { cvssScore: 0, severity: 'NONE', cvssVector: '' };
    }

    // 優先使用 CVSS v3
    const cvssV3 = severities.find(s => s.type === 'CVSS_V3');
    const cvssEntry = cvssV3 || severities[0];

    const cvssVector = cvssEntry.score;
    const cvssScore = this.extractScoreFromVector(cvssVector);
    const severity = this.scoreToSeverity(cvssScore);

    return { cvssScore, severity, cvssVector };
  }

  /**
   * 從 CVSS 向量字串中提取分數
   */
  private extractScoreFromVector(vector: string): number {
    if (!vector) return 0;

    // 嘗試從向量字串解析基礎分數
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
    // OSV 的 score 欄位有時直接是分數字串
    const numericScore = parseFloat(vector);
    if (!isNaN(numericScore) && numericScore >= 0 && numericScore <= 10) {
      return numericScore;
    }

    // 根據向量字串的關鍵指標估算分數
    if (!vector.startsWith('CVSS:')) return 0;

    return this.estimateCvssScore(vector);
  }

  /**
   * 根據 CVSS 向量估算分數
   */
  private estimateCvssScore(vector: string): number {
    const parts = vector.split('/');
    let score = 5.0; // 基礎分數

    for (const part of parts) {
      const [metric, value] = part.split(':');
      switch (metric) {
        case 'AV':
          if (value === 'N') score += 1.5;      // 網路
          else if (value === 'A') score += 0.5;  // 相鄰網路
          break;
        case 'AC':
          if (value === 'L') score += 0.5;       // 低複雜度
          break;
        case 'PR':
          if (value === 'N') score += 0.5;       // 無需權限
          break;
        case 'UI':
          if (value === 'N') score += 0.5;       // 無需使用者互動
          break;
        case 'C':
          if (value === 'H') score += 0.5;       // 高機密性影響
          break;
        case 'I':
          if (value === 'H') score += 0.5;       // 高完整性影響
          break;
        case 'A':
          if (value === 'H') score += 0.5;       // 高可用性影響
          break;
      }
    }

    return Math.min(10, Math.max(0, score));
  }

  /**
   * 分數轉換為嚴重程度
   */
  private scoreToSeverity(score: number): VulnerabilitySeverity {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0) return 'LOW';
    return 'NONE';
  }

  /**
   * 解析受影響版本和修復版本
   */
  private parseAffectedVersions(affected?: OsvAffected[]): {
    affectedVersions: string[];
    fixedVersion?: string;
  } {
    if (!affected || affected.length === 0) {
      return { affectedVersions: [] };
    }

    const affectedVersions: string[] = [];
    let fixedVersion: string | undefined;

    for (const entry of affected) {
      // 只處理 npm 生態系的影響
      if (entry.package.ecosystem !== 'npm') continue;

      for (const range of (entry.ranges || [])) {
        for (const event of range.events) {
          if (event.introduced && event.introduced !== '0') {
            affectedVersions.push(`>=${event.introduced}`);
          } else if (event.introduced === '0') {
            affectedVersions.push('>=0.0.0');
          }
          if (event.fixed) {
            affectedVersions.push(`<${event.fixed}`);
            // 保留最早的修復版本
            if (!fixedVersion || this.isLowerVersion(event.fixed, fixedVersion)) {
              fixedVersion = event.fixed;
            }
          }
          if (event.last_affected) {
            affectedVersions.push(`<=${event.last_affected}`);
          }
        }
      }

      // 如果有明確列出的受影響版本
      if (entry.versions && entry.versions.length > 0) {
        // 組合成版本範圍描述
        const versionList = entry.versions.join(', ');
        if (entry.versions.length <= 5) {
          affectedVersions.push(versionList);
        }
      }
    }

    return {
      affectedVersions: [...new Set(affectedVersions)],
      fixedVersion
    };
  }

  /**
   * 簡單的版本比較
   */
  private isLowerVersion(a: string, b: string): boolean {
    const partsA = a.split('.').map(n => parseInt(n, 10) || 0);
    const partsB = b.split('.').map(n => parseInt(n, 10) || 0);

    for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
      const numA = partsA[i] || 0;
      const numB = partsB[i] || 0;
      if (numA < numB) return true;
      if (numA > numB) return false;
    }
    return false;
  }

  /**
   * 正規化套件名稱（處理 scoped packages）
   */
  private normalizePackageName(name: string): string {
    // OSV 使用完整的 npm 套件名稱（含 scope）
    return name;
  }
}
