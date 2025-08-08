import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, forkJoin, of } from 'rxjs';
import { map, catchError, switchMap } from 'rxjs/operators';
import { Vulnerability, PackageInfo } from '../models/vulnerability.model';
import { NistApiService } from './nist-api.service';
import { CacheService } from './cache.service';
import { NistVulnerabilityItem } from '../interfaces/nist-api.interface';

interface NpmPackageInfo {
  name: string;
  versions: { [version: string]: NpmVersionInfo };
  'dist-tags': { [tag: string]: string };
  time: { [version: string]: string };
}

interface NpmVersionInfo {
  name: string;
  version: string;
  description?: string;
  main?: string;
  scripts?: { [script: string]: string };
  dependencies?: { [dep: string]: string };
  devDependencies?: { [dep: string]: string };
  deprecated?: string;
  _hasShrinkwrap?: boolean;
  dist: {
    tarball: string;
    shasum: string;
    integrity?: string;
  };
}

interface VersionAnalysis {
  version: string;
  vulnerabilities: Vulnerability[];
  securityScore: number;
  freshnessScore: number;
  stabilityScore: number;
  totalScore: number;
  publishDate: Date;
  isDeprecated: boolean;
  isPrerelease: boolean;
}

export interface VersionRecommendation {
  packageName: string;
  currentVersion: string;
  recommendedVersion?: string; // 可能沒有推薦版本
  reason: string;
  securityImprovement?: {
    currentVulnerabilities: number;
    recommendedVulnerabilities: number;
    severityReduction: string;
  };
  fixedVersions: string[]; // 從 CVE 資料中提取的修復版本
  hasData: boolean; // 是否有推薦資料
  updateStrategy: 'patch' | 'minor' | 'major' | 'none' | 'unknown';
  dataSource?: 'nvd' | 'npm' | 'mixed'; // 資料來源標識
}

@Injectable({
  providedIn: 'root'
})
export class VersionRecommendationService {
  private readonly NPM_REGISTRY_BASE = 'https://registry.npmjs.org';
  private readonly NPM_REQUEST_DELAY = 100; // NPM API 速率限制保護 (100ms)
  private readonly MAX_CONCURRENT_REQUESTS = 3; // 最多同時請求數
  private npmRequestQueue: Date[] = [];

  constructor(
    private http: HttpClient,
    private nistApiService: NistApiService,
    private cacheService: CacheService
  ) {}

  /**
   * 為套件推薦最佳版本
   */
  recommendVersion(packageName: string, currentVersion: string): Observable<VersionRecommendation> {
    // 檢查快取
    const cacheKey = `version_recommendation_${packageName}_${currentVersion}`;
    const cachedResult = this.cacheService.get<VersionRecommendation>(cacheKey);
    
    if (cachedResult) {
      console.log(`從快取取得 ${packageName} 的版本推薦`);
      return of(cachedResult);
    }

    // 直接查詢套件的漏洞資訊
    return this.nistApiService.searchVulnerabilities(packageName, currentVersion).pipe(
      map(vulnerabilities => {
        const recommendation = this.generateRecommendationFromVulnerabilities(
          packageName, 
          currentVersion, 
          vulnerabilities
        );
        
        // 快取結果（1小時）
        this.cacheService.set(cacheKey, recommendation, 60 * 60 * 1000);
        return recommendation;
      }),
      catchError(error => {
        console.error(`版本推薦失敗 ${packageName}:`, error);
        // 回傳無資訊的推薦
        return of(this.createNoDataRecommendation(packageName, currentVersion, error.message));
      })
    );
  }

  /**
   * 批次推薦多個套件的版本 (序列化處理)
   */
  recommendVersions(packages: PackageInfo[]): Observable<VersionRecommendation[]> {
    const results: VersionRecommendation[] = [];
    
    return new Observable<VersionRecommendation[]>(observer => {
      const processPackage = (index: number) => {
        if (index >= packages.length) {
          observer.next(results);
          observer.complete();
          return;
        }

        const pkg = packages[index];
        console.log(`正在推薦 ${pkg.name} 的版本... (${index + 1}/${packages.length})`);

        this.recommendVersion(pkg.name, pkg.version).subscribe({
          next: (recommendation) => {
            results.push(recommendation);
            // 延遲後處理下一個套件（每個推薦可能需要分析多個版本）
            setTimeout(() => processPackage(index + 1), 5000);
          },
          error: (error) => {
            console.error(`推薦 ${pkg.name} 版本失敗:`, error);
            // 即使失敗也繼續處理下一個
            setTimeout(() => processPackage(index + 1), 5000);
          }
        });
      };

      processPackage(0);
    });
  }

  /**
   * 獲取 NPM 套件資訊 (加入速率限制保護)
   */
  private getNpmPackageInfo(packageName: string): Observable<NpmPackageInfo | null> {
    return new Observable(observer => {
      // 簡單的 NPM API 速率限制保護
      const now = new Date();
      this.npmRequestQueue = this.npmRequestQueue.filter(time => now.getTime() - time.getTime() < 60000);
      
      if (this.npmRequestQueue.length >= 10) { // NPM API 每分鐘限制
        observer.error(new Error('NPM API 請求過於頻繁，請稍後再試'));
        return;
      }

      this.npmRequestQueue.push(now);
      
      this.http.get<NpmPackageInfo>(`${this.NPM_REGISTRY_BASE}/${packageName}`).pipe(
        catchError(error => {
          console.error(`無法獲取 ${packageName} 的 NPM 資訊:`, error);
          return of(null);
        })
      ).subscribe({
        next: (data) => {
          observer.next(data);
          observer.complete();
        },
        error: (error) => {
          observer.error(error);
        }
      });
    });
  }

  /**
   * 選擇要分析的版本（避免分析過多版本）
   */
  private selectVersionsForAnalysis(npmInfo: NpmPackageInfo, currentVersion: string): string[] {
    const allVersions = Object.keys(npmInfo.versions);
    const versionTimes = npmInfo.time;
    
    // 按發布時間排序（最新的在前）
    const sortedVersions = allVersions
      .filter(v => versionTimes[v]) // 過濾掉沒有時間資訊的版本
      .sort((a, b) => new Date(versionTimes[b]).getTime() - new Date(versionTimes[a]).getTime());

    // 選擇要分析的版本：
    // 1. 目前版本（如果不在列表中就加入）
    // 2. 最新的10個穩定版本
    // 3. 每個主要版本的最新版本
    const versionsToAnalyze = new Set<string>();
    
    // 加入目前版本
    if (allVersions.includes(currentVersion)) {
      versionsToAnalyze.add(currentVersion);
    }

    // 加入最新的3個穩定版本（排除預發布版本）- 減少分析數量
    const stableVersions = sortedVersions.filter(v => !this.isPrerelease(v));
    stableVersions.slice(0, 3).forEach(v => versionsToAnalyze.add(v));

    // 加入每個主要版本的最新版本
    const majorVersions = new Map<number, string>();
    stableVersions.forEach(version => {
      const major = this.extractMajorVersion(version);
      if (major !== null && !majorVersions.has(major)) {
        majorVersions.set(major, version);
      }
    });
    majorVersions.forEach(version => versionsToAnalyze.add(version));

    return Array.from(versionsToAnalyze);
  }

  /**
   * 序列化處理版本分析以符合 API 限制
   */
  private processVersionsSequentially(
    packageName: string, 
    versions: string[], 
    npmInfo: NpmPackageInfo
  ): Observable<VersionAnalysis[]> {
    const results: VersionAnalysis[] = [];
    
    return new Observable<VersionAnalysis[]>(observer => {
      const processVersion = (index: number) => {
        if (index >= versions.length) {
          observer.next(results);
          observer.complete();
          return;
        }

        const version = versions[index];
        console.log(`分析版本 ${version} (${index + 1}/${versions.length})`);

        this.analyzeVersion(packageName, version, npmInfo).subscribe({
          next: (analysis) => {
            results.push(analysis);
            // 延遲後處理下一個版本（每個版本分析需要2個API請求，所以延遲12秒）
            setTimeout(() => processVersion(index + 1), 12000);
          },
          error: (error) => {
            console.error(`分析版本 ${version} 失敗:`, error);
            // 即使失敗也繼續處理下一個版本
            setTimeout(() => processVersion(index + 1), 12000);
          }
        });
      };

      processVersion(0);
    });
  }

  /**
   * 分析單一版本的安全性
   */
  private analyzeVersion(packageName: string, version: string, npmInfo: NpmPackageInfo): Observable<VersionAnalysis> {
    const versionInfo = npmInfo.versions[version];
    const publishDate = new Date(npmInfo.time[version]);

    return this.nistApiService.searchVulnerabilities(packageName, version).pipe(
      map(vulnerabilities => ({
        version,
        vulnerabilities,
        securityScore: this.calculateSecurityScore(vulnerabilities),
        freshnessScore: this.calculateFreshnessScore(publishDate),
        stabilityScore: this.calculateStabilityScore(version, versionInfo),
        totalScore: 0, // 稍後計算
        publishDate,
        isDeprecated: !!versionInfo.deprecated,
        isPrerelease: this.isPrerelease(version)
      })),
      map(analysis => {
        // 計算總分
        analysis.totalScore = 
          analysis.securityScore * 0.6 + 
          analysis.freshnessScore * 0.3 + 
          analysis.stabilityScore * 0.1;
        return analysis;
      }),
      catchError(error => {
        console.error(`分析版本 ${packageName}@${version} 失敗:`, error);
        // 返回預設分析結果
        return of({
          version,
          vulnerabilities: [],
          securityScore: 0.5, // 未知安全性
          freshnessScore: this.calculateFreshnessScore(publishDate),
          stabilityScore: this.calculateStabilityScore(version, versionInfo),
          totalScore: 0.5,
          publishDate,
          isDeprecated: !!versionInfo.deprecated,
          isPrerelease: this.isPrerelease(version)
        });
      })
    );
  }

  /**
   * 計算安全分數 (0-1，越高越好)
   */
  private calculateSecurityScore(vulnerabilities: Vulnerability[]): number {
    if (vulnerabilities.length === 0) return 1.0;

    // 根據漏洞嚴重程度加權計算
    let totalImpact = 0;
    vulnerabilities.forEach(vuln => {
      switch (vuln.severity) {
        case 'CRITICAL': totalImpact += 4; break;
        case 'HIGH': totalImpact += 3; break;
        case 'MEDIUM': totalImpact += 2; break;
        case 'LOW': totalImpact += 1; break;
      }
    });

    // 使用指數衰減函數，讓分數在 0-1 之間
    return Math.exp(-totalImpact / 5);
  }

  /**
   * 計算新舊分數 (0-1，越新分數越高)
   */
  private calculateFreshnessScore(publishDate: Date): number {
    const now = new Date();
    const ageInDays = (now.getTime() - publishDate.getTime()) / (1000 * 60 * 60 * 24);
    
    // 2年以內的版本得滿分，之後逐漸衰減
    if (ageInDays <= 730) return 1.0;
    
    // 使用對數衰減，最舊的版本分數不會低於0.1
    return Math.max(0.1, 1 - Math.log(ageInDays / 730) / 3);
  }

  /**
   * 計算穩定性分數 (0-1，穩定版本分數更高)
   */
  private calculateStabilityScore(version: string, versionInfo: NpmVersionInfo): number {
    if (versionInfo.deprecated) return 0.0;
    if (this.isPrerelease(version)) return 0.7;
    return 1.0;
  }

  /**
   * 判斷是否為預發布版本
   */
  private isPrerelease(version: string): boolean {
    return /-(alpha|beta|rc|pre|dev|canary|next|snapshot)/.test(version);
  }

  /**
   * 提取主要版本號
   */
  private extractMajorVersion(version: string): number | null {
    const match = version.match(/^(\d+)/);
    return match ? parseInt(match[1], 10) : null;
  }


  /**
   * 決定更新策略
   */
  private determineUpdateStrategy(currentVersion: string, recommendedVersion: string): 'patch' | 'minor' | 'major' | 'none' | 'unknown' {
    if (currentVersion === recommendedVersion) return 'none';

    const currentMajor = this.extractMajorVersion(currentVersion);
    const recommendedMajor = this.extractMajorVersion(recommendedVersion);

    if (currentMajor !== null && recommendedMajor !== null) {
      if (recommendedMajor > currentMajor) return 'major';
      
      const currentParts = currentVersion.split('.').map(n => parseInt(n) || 0);
      const recommendedParts = recommendedVersion.split('.').map(n => parseInt(n) || 0);
      
      if (recommendedParts[1] > currentParts[1]) return 'minor';
      if (recommendedParts[2] > currentParts[2]) return 'patch';
    }

    return 'minor'; // 預設
  }


  /**
   * 計算嚴重程度改善
   */
  private calculateSeverityReduction(current: Vulnerability[], recommended: Vulnerability[]): string {
    const currentSeverity = this.getHighestSeverity(current);
    const recommendedSeverity = this.getHighestSeverity(recommended);

    if (currentSeverity === recommendedSeverity) return '無變化';
    
    const severityLevels = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const currentLevel = severityLevels.indexOf(currentSeverity);
    const recommendedLevel = severityLevels.indexOf(recommendedSeverity);

    if (recommendedLevel < currentLevel) {
      return `從 ${currentSeverity} 降低到 ${recommendedSeverity}`;
    } else if (recommendedLevel > currentLevel) {
      return `從 ${currentSeverity} 增加到 ${recommendedSeverity}`;
    }

    return '無變化';
  }

  /**
   * 獲取最高嚴重程度
   */
  private getHighestSeverity(vulnerabilities: Vulnerability[]): string {
    if (vulnerabilities.length === 0) return 'NONE';

    const severityOrder: { [key: string]: number } = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'NONE': 0 };
    let highest = 'NONE';
    
    vulnerabilities.forEach(vuln => {
      if (severityOrder[vuln.severity] > severityOrder[highest]) {
        highest = vuln.severity;
      }
    });

    return highest;
  }

  /**
   * 基於漏洞資料生成版本推薦
   */
  private generateRecommendationFromVulnerabilities(
    packageName: string,
    currentVersion: string,
    vulnerabilities: Vulnerability[]
  ): VersionRecommendation {
    if (vulnerabilities.length === 0) {
      return {
        packageName,
        currentVersion,
        reason: '目前版本沒有發現已知漏洞',
        fixedVersions: [],
        hasData: true,
        updateStrategy: 'none'
      };
    }

    // 從漏洞資料中提取修復版本建議 (參考 Node.js 範例實作)
    const suggestions = this.suggestPatchedVersionsFromNvd(vulnerabilities);
    const allFixedVersions: string[] = [];
    
    // 收集所有建議版本
    suggestions.forEach(suggestion => {
      if (suggestion.safeVersion && suggestion.safeVersion !== 'unknown') {
        allFixedVersions.push(suggestion.safeVersion);
      }
    });

    // 也從現有的 fixedVersion 欄位收集
    vulnerabilities.forEach(vuln => {
      if (vuln.fixedVersion) {
        allFixedVersions.push(vuln.fixedVersion);
      }
    });

    // 去重並排序修復版本
    const uniqueFixedVersions = [...new Set(allFixedVersions)];
    const recommendedVersion = this.selectBestFixedVersion(uniqueFixedVersions, currentVersion);

    if (!recommendedVersion) {
      return {
        packageName,
        currentVersion,
        reason: `發現 ${vulnerabilities.length} 個漏洞，但無法從 NIST CVE 資料中確定修復版本`,
        fixedVersions: uniqueFixedVersions,
        hasData: false,
        updateStrategy: 'unknown'
      };
    }

    const updateStrategy = this.determineUpdateStrategy(currentVersion, recommendedVersion);
    const reason = this.generateReasonFromVulnerabilities(vulnerabilities, recommendedVersion, suggestions);

    return {
      packageName,
      currentVersion,
      recommendedVersion,
      reason,
      fixedVersions: uniqueFixedVersions,
      hasData: true,
      updateStrategy,
      securityImprovement: {
        currentVulnerabilities: vulnerabilities.length,
        recommendedVulnerabilities: 0,
        severityReduction: `從 ${this.getHighestSeverity(vulnerabilities)} 降低到安全版本`
      }
    };
  }

  /**
   * 選擇最佳的修復版本
   */
  private selectBestFixedVersion(fixedVersions: string[], _currentVersion: string): string | undefined {
    if (fixedVersions.length === 0) return undefined;

    // 簡化實作：選擇最低的修復版本
    return fixedVersions.sort((a, b) => {
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
   * 參考 Node.js 範例實作，從 NVD CVE 資料中提取修復版本建議
   */
  private suggestPatchedVersionsFromNvd(vulnerabilities: Vulnerability[]): Array<{reason: string, safeVersion: string | null}> {
    const suggestions: Array<{reason: string, safeVersion: string | null}> = [];

    // 注意：Vulnerability 模型並未直接包含 configurations，需要從 NIST API 原始資料中取得
    // 這裡我們擴展 Vulnerability 模型來包含此資訊
    vulnerabilities.forEach(vuln => {
      const extendedVuln = vuln as Vulnerability & { rawNistData?: NistVulnerabilityItem };
      
      if (extendedVuln.rawNistData?.cve?.configurations) {
        extendedVuln.rawNistData.cve.configurations.forEach(config => {
          config.nodes.forEach(node => {
            const matches = node.cpeMatch.filter(m => m.vulnerable);
            matches.forEach(m => {
              const ve = m.versionEndExcluding;
              const vei = m.versionEndIncluding;
              // 先移除未使用的變數以修復 TypeScript 警告
              // const vsi = m.versionStartIncluding;
              // const vse = m.versionStartExcluding;

              if (ve) {
                // versionEndExcluding: 第一個安全版本就是 ve
                suggestions.push({ reason: "versionEndExcluding", safeVersion: ve });
              } else if (vei) {
                // versionEndIncluding: 安全版本 > vei -> 選擇下一個補丁版本
                if (this.isValidVersion(vei)) {
                  const nextVersion = this.incrementPatchVersion(vei);
                  suggestions.push({
                    reason: "versionEndIncluding",
                    safeVersion: nextVersion || ">" + vei
                  });
                } else {
                  suggestions.push({
                    reason: "versionEndIncluding",
                    safeVersion: ">" + vei
                  });
                }
              } else {
                // 沒有明確的結束範圍 — 需要檢查描述或參考資料
                suggestions.push({ reason: "noEndRange", safeVersion: null });
              }
            });
          });
        });
      } else {
        // 如果沒有 configurations 資料，嘗試從 fixedVersion 取得資訊
        if (vuln.fixedVersion) {
          suggestions.push({ reason: "fixedVersion", safeVersion: vuln.fixedVersion });
        }
      }
    });

    // 去重處理
    const uniq: { [key: string]: {reason: string, safeVersion: string | null} } = {};
    suggestions.forEach(s => {
      const v = s.safeVersion || "unknown";
      uniq[v] = uniq[v] || s;
    });
    
    return Object.values(uniq);
  }

  /**
   * 檢查版本是否有效
   */
  private isValidVersion(version: string): boolean {
    return /^\d+\.\d+\.\d+/.test(version);
  }

  /**
   * 增加補丁版本號
   */
  private incrementPatchVersion(version: string): string | null {
    const parts = version.split('.');
    if (parts.length >= 3) {
      const patchNum = parseInt(parts[2], 10);
      if (!isNaN(patchNum)) {
        parts[2] = (patchNum + 1).toString();
        return parts.join('.');
      }
    }
    return null;
  }

  /**
   * 基於漏洞資料生成推薦原因
   */
  private generateReasonFromVulnerabilities(
    vulnerabilities: Vulnerability[], 
    recommendedVersion: string, 
    suggestions: Array<{reason: string, safeVersion: string | null}> = []
  ): string {
    const severityCount = {
      CRITICAL: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
      HIGH: vulnerabilities.filter(v => v.severity === 'HIGH').length,
      MEDIUM: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
      LOW: vulnerabilities.filter(v => v.severity === 'LOW').length
    };

    const reasons = [];
    
    if (severityCount.CRITICAL > 0) {
      reasons.push(`修復 ${severityCount.CRITICAL} 個嚴重漏洞`);
    }
    if (severityCount.HIGH > 0) {
      reasons.push(`修復 ${severityCount.HIGH} 個高風險漏洞`);
    }
    if (severityCount.MEDIUM > 0) {
      reasons.push(`修復 ${severityCount.MEDIUM} 個中風險漏洞`);
    }
    if (severityCount.LOW > 0) {
      reasons.push(`修復 ${severityCount.LOW} 個低風險漏洞`);
    }

    const baseReason = reasons.length > 0 ? reasons.join('，') : `修復 ${vulnerabilities.length} 個已知漏洞`;
    
    // 如果有從 NVD 資料中找到版本建議，加入額外說明
    const nvdSuggestions = suggestions.filter(s => s.safeVersion && s.safeVersion !== 'unknown');
    if (nvdSuggestions.length > 0) {
      return `${baseReason}，根據 NIST CVE 資料分析建議升級至 ${recommendedVersion}`;
    }
    
    return `${baseReason}，建議升級至 ${recommendedVersion}`;
  }

  /**
   * 建立無資訊的推薦
   */
  private createNoDataRecommendation(packageName: string, currentVersion: string, errorMessage?: string): VersionRecommendation {
    let reason: string;
    
    if (errorMessage) {
      if (errorMessage.includes('404') || errorMessage.includes('not found')) {
        reason = '此套件在 NIST CVE 資料庫中無相關漏洞記錄，可能為安全套件或資料庫尚未收錄';
      } else if (errorMessage.includes('timeout') || errorMessage.includes('network')) {
        reason = '網路連線問題，無法查詢版本推薦資訊';
      } else {
        reason = `查詢失敗：${errorMessage}`;
      }
    } else {
      reason = '無可用的版本推薦資訊';
    }
    
    return {
      packageName,
      currentVersion,
      reason,
      fixedVersions: [],
      hasData: false,
      updateStrategy: 'unknown'
    };
  }
}