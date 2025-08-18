import { Injectable } from '@angular/core';
import { Vulnerability, PackageInfo, VexStatus } from '../models/vulnerability.model';
import { isVersionGreaterOrEqual } from '../../shared/utils/version-utils';

@Injectable({
  providedIn: 'root'
})
export class VexAnalysisService {

  constructor() { }

  /**
   * 分析並設定漏洞的 VEX 狀態
   */
  analyzeVulnerabilityStatus(
    vulnerability: Vulnerability, 
    packageInfo: PackageInfo
  ): Vulnerability {
    const vexStatus = this.determineVexStatus(vulnerability, packageInfo);
    const vexJustification = this.generateVexJustification(vexStatus, vulnerability, packageInfo);

    return {
      ...vulnerability,
      vexStatus,
      vexJustification
    };
  }

  /**
   * 批次分析漏洞狀態
   */
  analyzeVulnerabilities(
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    packages: PackageInfo[]
  ): {packageName: string, vulnerabilities: Vulnerability[]}[] {
    return scanResults.map(result => {
      const packageInfo = packages.find(pkg => 
        pkg.name === result.packageName || 
        pkg.packageKey === result.packageName ||
        `${pkg.name}@${pkg.version}` === result.packageName
      );

      if (!packageInfo) {
        return result;
      }

      const analyzedVulnerabilities = result.vulnerabilities.map(vuln => 
        this.analyzeVulnerabilityStatus(vuln, packageInfo)
      );

      return {
        ...result,
        vulnerabilities: analyzedVulnerabilities
      };
    });
  }

  /**
   * 決定 VEX 狀態
   */
  private determineVexStatus(
    vulnerability: Vulnerability, 
    packageInfo: PackageInfo
  ): VexStatus {
    // 如果有修復版本且當前版本大於等於修復版本，則標記為已修復
    if (vulnerability.fixedVersion && packageInfo.version) {
      try {
        if (isVersionGreaterOrEqual(packageInfo.version, vulnerability.fixedVersion)) {
          return 'fixed';
        }
      } catch (error) {
        console.warn('版本比較失敗:', error);
      }
    }

    // 其他情況視為受影響
    return 'affected';
  }

  /**
   * 產生 VEX 說明
   */
  private generateVexJustification(
    status: VexStatus,
    vulnerability: Vulnerability,
    packageInfo: PackageInfo
  ): string {
    switch (status) {
      case 'fixed':
        return `套件版本 ${packageInfo.version} 已包含修復 (修復版本: ${vulnerability.fixedVersion})`;
      
      case 'affected':
        if (vulnerability.fixedVersion) {
          return `套件版本 ${packageInfo.version} 受此漏洞影響，建議升級至 ${vulnerability.fixedVersion} 或更新版本`;
        }
        return `套件版本 ${packageInfo.version} 受此漏洞影響，目前尚無修復版本`;
      
      case 'not_affected':
        return '經分析此套件不受此漏洞影響';
      
      case 'under_investigation':
        return '此漏洞影響程度正在調查中';
      
      default:
        return '漏洞狀態未知';
    }
  }

  /**
   * 取得 VEX 狀態統計
   */
  getVexStatusSummary(
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]
  ): {
    affected: number;
    fixed: number;
    notAffected: number;
    underInvestigation: number;
    unknown: number;
  } {
    const summary = {
      affected: 0,
      fixed: 0,
      notAffected: 0,
      underInvestigation: 0,
      unknown: 0
    };

    scanResults.forEach(result => {
      result.vulnerabilities.forEach(vuln => {
        switch (vuln.vexStatus) {
          case 'affected':
            summary.affected++;
            break;
          case 'fixed':
            summary.fixed++;
            break;
          case 'not_affected':
            summary.notAffected++;
            break;
          case 'under_investigation':
            summary.underInvestigation++;
            break;
          default:
            summary.unknown++;
        }
      });
    });

    return summary;
  }

  /**
   * 檢查套件是否有已修復的漏洞
   */
  hasFixedVulnerabilities(packageInfo: PackageInfo, vulnerabilities: Vulnerability[]): boolean {
    return vulnerabilities.some(vuln => {
      if (!vuln.fixedVersion) return false;
      try {
        return isVersionGreaterOrEqual(packageInfo.version, vuln.fixedVersion);
      } catch {
        return false;
      }
    });
  }

  /**
   * 取得修復建議
   */
  getFixRecommendations(
    packageInfo: PackageInfo, 
    vulnerabilities: Vulnerability[]
  ): {
    hasRecommendations: boolean;
    recommendedVersion?: string;
    fixableCount: number;
    totalCount: number;
  } {
    const fixableVulns = vulnerabilities.filter(vuln => vuln.fixedVersion);
    
    if (fixableVulns.length === 0) {
      return {
        hasRecommendations: false,
        fixableCount: 0,
        totalCount: vulnerabilities.length
      };
    }

    // 找出最高的修復版本
    const fixVersions = fixableVulns
      .map(vuln => vuln.fixedVersion!)
      .filter(version => version);

    if (fixVersions.length === 0) {
      return {
        hasRecommendations: false,
        fixableCount: 0,
        totalCount: vulnerabilities.length
      };
    }

    // 簡單的版本排序（可以改進為更準確的 semver 排序）
    const recommendedVersion = fixVersions.sort().pop();

    return {
      hasRecommendations: true,
      recommendedVersion,
      fixableCount: fixableVulns.length,
      totalCount: vulnerabilities.length
    };
  }
}