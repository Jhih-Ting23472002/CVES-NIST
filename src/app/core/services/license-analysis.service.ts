import { Injectable } from '@angular/core';
import { PackageInfo } from '../models/vulnerability.model';

@Injectable({
  providedIn: 'root'
})
export class LicenseAnalysisService {

  // 常見套件的已知授權映射
  private readonly KNOWN_LICENSES: Record<string, string> = {
    // 熱門套件
    'lodash': 'MIT',
    'express': 'MIT',
    'axios': 'MIT',
    'react': 'MIT',
    'vue': 'MIT',
    'angular': 'MIT',
    '@angular/core': 'MIT',
    '@angular/common': 'MIT',
    'typescript': 'Apache-2.0',
    'jest': 'MIT',
    'mocha': 'MIT',
    'webpack': 'MIT',
    'babel-core': 'MIT',
    '@babel/core': 'MIT',
    'eslint': 'MIT',
    'prettier': 'MIT',
    'moment': 'MIT',
    'uuid': 'MIT',
    'crypto-js': 'MIT',
    'fs-extra': 'MIT',
    'commander': 'MIT',
    'chalk': 'MIT',
    'debug': 'MIT',
    'semver': 'ISC',
    'glob': 'ISC',
    'minimist': 'MIT',
    'yargs': 'MIT',
    'inquirer': 'MIT',
    'rxjs': 'Apache-2.0',
    'zone.js': 'MIT',
    'tslib': '0BSD',
    // Node.js 核心模組相關
    'node-fetch': 'MIT',
    'cross-env': 'MIT',
    'dotenv': 'BSD-2-Clause'
  };

  constructor() { }

  /**
   * 分析套件的授權資訊
   */
  analyzeLicense(packageInfo: any, source: 'package-json' | 'package-lock'): {
    license?: string;
    licenseDeclared?: string;
    licenseConcluded?: string;
    licenseSource: 'package-json' | 'package-lock' | 'inferred' | 'registry';
  } {
    let license: string | undefined;
    let licenseDeclared: string | undefined;
    let licenseConcluded: string | undefined;
    let licenseSource: 'package-json' | 'package-lock' | 'inferred' | 'registry' = source;

    // 提取原始授權資訊
    if (packageInfo.license) {
      if (typeof packageInfo.license === 'string') {
        license = packageInfo.license;
        licenseDeclared = packageInfo.license;
      } else if (typeof packageInfo.license === 'object' && packageInfo.license.type) {
        license = packageInfo.license.type;
        licenseDeclared = packageInfo.license.type;
      }
    }

    // 如果沒有授權資訊，嘗試從已知映射推斷
    if (!license && packageInfo.name) {
      const inferredLicense = this.inferLicenseFromPackageName(packageInfo.name);
      if (inferredLicense) {
        license = inferredLicense;
        licenseConcluded = inferredLicense;
        licenseSource = 'inferred';
      }
    }

    // 分析得出的授權（如果有聲明的授權，將其作為分析結果）
    if (licenseDeclared && !licenseConcluded) {
      licenseConcluded = this.normalizeLicense(licenseDeclared);
    }

    return {
      license,
      licenseDeclared,
      licenseConcluded,
      licenseSource
    };
  }

  /**
   * 從套件名稱推斷授權
   */
  private inferLicenseFromPackageName(packageName: string): string | undefined {
    // 完全匹配
    if (this.KNOWN_LICENSES[packageName]) {
      return this.KNOWN_LICENSES[packageName];
    }

    // 前綴匹配（用於 scoped packages）
    for (const [knownPackage, license] of Object.entries(this.KNOWN_LICENSES)) {
      if (packageName.startsWith(knownPackage)) {
        return license;
      }
    }

    // 特殊模式匹配
    if (packageName.startsWith('@types/')) {
      return 'MIT'; // TypeScript 類型定義通常是 MIT
    }

    if (packageName.startsWith('@angular/')) {
      return 'MIT'; // Angular 套件通常是 MIT
    }

    if (packageName.startsWith('@babel/')) {
      return 'MIT'; // Babel 套件通常是 MIT
    }

    if (packageName.startsWith('eslint-')) {
      return 'MIT'; // ESLint 相關套件通常是 MIT
    }

    return undefined;
  }

  /**
   * 正規化授權名稱
   */
  private normalizeLicense(license: string): string {
    const normalized = license.trim().toUpperCase();

    // 常見的授權別名映射
    const aliasMap: Record<string, string> = {
      'APACHE': 'Apache-2.0',
      'APACHE2': 'Apache-2.0',
      'APACHE-2': 'Apache-2.0',
      'APACHE 2.0': 'Apache-2.0',
      'GPL': 'GPL-3.0',
      'GPLV3': 'GPL-3.0',
      'GPL-3': 'GPL-3.0',
      'GPL V3': 'GPL-3.0',
      'LGPL': 'LGPL-3.0',
      'BSD': 'BSD-3-Clause',
      'BSD3': 'BSD-3-Clause',
      'BSD-3': 'BSD-3-Clause',
      'ISC LICENSE': 'ISC',
      'MIT LICENSE': 'MIT',
      'MOZILLA': 'MPL-2.0',
      'MPL': 'MPL-2.0'
    };

    return aliasMap[normalized] || license;
  }

  /**
   * 增強套件資訊的授權分析
   */
  enhancePackageWithLicenseInfo(
    packageInfo: PackageInfo, 
    source: 'package-json' | 'package-lock'
  ): PackageInfo {
    const licenseAnalysis = this.analyzeLicense(packageInfo, source);

    return {
      ...packageInfo,
      license: licenseAnalysis.license || packageInfo.license,
      licenseDeclared: licenseAnalysis.licenseDeclared,
      licenseConcluded: licenseAnalysis.licenseConcluded,
      licenseSource: licenseAnalysis.licenseSource
    };
  }

  /**
   * 批次增強套件授權資訊
   */
  enhancePackagesWithLicenseInfo(
    packages: PackageInfo[],
    source: 'package-json' | 'package-lock' = 'package-lock'
  ): PackageInfo[] {
    return packages.map(pkg => this.enhancePackageWithLicenseInfo(pkg, source));
  }

  /**
   * 取得授權統計
   */
  getLicenseStatistics(packages: PackageInfo[]): {
    totalPackages: number;
    licensedPackages: number;
    unlicensedPackages: number;
    inferredLicenses: number;
    licenseBreakdown: Record<string, number>;
    sourceBreakdown: Record<string, number>;
  } {
    const stats = {
      totalPackages: packages.length,
      licensedPackages: 0,
      unlicensedPackages: 0,
      inferredLicenses: 0,
      licenseBreakdown: {} as Record<string, number>,
      sourceBreakdown: {
        'package-json': 0,
        'package-lock': 0,
        'inferred': 0,
        'registry': 0
      }
    };

    packages.forEach(pkg => {
      // 統計有無授權
      if (pkg.licenseConcluded || pkg.licenseDeclared || pkg.license) {
        stats.licensedPackages++;
      } else {
        stats.unlicensedPackages++;
      }

      // 統計推斷的授權
      if (pkg.licenseSource === 'inferred') {
        stats.inferredLicenses++;
      }

      // 統計授權類型分佈
      const license = pkg.licenseConcluded || pkg.licenseDeclared || pkg.license || 'Unknown';
      stats.licenseBreakdown[license] = (stats.licenseBreakdown[license] || 0) + 1;

      // 統計授權來源分佈
      if (pkg.licenseSource) {
        stats.sourceBreakdown[pkg.licenseSource]++;
      }
    });

    return stats;
  }

  /**
   * 檢查授權相容性（基本檢查）
   */
  checkLicenseCompatibility(packages: PackageInfo[]): {
    potentialIssues: {
      packageName: string;
      license: string;
      issue: string;
    }[];
    riskLevel: 'low' | 'medium' | 'high';
  } {
    const issues: {packageName: string; license: string; issue: string}[] = [];
    
    // 高風險授權清單
    const highRiskLicenses = ['GPL-3.0', 'GPL-2.0', 'AGPL-3.0', 'LGPL-3.0'];
    const mediumRiskLicenses = ['MPL-2.0', 'EPL-2.0', 'CDDL-1.0'];

    packages.forEach(pkg => {
      const license = pkg.licenseConcluded || pkg.licenseDeclared || pkg.license;
      if (!license) return;

      if (highRiskLicenses.includes(license)) {
        issues.push({
          packageName: pkg.name,
          license,
          issue: '此授權可能要求衍生作品也使用相同授權（Copyleft）'
        });
      } else if (mediumRiskLicenses.includes(license)) {
        issues.push({
          packageName: pkg.name,
          license,
          issue: '此授權有特殊要求，建議詳細檢查授權條款'
        });
      }
    });

    let riskLevel: 'low' | 'medium' | 'high' = 'low';
    if (issues.some(issue => highRiskLicenses.includes(issue.license))) {
      riskLevel = 'high';
    } else if (issues.length > 0) {
      riskLevel = 'medium';
    }

    return { potentialIssues: issues, riskLevel };
  }
}