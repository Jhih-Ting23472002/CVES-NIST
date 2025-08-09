import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTabsModule } from '@angular/material/tabs';
import { MatChipsModule } from '@angular/material/chips';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatTooltipModule } from '@angular/material/tooltip';
import { BaseChartDirective } from 'ng2-charts';
import { ChartConfiguration, ChartType } from 'chart.js';

import { VirtualScrollVulnerabilitiesComponent } from '../../shared/components/virtual-scroll-vulnerabilities.component';
import { VirtualScrollPackagesComponent } from '../../shared/components/virtual-scroll-packages.component';
import { VulnerabilityDetailComponent } from '../../shared/components/vulnerability-detail.component';
import { PackageInfo, Vulnerability } from '../../core/models/vulnerability.model';
import { ReportExportService } from '../../core/services/report-export.service';
import { VersionRecommendationService } from '../../core/services/version-recommendation.service';

@Component({
  selector: 'app-report',
  standalone: true,
  imports: [
    CommonModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatTabsModule,
    MatChipsModule,
    MatExpansionModule,
    MatTooltipModule,
    BaseChartDirective,
    VirtualScrollVulnerabilitiesComponent,
    VirtualScrollPackagesComponent,
    VulnerabilityDetailComponent
  ],
  templateUrl: './report.component.html',
  styleUrls: ['./report.component.scss']
})
export class ReportComponent implements OnInit {
  packages: PackageInfo[] = [];
  scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];
  scanTimestamp: Date = new Date();
  groupedScanResults: {
    mainPackage: {packageName: string, vulnerabilities: Vulnerability[], packageInfo?: PackageInfo},
    dependencies: {packageName: string, vulnerabilities: Vulnerability[], packageInfo?: PackageInfo}[]
  }[] = [];
  
  // 版本推薦相關
  versionRecommendations: Map<string, any> = new Map(); // 使用套件名稱作為 key
  loadingRecommendations: boolean = false;
  recommendationErrors: Map<string, string> = new Map();
  packageRecommendationStatus: Map<string, 'loading' | 'completed' | 'error'> = new Map();

  // 圖表配置
  doughnutChartType: ChartType = 'doughnut';
  doughnutChartData: ChartConfiguration<'doughnut'>['data'] = {
    labels: [],
    datasets: [{
      data: [],
      backgroundColor: [
        '#d32f2f', // Critical
        '#f57c00', // High  
        '#e65100', // Medium (updated color)
        '#388e3c'  // Low
      ]
    }]
  };
  doughnutChartOptions: ChartConfiguration<'doughnut'>['options'] = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      legend: {
        position: 'bottom'
      }
    }
  };

  constructor(
    private router: Router,
    private reportExportService: ReportExportService,
    private versionRecommendationService: VersionRecommendationService
  ) {
    // 從路由狀態取得資料
    const navigation = this.router.getCurrentNavigation();
    if (navigation?.extras?.state) {
      this.packages = navigation.extras.state['packages'] || [];
      this.scanResults = navigation.extras.state['scanResults'] || [];
      this.scanTimestamp = navigation.extras.state['scanTimestamp'] || new Date();
    } else {
      // 如果沒有路由狀態，嘗試從 history.state 取得
      const state = history.state;
      if (state) {
        this.packages = state.packages || [];
        this.scanResults = state.scanResults || [];
        this.scanTimestamp = state.scanTimestamp || new Date();
      }
    }
  }

  ngOnInit(): void {
    console.log('Report component initialized');
    console.log('Packages:', this.packages.length);
    console.log('Scan results:', this.scanResults.length);
    
    if (this.packages.length === 0 && this.scanResults.length === 0) {
      console.warn('No data available, creating demo data for testing');
      // 為了測試目的，創建一些示例資料
      this.createDemoData();
    }
    
    this.setupChart();
    this.groupScanResults();
    this.loadVersionRecommendations();
  }

  private createDemoData(): void {
    // 創建示例套件資料
    this.packages = [
      { name: 'crypto-js', version: '3.1.2', type: 'dependency' },
      { name: 'lodash', version: '4.17.15', type: 'dependency' },
      { name: 'express', version: '4.18.2', type: 'dependency' }
    ];

    // 創建示例漏洞資料
    this.scanResults = [
      {
        packageName: 'crypto-js',
        vulnerabilities: [
          {
            cveId: 'CVE-2023-46233',
            description: 'crypto-js PBKDF2 is 1,000 times weaker than originally specified in 1993, and at least 1,300,000 times weaker than current industry standard.',
            severity: 'CRITICAL',
            cvssScore: 9.1,
            cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
            publishedDate: '2023-10-25T21:15:10.307',
            lastModifiedDate: '2024-11-21T08:28:07.867',
            references: [
              'https://github.com/brix/crypto-js/commit/421dd538b2d34e7c24a5b72cc64dc2b9167db40a',
              'https://github.com/brix/crypto-js/security/advisories/GHSA-xwcq-pm8m-c4vf'
            ],
            affectedVersions: ['< 4.2.0'],
            fixedVersion: '4.2.0'
          }
        ]
      },
      {
        packageName: 'lodash', 
        vulnerabilities: []
      },
      {
        packageName: 'express',
        vulnerabilities: []
      }
    ];
  }

  setupChart(): void {
    const critical = this.getSeverityCount('CRITICAL');
    const high = this.getSeverityCount('HIGH');
    const medium = this.getSeverityCount('MEDIUM');
    const low = this.getSeverityCount('LOW');

    if (critical + high + medium + low > 0) {
      this.doughnutChartData.labels = [];
      this.doughnutChartData.datasets[0].data = [];

      if (critical > 0) {
        this.doughnutChartData.labels.push(`嚴重 (${critical})`);
        this.doughnutChartData.datasets[0].data.push(critical);
      }
      if (high > 0) {
        this.doughnutChartData.labels.push(`高風險 (${high})`);
        this.doughnutChartData.datasets[0].data.push(high);
      }
      if (medium > 0) {
        this.doughnutChartData.labels.push(`中風險 (${medium})`);
        this.doughnutChartData.datasets[0].data.push(medium);
      }
      if (low > 0) {
        this.doughnutChartData.labels.push(`低風險 (${low})`);
        this.doughnutChartData.datasets[0].data.push(low);
      }
    }
  }

  getSeverityCount(severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'): number {
    return this.scanResults.reduce((count, result) => {
      return count + result.vulnerabilities.filter(v => v.severity === severity).length;
    }, 0);
  }

  getSafePackagesCount(): number {
    return this.scanResults.filter(result => result.vulnerabilities.length === 0).length;
  }

  getTotalVulnerabilities(): number {
    return this.scanResults.reduce((total, result) => total + result.vulnerabilities.length, 0);
  }

  getPackageRiskClass(vulnerabilities: Vulnerability[]): string {
    if (vulnerabilities.length === 0) return 'package-risk-safe';
    
    const severities = vulnerabilities.map(v => v.severity);
    if (severities.includes('CRITICAL')) return 'package-risk-critical';
    if (severities.includes('HIGH')) return 'package-risk-high';
    if (severities.includes('MEDIUM')) return 'package-risk-medium';
    return 'package-risk-low';
  }

  getPackageRiskLabel(vulnerabilities: Vulnerability[]): string {
    if (vulnerabilities.length === 0) return '安全';
    
    const severities = vulnerabilities.map(v => v.severity);
    if (severities.includes('CRITICAL')) return '嚴重風險';
    if (severities.includes('HIGH')) return '高風險';
    if (severities.includes('MEDIUM')) return '中風險';
    return '低風險';
  }

  getPackageRiskLevel(vulnerabilities: Vulnerability[]): string {
    if (vulnerabilities.length === 0) return 'safe';
    
    const severities = vulnerabilities.map(v => v.severity);
    if (severities.includes('CRITICAL')) return 'critical';
    if (severities.includes('HIGH')) return 'high';
    if (severities.includes('MEDIUM')) return 'medium';
    return 'low';
  }

  getVulnerabilityCountChipClass(vulnerabilities: Vulnerability[]): string {
    if (vulnerabilities.length === 0) return '';
    
    const severities = vulnerabilities.map(v => v.severity);
    if (severities.includes('CRITICAL')) return 'count-chip-critical';
    if (severities.includes('HIGH')) return 'count-chip-high';
    if (severities.includes('MEDIUM')) return 'count-chip-medium';
    return 'count-chip-low';
  }

  formatScanTimestamp(): string {
    return this.scanTimestamp.toLocaleString('zh-TW', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    });
  }

  exportAsJson(): void {
    this.reportExportService.exportAsJson(this.packages, this.scanResults, this.scanTimestamp);
  }

  exportAsCsv(): void {
    this.reportExportService.exportAsCsv(this.packages, this.scanResults, this.scanTimestamp);
  }

  exportAsHtml(): void {
    this.reportExportService.exportAsHtml(this.packages, this.scanResults, this.scanTimestamp);
  }

  startNewScan(): void {
    this.router.navigate(['/upload']);
  }

  goBack(): void {
    this.router.navigate(['/scan']);
  }

  trackByGroupFn(_: number, group: any): string {
    return group.mainPackage.packageName;
  }

  trackByDepFn(_: number, dep: any): string {
    return dep.packageName;
  }

  /**
   * 載入版本推薦
   */
  private loadVersionRecommendations(): void {
    if (this.packages.length === 0) {
      return;
    }

    this.loadingRecommendations = true;
    console.log(`開始為 ${this.packages.length} 個套件載入版本推薦`);

    // 為所有主要套件推薦版本（不只是有漏洞的）
    const mainPackages = this.packages.filter(pkg => 
      pkg.type === 'dependency' || pkg.type === 'devDependency'
    );

    if (mainPackages.length === 0) {
      console.log('沒有主要套件需要推薦版本');
      this.loadingRecommendations = false;
      return;
    }

    console.log(`為 ${mainPackages.length} 個主要套件推薦版本`);

    // 標記所有套件為載入中
    mainPackages.forEach(pkg => {
      this.packageRecommendationStatus.set(pkg.name, 'loading');
    });

    this.versionRecommendationService.recommendVersions(mainPackages)
      .subscribe({
        next: (recommendations) => {
          console.log(`成功取得 ${recommendations.length} 個版本推薦`);
          recommendations.forEach(rec => {
            // 使用套件名稱作為 key，不是 currentVersion
            this.versionRecommendations.set(rec.packageName, rec);
            this.packageRecommendationStatus.set(rec.packageName, 'completed');
          });
          
          // 標記沒有推薦結果的套件為錯誤
          mainPackages.forEach(pkg => {
            if (!this.versionRecommendations.has(pkg.name)) {
              this.packageRecommendationStatus.set(pkg.name, 'error');
              this.recommendationErrors.set(pkg.name, '無法取得版本推薦');
            }
          });
          
          this.loadingRecommendations = false;
        },
        error: (error) => {
          console.error('載入版本推薦失敗:', error);
          // 標記所有套件為錯誤
          mainPackages.forEach(pkg => {
            this.packageRecommendationStatus.set(pkg.name, 'error');
            this.recommendationErrors.set(pkg.name, error.message || '版本推薦失敗');
          });
          this.loadingRecommendations = false;
        }
      });
  }

  /**
   * 為單一套件載入版本推薦
   */
  loadRecommendationForPackage(packageInfo: PackageInfo): void {
    const packageName = packageInfo.name;
    
    if (this.versionRecommendations.has(packageName) || this.recommendationErrors.has(packageName)) {
      return; // 已經載入過或有錯誤
    }

    console.log(`載入 ${packageInfo.name} 的版本推薦`);
    this.packageRecommendationStatus.set(packageName, 'loading');

    this.versionRecommendationService.recommendVersion(packageInfo.name, packageInfo.version)
      .subscribe({
        next: (recommendation) => {
          this.versionRecommendations.set(packageName, recommendation);
          this.packageRecommendationStatus.set(packageName, 'completed');
          console.log(`成功取得 ${packageInfo.name} 的版本推薦`);
        },
        error: (error) => {
          console.error(`載入 ${packageInfo.name} 版本推薦失敗:`, error);
          this.packageRecommendationStatus.set(packageName, 'error');
          this.recommendationErrors.set(packageName, error.message || '版本推薦失敗');
        }
      });
  }

  /**
   * 取得套件的版本推薦
   */
  getRecommendation(packageInfo: PackageInfo | undefined): any | null {
    if (!packageInfo) return null;
    return this.versionRecommendations.get(packageInfo.name);
  }

  /**
   * 取得推薦錯誤
   */
  getRecommendationError(packageInfo: PackageInfo | undefined): string | null {
    if (!packageInfo) return null;
    return this.recommendationErrors.get(packageInfo.name) || null;
  }

  /**
   * 判斷是否需要顯示版本推薦
   */
  shouldShowRecommendation(packageInfo: PackageInfo | undefined): boolean {
    if (!packageInfo) return false;
    
    // 所有主要套件都顯示版本推薦，不只是有漏洞的
    return packageInfo.type === 'dependency' || packageInfo.type === 'devDependency';
  }

  /**
   * 取得更新策略顯示文字
   */
  getUpdateStrategyText(strategy: string): string {
    switch (strategy) {
      case 'patch': return '修正版更新';
      case 'minor': return '次要版更新';
      case 'major': return '主要版更新';
      case 'none': return '無需更新';
      case 'unknown': return '無法確定';
      default: return '建議更新';
    }
  }

  /**
   * 取得更新策略樣式
   */
  getUpdateStrategyClass(strategy: string): string {
    switch (strategy) {
      case 'patch': return 'update-strategy-patch';
      case 'minor': return 'update-strategy-minor';
      case 'major': return 'update-strategy-major';
      case 'none': return 'update-strategy-none';
      case 'unknown': return 'update-strategy-unknown';
      default: return 'update-strategy-default';
    }
  }

  /**
   * 取得套件推薦狀態
   */
  getPackageRecommendationStatus(packageInfo: PackageInfo | undefined): 'loading' | 'completed' | 'error' | 'none' {
    if (!packageInfo) return 'none';
    return this.packageRecommendationStatus.get(packageInfo.name) || 'none';
  }

  /**
   * 取得套件類型標籤
   */
  getPackageTypeLabel(type: 'dependency' | 'devDependency' | 'transitive'): string {
    switch (type) {
      case 'dependency': return '主要相依';
      case 'devDependency': return '開發相依';
      case 'transitive': return '間接相依';
      default: return '未知';
    }
  }

  private groupScanResults(): void {
    this.groupedScanResults = [];
    
    // 按套件名稱分組所有套件和掃描結果
    const packagesByName = new Map<string, PackageInfo[]>();
    const scanResultsByName = new Map<string, {packageName: string, vulnerabilities: Vulnerability[]}[]>();
    
    // 分組套件
    this.packages.forEach(pkg => {
      if (!packagesByName.has(pkg.name)) {
        packagesByName.set(pkg.name, []);
      }
      packagesByName.get(pkg.name)!.push(pkg);
    });
    
    // 分組掃描結果（按套件名稱和版本）
    this.scanResults.forEach(result => {
      const key = result.packageName;
      if (!scanResultsByName.has(key)) {
        scanResultsByName.set(key, []);
      }
      scanResultsByName.get(key)!.push(result);
    });
    
    // 取得主套件（dependency 和 devDependency）
    const mainPackageNames = new Set<string>();
    this.packages.forEach(pkg => {
      if (pkg.type === 'dependency' || pkg.type === 'devDependency') {
        mainPackageNames.add(pkg.name);
      }
    });
    
    // 為每個主套件建立分組
    mainPackageNames.forEach(packageName => {
      const packageVersions = packagesByName.get(packageName) || [];
      // 為這個套件名稱收集所有版本的掃描結果
      const scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];
      packageVersions.forEach(pkg => {
        const pkgKey = pkg.packageKey || `${pkg.name}@${pkg.version}`;
        const results = scanResultsByName.get(pkgKey) || [];
        scanResults.push(...results);
      });
      
      if (packageVersions.length > 0) {
        // 找到優先級最高的套件版本作為主要顯示
        const mainPackage = packageVersions.sort((a, b) => {
          const typePriority = { 'dependency': 0, 'devDependency': 1, 'transitive': 2 };
          return typePriority[a.type] - typePriority[b.type];
        })[0];
        
        // 合併所有版本的漏洞
        const allVulnerabilities = scanResults.reduce((acc, result) => {
          return acc.concat(result.vulnerabilities);
        }, [] as Vulnerability[]);
        
        // 去除重複的漏洞（同一 CVE ID）
        const uniqueVulnerabilities = this.deduplicateVulnerabilities(allVulnerabilities);
        
        // 找到相關的間接相依套件
        const transitivePackages = this.packages.filter(pkg => pkg.type === 'transitive');
        const relatedDependencies = transitivePackages
          .map(transPkg => {
            const pkgKey = transPkg.packageKey || `${transPkg.name}@${transPkg.version}`;
            const transScanResults = scanResultsByName.get(pkgKey) || [];
            const transVulns = transScanResults.reduce((acc, result) => acc.concat(result.vulnerabilities), [] as Vulnerability[]);
            return {
              packageName: transPkg.name,
              vulnerabilities: this.deduplicateVulnerabilities(transVulns),
              packageInfo: transPkg
            };
          })
          .filter(dep => dep.vulnerabilities.length > 0 || dep.packageInfo);
        
        this.groupedScanResults.push({
          mainPackage: {
            packageName: packageName,
            vulnerabilities: uniqueVulnerabilities,
            packageInfo: mainPackage
          },
          dependencies: relatedDependencies
        });
      }
    });
    
    // 處理孤立的間接相依套件
    const orphanTransitiveNames = new Set<string>();
    this.packages.forEach(pkg => {
      if (pkg.type === 'transitive' && !mainPackageNames.has(pkg.name)) {
        orphanTransitiveNames.add(pkg.name);
      }
    });
    
    if (orphanTransitiveNames.size > 0) {
      const orphanResults: {packageName: string, vulnerabilities: Vulnerability[], packageInfo: PackageInfo}[] = [];
      
      orphanTransitiveNames.forEach(packageName => {
        const packageVersions = packagesByName.get(packageName) || [];
        
        // 為這個套件名稱收集所有版本的掃描結果
        const allScanResults: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];
        packageVersions.forEach(pkg => {
          const pkgKey = pkg.packageKey || `${pkg.name}@${pkg.version}`;
          const results = scanResultsByName.get(pkgKey) || [];
          allScanResults.push(...results);
        });
        
        if (packageVersions.length > 0) {
          const allVulns = allScanResults.reduce((acc, result) => acc.concat(result.vulnerabilities), [] as Vulnerability[]);
          orphanResults.push({
            packageName,
            vulnerabilities: this.deduplicateVulnerabilities(allVulns),
            packageInfo: packageVersions[0]
          });
        }
      });
      
      if (orphanResults.length > 0) {
        this.groupedScanResults.push({
          mainPackage: {
            packageName: '其他間接相依套件',
            vulnerabilities: [],
            packageInfo: undefined
          },
          dependencies: orphanResults
        });
      }
    }
  }
  
  // 去除重複的漏洞（基於 CVE ID）
  private deduplicateVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[] {
    const seen = new Set<string>();
    return vulnerabilities.filter(vuln => {
      if (seen.has(vuln.cveId)) {
        return false;
      }
      seen.add(vuln.cveId);
      return true;
    });
  }
  
}