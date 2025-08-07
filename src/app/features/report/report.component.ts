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
    private reportExportService: ReportExportService
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
    
    // 取得主套件（dependency 和 devDependency）
    const mainPackages = this.packages.filter(pkg => 
      pkg.type === 'dependency' || pkg.type === 'devDependency'
    );
    
    // 取得間接相依套件
    const transitivePackages = this.packages.filter(pkg => pkg.type === 'transitive');
    
    // 為每個主套件建立分組
    mainPackages.forEach(mainPkg => {
      const mainScanResult = this.scanResults.find(result => result.packageName === mainPkg.name);
      
      if (mainScanResult) {
        // 找到相關的間接相依套件（這裡簡化處理，實際可能需要更複雜的依賴樹分析）
        const relatedDependencies = transitivePackages
          .map(transPkg => {
            const transScanResult = this.scanResults.find(result => result.packageName === transPkg.name);
            return transScanResult ? {
              packageName: transPkg.name,
              vulnerabilities: transScanResult.vulnerabilities,
              packageInfo: transPkg
            } : null;
          })
          .filter(dep => dep !== null) as {packageName: string, vulnerabilities: Vulnerability[], packageInfo: PackageInfo}[];
        
        this.groupedScanResults.push({
          mainPackage: {
            packageName: mainPkg.name,
            vulnerabilities: mainScanResult.vulnerabilities,
            packageInfo: mainPkg
          },
          dependencies: relatedDependencies
        });
      }
    });
    
    // 如果有孤立的間接相依套件（沒有對應的主套件），加入到"其他套件"分組
    const orphanTransitivePackages = transitivePackages.filter(transPkg => {
      return !this.groupedScanResults.some(group => 
        group.dependencies.some(dep => dep.packageName === transPkg.name)
      );
    });
    
    if (orphanTransitivePackages.length > 0) {
      const orphanScanResults = orphanTransitivePackages
        .map(pkg => {
          const scanResult = this.scanResults.find(result => result.packageName === pkg.name);
          return scanResult ? {
            packageName: pkg.name,
            vulnerabilities: scanResult.vulnerabilities,
            packageInfo: pkg
          } : null;
        })
        .filter(result => result !== null) as {packageName: string, vulnerabilities: Vulnerability[], packageInfo: PackageInfo}[];
      
      if (orphanScanResults.length > 0) {
        this.groupedScanResults.push({
          mainPackage: {
            packageName: '其他間接相依套件',
            vulnerabilities: [],
            packageInfo: undefined
          },
          dependencies: orphanScanResults
        });
      }
    }
  }
  
}