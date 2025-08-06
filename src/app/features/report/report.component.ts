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
import { PackageInfo, Vulnerability } from '../../core/models/vulnerability.model';
import { ReportExportService } from '../../core/services/report-export.service';
import { PerformanceTestHelper } from '../../shared/components/performance-test-helper';

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
    VirtualScrollPackagesComponent
  ],
  templateUrl: './report.component.html',
  styleUrls: ['./report.component.scss']
})
export class ReportComponent implements OnInit {
  packages: PackageInfo[] = [];
  scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];
  scanTimestamp: Date = new Date();

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
  
  testLargeDataset(): void {
    console.log('🧪 開始效能測試 - 生成大量測試資料...');
    
    PerformanceTestHelper.measurePerformance('資料生成', () => {
      this.scanResults = PerformanceTestHelper.generateLargeDataset(50, 8);
      this.packages = this.scanResults.map(result => ({
        name: result.packageName,
        version: '1.0.0',
        type: 'dependency' as const
      }));
    });
    
    PerformanceTestHelper.logMemoryUsage('資料載入後');
    PerformanceTestHelper.logVirtualScrollBenefits(this.scanResults.length * 8);
    
    // 重新設定圖表
    this.setupChart();
    
    console.log(`✅ 測試資料已載入: ${this.scanResults.length} 個套件，共 ${this.getTotalVulnerabilities()} 個漏洞`);
  }
}