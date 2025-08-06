import { Component, Input, OnInit, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatExpansionModule } from '@angular/material/expansion';
import { VulnerabilityDetailComponent } from './vulnerability-detail.component';
import { Vulnerability } from '../../core/models/vulnerability.model';

@Component({
  selector: 'app-virtual-scroll-packages',
  standalone: true,
  imports: [
    CommonModule,
    ScrollingModule,
    MatCardModule,
    MatChipsModule,
    MatIconModule,
    MatExpansionModule,
    VulnerabilityDetailComponent
  ],
  template: `
    <div class="virtual-scroll-container">
      <div class="scroll-header" *ngIf="scanResults.length > 0">
        <span>共 {{ scanResults.length }} 個套件，按風險等級排序</span>
      </div>
      <cdk-virtual-scroll-viewport 
        [itemSize]="itemHeight" 
        class="packages-viewport"
        [style.height.px]="viewportHeight">
        <mat-card *cdkVirtualFor="let result of scanResults; trackBy: trackByFn" 
                  class="package-card"
                  [class]="'risk-' + getPackageRiskLevel(result.vulnerabilities)">
          <mat-card-header>
            <mat-card-title>{{ result.packageName }}</mat-card-title>
            <mat-card-subtitle>
              <mat-chip-set>
                <mat-chip 
                  [class]="getPackageRiskClass(result.vulnerabilities)"
                  [highlighted]="true">
                  {{ getPackageRiskLabel(result.vulnerabilities) }}
                </mat-chip>
                <mat-chip 
                  [class]="getVulnerabilityCountChipClass(result.vulnerabilities)" 
                  *ngIf="result.vulnerabilities.length > 0">
                  {{ result.vulnerabilities.length }} 個漏洞
                </mat-chip>
              </mat-chip-set>
            </mat-card-subtitle>
          </mat-card-header>
          
          <mat-card-content *ngIf="result.vulnerabilities.length === 0">
            <div class="no-vulnerabilities">
              <mat-icon class="safe-icon">verified</mat-icon>
              <p>此套件沒有發現已知漏洞</p>
            </div>
          </mat-card-content>
          
          <mat-card-content *ngIf="result.vulnerabilities.length > 0">
            <mat-expansion-panel>
              <mat-expansion-panel-header>
                <mat-panel-title>
                  檢視 {{ result.vulnerabilities.length }} 個漏洞詳情
                </mat-panel-title>
              </mat-expansion-panel-header>
              
              <div class="vulnerabilities-list">
                <app-vulnerability-detail 
                  *ngFor="let vulnerability of result.vulnerabilities"
                  [vulnerability]="vulnerability">
                </app-vulnerability-detail>
              </div>
            </mat-expansion-panel>
          </mat-card-content>
        </mat-card>
      </cdk-virtual-scroll-viewport>
      <div class="empty-state" *ngIf="scanResults.length === 0">
        <mat-icon>inbox</mat-icon>
        <p>沒有套件資料</p>
      </div>
    </div>
  `,
  styles: [`
    .virtual-scroll-container {
      width: 100%;
      height: 100%;
    }
    
    .packages-viewport {
      width: 100%;
      padding: 8px;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
    }
    
    .package-card {
      margin: 8px 0;
      transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    
    .package-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    
    .risk-critical {
      border-left: 4px solid #d32f2f;
    }
    
    .risk-high {
      border-left: 4px solid #f57c00;
    }
    
    .risk-medium {
      border-left: 4px solid #e65100;
    }
    
    .risk-low {
      border-left: 4px solid #388e3c;
    }
    
    .risk-safe {
      border-left: 4px solid #4caf50;
    }
    
    .no-vulnerabilities {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 16px;
      background-color: #e8f5e8;
      border-radius: 8px;
      color: #2e7d32;
    }
    
    .safe-icon {
      color: #4caf50;
    }
    
    .vulnerabilities-list {
      margin-top: 16px;
    }
    
    /* 自訂捲軸樣式 */
    .packages-viewport::-webkit-scrollbar {
      width: 8px;
    }
    
    .packages-viewport::-webkit-scrollbar-track {
      background: #f1f1f1;
      border-radius: 4px;
    }
    
    .packages-viewport::-webkit-scrollbar-thumb {
      background: #c1c1c1;
      border-radius: 4px;
    }
    
    .packages-viewport::-webkit-scrollbar-thumb:hover {
      background: #a8a8a8;
    }
    
    .scroll-header {
      padding: 12px 16px;
      background-color: #e8f5e8;
      border-bottom: 1px solid #c8e6c9;
      color: #2e7d32;
      font-size: 14px;
      font-weight: 500;
    }
    
    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100%;
      color: #757575;
      gap: 16px;
      
      mat-icon {
        font-size: 48px;
        width: 48px;
        height: 48px;
        color: #9e9e9e;
      }
      
      p {
        margin: 0;
        font-size: 16px;
      }
    }
  `]
})
export class VirtualScrollPackagesComponent implements OnInit, OnChanges {
  @Input() scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];
  @Input() viewportHeight: number = 600;
  @Input() itemHeight: number = 200; // 套件卡片的估計高度
  
  ngOnInit(): void {
    this.sortPackagesByRisk();
  }
  
  ngOnChanges(): void {
    this.sortPackagesByRisk();
  }
  
  private sortPackagesByRisk(): void {
    this.scanResults.sort((a, b) => {
      const aRiskLevel = this.getRiskScore(a.vulnerabilities);
      const bRiskLevel = this.getRiskScore(b.vulnerabilities);
      return bRiskLevel - aRiskLevel; // 高風險排在前面
    });
  }
  
  private getRiskScore(vulnerabilities: Vulnerability[]): number {
    if (vulnerabilities.length === 0) return 0;
    
    let score = 0;
    vulnerabilities.forEach(v => {
      switch (v.severity) {
        case 'CRITICAL': score += 100; break;
        case 'HIGH': score += 50; break;
        case 'MEDIUM': score += 25; break;
        case 'LOW': score += 10; break;
      }
    });
    return score;
  }
  
  trackByFn(index: number, item: {packageName: string, vulnerabilities: Vulnerability[]}): string {
    return item.packageName;
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
}