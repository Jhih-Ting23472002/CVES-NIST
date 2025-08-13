import { Component, Input, OnInit, OnChanges, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatButtonModule } from '@angular/material/button';
import { VulnerabilityDetailComponent } from './vulnerability-detail.component';
import { Vulnerability } from '../../core/models/vulnerability.model';
import { Subject, takeUntil, debounceTime } from 'rxjs';

interface VulnerabilityWithPackage extends Vulnerability {
  packageName: string;
}

@Component({
  selector: 'app-virtual-scroll-vulnerabilities',
  standalone: true,
  imports: [
    CommonModule,
    ScrollingModule,
    MatIconModule,
    MatProgressBarModule,
    MatButtonModule,
    VulnerabilityDetailComponent
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="virtual-scroll-container">
      <!-- 載入指示器 -->
      <div class="loading-indicator" *ngIf="isProcessing">
        <mat-progress-bar mode="indeterminate"></mat-progress-bar>
        <p>正在處理漏洞資料... ({{ processedCount }}/{{ totalCount }})</p>
      </div>
      
      <!-- 漏洞統計 -->
      <div class="scroll-header" *ngIf="vulnerabilities.length > 0 && !isProcessing">
        <div class="stats-row">
          <span>共 {{ displayedVulnerabilities.length }}/{{ vulnerabilities.length }} 個漏洞</span>
          <div class="severity-stats">
            <span class="stat critical" *ngIf="severityStats.CRITICAL > 0">
              極危: {{ severityStats.CRITICAL }}
            </span>
            <span class="stat high" *ngIf="severityStats.HIGH > 0">
              高危: {{ severityStats.HIGH }}
            </span>
            <span class="stat medium" *ngIf="severityStats.MEDIUM > 0">
              中危: {{ severityStats.MEDIUM }}
            </span>
            <span class="stat low" *ngIf="severityStats.LOW > 0">
              低危: {{ severityStats.LOW }}
            </span>
          </div>
        </div>
        
        <!-- 批次載入控制 -->
        <div class="batch-controls" *ngIf="vulnerabilities.length > batchSize">
          <button mat-button (click)="loadMoreVulnerabilities()" 
                  [disabled]="displayedVulnerabilities.length >= vulnerabilities.length">
            載入更多 ({{ Math.min(batchSize, vulnerabilities.length - displayedVulnerabilities.length) }} 個)
          </button>
          <button mat-button (click)="loadAllVulnerabilities()" 
                  [disabled]="displayedVulnerabilities.length >= vulnerabilities.length">
            載入全部
          </button>
        </div>
      </div>
      
      <!-- 虛擬滾動視窗 -->
      <cdk-virtual-scroll-viewport 
        [itemSize]="dynamicItemHeight" 
        class="vulnerability-viewport"
        [style.height.px]="viewportHeight"
        *ngIf="!isProcessing">
        <div *cdkVirtualFor="let vulnerability of displayedVulnerabilities; trackBy: trackByFn; 
                              let index = index" 
             class="vulnerability-item"
             [class.expanded]="expandedItems.has(vulnerability.packageName + '-' + vulnerability.cveId)">
          <div class="package-header" 
               (click)="toggleExpanded(vulnerability.packageName + '-' + vulnerability.cveId)">
            <mat-icon>{{ getExpandIcon(vulnerability.packageName + '-' + vulnerability.cveId) }}</mat-icon>
            <span class="package-name">{{ vulnerability.packageName }}</span>
            <span class="cve-id">{{ vulnerability.cveId }}</span>
            <span class="severity-badge" [class]="vulnerability.severity.toLowerCase()">
              {{ vulnerability.severity }}
            </span>
          </div>
          
          <div class="vulnerability-content" 
               *ngIf="expandedItems.has(vulnerability.packageName + '-' + vulnerability.cveId)">
            <app-vulnerability-detail 
              [vulnerability]="vulnerability">
            </app-vulnerability-detail>
          </div>
        </div>
      </cdk-virtual-scroll-viewport>
      
      <!-- 空狀態 -->
      <div class="empty-state" *ngIf="vulnerabilities.length === 0 && !isProcessing">
        <mat-icon>security</mat-icon>
        <p>沒有發現漏洞</p>
      </div>
    </div>
  `,
  styles: [`
    .virtual-scroll-container {
      width: 100%;
      height: 100%;
    }
    
    /* 載入指示器 */
    .loading-indicator {
      padding: 24px 16px;
      text-align: center;
      background-color: #f8f9fa;
      border-radius: 8px;
      margin-bottom: 16px;
    }
    
    .loading-indicator p {
      margin-top: 12px;
      color: #666;
      font-size: 14px;
    }
    
    /* 標題區域 */
    .scroll-header {
      padding: 12px 16px;
      background-color: #e3f2fd;
      border-bottom: 1px solid #bbdefb;
      color: #1565c0;
      font-size: 14px;
      font-weight: 500;
      border-radius: 8px 8px 0 0;
    }
    
    .stats-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 8px;
    }
    
    .severity-stats {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }
    
    .stat {
      padding: 4px 8px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
      color: white;
    }
    
    .stat.critical { background-color: #d32f2f; }
    .stat.high { background-color: #f57c00; }
    .stat.medium { background-color: #e65100; }
    .stat.low { background-color: #388e3c; }
    
    .batch-controls {
      display: flex;
      gap: 8px;
      margin-top: 8px;
      flex-wrap: wrap;
    }
    
    /* 虛擬滾動視窗 */
    .vulnerability-viewport {
      width: 100%;
      border-radius: 0 0 8px 8px;
      background-color: #fafafa;
    }
    
    /* 漏洞項目 */
    .vulnerability-item {
      margin: 4px 8px;
      border-radius: 8px;
      background-color: white;
      box-shadow: 0 1px 3px rgba(0,0,0,0.12);
      transition: all 0.2s ease;
      overflow: hidden;
    }
    
    .vulnerability-item:hover {
      box-shadow: 0 2px 8px rgba(0,0,0,0.16);
    }
    
    .vulnerability-item.expanded {
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    
    /* 套件標頭 */
    .package-header {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 12px 16px;
      background-color: #f8f9fa;
      border-bottom: 1px solid #e9ecef;
      cursor: pointer;
      transition: background-color 0.2s ease;
      user-select: none;
    }
    
    .package-header:hover {
      background-color: #e9ecef;
    }
    
    .package-header mat-icon {
      font-size: 20px;
      width: 20px;
      height: 20px;
      color: #666;
      transition: transform 0.2s ease;
    }
    
    .package-name {
      font-family: 'Roboto Mono', monospace;
      font-weight: 500;
      color: #1976d2;
      flex: 1;
    }
    
    .cve-id {
      font-family: 'Roboto Mono', monospace;
      font-size: 13px;
      color: #666;
      background-color: #f0f0f0;
      padding: 2px 8px;
      border-radius: 4px;
    }
    
    .severity-badge {
      padding: 4px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
      color: white;
      text-transform: uppercase;
    }
    
    .severity-badge.critical { background-color: #d32f2f; }
    .severity-badge.high { background-color: #f57c00; }
    .severity-badge.medium { background-color: #e65100; }
    .severity-badge.low { background-color: #388e3c; }
    
    /* 漏洞內容 */
    .vulnerability-content {
      animation: expandIn 0.2s ease-out;
      overflow: hidden;
    }
    
    @keyframes expandIn {
      from {
        opacity: 0;
        max-height: 0;
      }
      to {
        opacity: 1;
        max-height: 2000px;
      }
    }
    
    /* 空狀態 */
    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 300px;
      color: #757575;
      gap: 16px;
      
      mat-icon {
        font-size: 48px;
        width: 48px;
        height: 48px;
        color: #4caf50;
      }
      
      p {
        margin: 0;
        font-size: 16px;
      }
    }
    
    /* 自訂捲軸樣式 */
    .vulnerability-viewport::-webkit-scrollbar {
      width: 8px;
    }
    
    .vulnerability-viewport::-webkit-scrollbar-track {
      background: #f1f1f1;
      border-radius: 4px;
    }
    
    .vulnerability-viewport::-webkit-scrollbar-thumb {
      background: #c1c1c1;
      border-radius: 4px;
    }
    
    .vulnerability-viewport::-webkit-scrollbar-thumb:hover {
      background: #a8a8a8;
    }
    
    /* 響應式設計 */
    @media (max-width: 768px) {
      .stats-row {
        flex-direction: column;
        align-items: flex-start;
      }
      
      .severity-stats {
        align-self: stretch;
        justify-content: space-between;
      }
      
      .batch-controls {
        align-self: stretch;
        justify-content: center;
      }
      
      .package-header {
        padding: 8px 12px;
      }
      
      .cve-id {
        display: none;
      }
    }
  `]
})
export class VirtualScrollVulnerabilitiesComponent implements OnInit, OnChanges, OnDestroy {
  @Input() scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];
  @Input() viewportHeight: number = 600;
  @Input() batchSize: number = 50; // 批次載入大小
  @Input() maxInitialLoad: number = 100; // 初始最大載入數量
  
  // 資料管理
  vulnerabilities: VulnerabilityWithPackage[] = [];
  displayedVulnerabilities: VulnerabilityWithPackage[] = [];
  
  // 效能控制
  isProcessing: boolean = false;
  processedCount: number = 0;
  totalCount: number = 0;
  expandedItems: Set<string> = new Set();
  
  // 統計資料
  severityStats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  
  // 動態高度計算
  get dynamicItemHeight(): number {
    return 80; // 摺疊狀態的高度，展開時會自動調整
  }
  
  // RxJS 清理
  private destroy$ = new Subject<void>();
  private processingSubject = new Subject<void>();
  
  // 公開 Math 給模板使用
  Math = Math;
  
  constructor(private cdr: ChangeDetectorRef) {}
  
  ngOnInit(): void {
    // 防抖處理，避免頻繁重新計算
    this.processingSubject
      .pipe(
        debounceTime(100),
        takeUntil(this.destroy$)
      )
      .subscribe(() => {
        this.processVulnerabilities();
      });
      
    this.triggerProcessing();
  }
  
  ngOnChanges(): void {
    this.triggerProcessing();
  }
  
  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }
  
  private triggerProcessing(): void {
    this.processingSubject.next();
  }
  
  private async processVulnerabilities(): Promise<void> {
    if (this.scanResults.length === 0) return;
    
    this.isProcessing = true;
    this.processedCount = 0;
    this.totalCount = this.scanResults.reduce((sum, result) => sum + result.vulnerabilities.length, 0);
    this.cdr.markForCheck();
    
    try {
      await this.processVulnerabilitiesAsync();
    } catch (error) {
      console.error('處理漏洞資料時發生錯誤:', error);
    } finally {
      this.isProcessing = false;
      this.cdr.markForCheck();
    }
  }
  
  private async processVulnerabilitiesAsync(): Promise<void> {
    this.vulnerabilities = [];
    this.severityStats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    
    // 分批處理以避免阻塞主執行緒
    for (const result of this.scanResults) {
      for (const vulnerability of result.vulnerabilities) {
        this.vulnerabilities.push({
          ...vulnerability,
          packageName: result.packageName
        });
        
        // 更新統計
        if (this.severityStats.hasOwnProperty(vulnerability.severity)) {
          this.severityStats[vulnerability.severity as keyof typeof this.severityStats]++;
        }
        
        this.processedCount++;
        
        // 每處理一定數量就暫停一下，讓 UI 保持響應
        if (this.processedCount % 20 === 0) {
          await this.yield();
          this.cdr.markForCheck();
        }
      }
    }
    
    // 排序（按嚴重性）
    this.vulnerabilities.sort((a, b) => {
      const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
      const severityDiff = (severityOrder[a.severity as keyof typeof severityOrder] || 999) - 
                          (severityOrder[b.severity as keyof typeof severityOrder] || 999);
      
      // 如果嚴重程度相同，按 CVSS 分數排序
      if (severityDiff === 0) {
        return (b.cvssScore || 0) - (a.cvssScore || 0);
      }
      
      return severityDiff;
    });
    
    // 初始載入
    this.loadInitialVulnerabilities();
  }
  
  private async yield(): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, 0));
  }
  
  private loadInitialVulnerabilities(): void {
    const initialCount = Math.min(this.maxInitialLoad, this.vulnerabilities.length);
    this.displayedVulnerabilities = this.vulnerabilities.slice(0, initialCount);
  }
  
  loadMoreVulnerabilities(): void {
    const currentCount = this.displayedVulnerabilities.length;
    const nextCount = Math.min(currentCount + this.batchSize, this.vulnerabilities.length);
    this.displayedVulnerabilities = this.vulnerabilities.slice(0, nextCount);
    this.cdr.markForCheck();
  }
  
  loadAllVulnerabilities(): void {
    this.displayedVulnerabilities = [...this.vulnerabilities];
    this.cdr.markForCheck();
  }
  
  toggleExpanded(itemId: string): void {
    if (this.expandedItems.has(itemId)) {
      this.expandedItems.delete(itemId);
    } else {
      // 限制同時展開的項目數量以節省記憶體
      if (this.expandedItems.size >= 5) {
        const firstItem = this.expandedItems.values().next().value;
        this.expandedItems.delete(firstItem);
      }
      this.expandedItems.add(itemId);
    }
    this.cdr.markForCheck();
  }
  
  getExpandIcon(itemId: string): string {
    return this.expandedItems.has(itemId) ? 'expand_less' : 'expand_more';
  }
  
  trackByFn(index: number, item: VulnerabilityWithPackage): string {
    return `${item.packageName}-${item.cveId}`;
  }
}