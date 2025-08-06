import { Component, Input, OnInit, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { MatIconModule } from '@angular/material/icon';
import { VulnerabilityDetailComponent } from './vulnerability-detail.component';
import { Vulnerability } from '../../core/models/vulnerability.model';

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
    VulnerabilityDetailComponent
  ],
  template: `
    <div class="virtual-scroll-container">
      <div class="scroll-header" *ngIf="vulnerabilities.length > 0">
        <span>共 {{ vulnerabilities.length }} 個漏洞，按嚴重程度排序</span>
      </div>
      <cdk-virtual-scroll-viewport 
        [itemSize]="itemHeight" 
        class="vulnerability-viewport"
        [style.height.px]="viewportHeight">
        <div *cdkVirtualFor="let vulnerability of vulnerabilities; trackBy: trackByFn" 
             class="vulnerability-item">
          <div class="package-header">
            <mat-icon>folder</mat-icon>
            <span class="package-name">{{ vulnerability.packageName }}</span>
          </div>
          <app-vulnerability-detail 
            [vulnerability]="vulnerability">
          </app-vulnerability-detail>
        </div>
      </cdk-virtual-scroll-viewport>
      <div class="empty-state" *ngIf="vulnerabilities.length === 0">
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
    
    .vulnerability-viewport {
      width: 100%;
      border-radius: 8px;
      background-color: #fafafa;
      padding: 8px 0;
    }
    
    .vulnerability-item {
      margin: 8px 16px;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.12);
      transition: box-shadow 0.2s ease;
    }
    
    .vulnerability-item:hover {
      box-shadow: 0 2px 8px rgba(0,0,0,0.16);
    }
    
    .package-header {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      background-color: #f5f5f5;
      border-bottom: 1px solid #e0e0e0;
      font-weight: 500;
      color: #1976d2;
      font-size: 14px;
    }
    
    .package-header mat-icon {
      font-size: 16px;
      width: 16px;
      height: 16px;
    }
    
    .package-name {
      font-family: 'Roboto Mono', monospace;
    }
    
    .scroll-header {
      padding: 12px 16px;
      background-color: #e3f2fd;
      border-bottom: 1px solid #bbdefb;
      color: #1565c0;
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
  `]
})
export class VirtualScrollVulnerabilitiesComponent implements OnInit, OnChanges {
  @Input() scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];
  @Input() viewportHeight: number = 600; // 預設視窗高度 600px
  @Input() itemHeight: number = 280; // 每個漏洞項目的估計高度
  
  vulnerabilities: VulnerabilityWithPackage[] = [];
  
  ngOnInit(): void {
    this.processVulnerabilities();
  }
  
  ngOnChanges(): void {
    this.processVulnerabilities();
  }
  
  private processVulnerabilities(): void {
    this.vulnerabilities = [];
    
    this.scanResults.forEach(result => {
      result.vulnerabilities.forEach(vulnerability => {
        this.vulnerabilities.push({
          ...vulnerability,
          packageName: result.packageName
        });
      });
    });
    
    // 按嚴重性排序
    this.vulnerabilities.sort((a, b) => {
      const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
      return severityOrder[a.severity as keyof typeof severityOrder] - 
             severityOrder[b.severity as keyof typeof severityOrder];
    });
  }
  
  trackByFn(index: number, item: VulnerabilityWithPackage): string {
    return `${item.packageName}-${item.cveId}`;
  }
}