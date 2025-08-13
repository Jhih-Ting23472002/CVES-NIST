import { Component, Input, OnInit, OnChanges, ViewChild, AfterViewInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatTableModule, MatTableDataSource } from '@angular/material/table';
import { MatPaginatorModule, MatPaginator } from '@angular/material/paginator';
import { MatSortModule, MatSort } from '@angular/material/sort';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatCardModule } from '@angular/material/card';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { FormsModule } from '@angular/forms';

import { PackageInfo, Vulnerability } from '../../core/models/vulnerability.model';

interface PackageTableRow {
  packageInfo: PackageInfo;
  vulnerabilities: Vulnerability[];
  vulnerabilityCount: number;
  highestSeverity: string;
  riskLevel: string;
  expanded: boolean;
}

@Component({
  selector: 'app-package-table',
  standalone: true,
  imports: [
    CommonModule,
    MatTableModule,
    MatPaginatorModule,
    MatSortModule,
    MatIconModule,
    MatButtonModule,
    MatChipsModule,
    MatTooltipModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatCardModule,
    MatProgressBarModule,
    FormsModule
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <mat-card class="package-table-card">
      <mat-card-header>
        <mat-card-title>
          <mat-icon>inventory</mat-icon>
          套件列表
        </mat-card-title>
        <mat-card-subtitle *ngIf="dataSource.data.length > 0">
          共 {{ dataSource.data.length }} 個套件
        </mat-card-subtitle>
      </mat-card-header>
      
      <mat-card-content>
        <!-- 篩選控制區 -->
        <div class="filter-controls" *ngIf="dataSource.data.length > 0">
          <mat-form-field appearance="outline" class="search-field">
            <mat-label>搜尋套件</mat-label>
            <input matInput 
                   [(ngModel)]="searchTerm" 
                   (input)="applyFilter()"
                   placeholder="套件名稱或描述">
            <mat-icon matSuffix>search</mat-icon>
          </mat-form-field>
          
          <mat-form-field appearance="outline" class="type-filter">
            <mat-label>套件類型</mat-label>
            <mat-select [(ngModel)]="typeFilter" (selectionChange)="applyFilter()" multiple>
              <mat-option value="dependency">主要相依</mat-option>
              <mat-option value="devDependency">開發相依</mat-option>
              <mat-option value="transitive">間接相依</mat-option>
            </mat-select>
          </mat-form-field>
          
          <mat-form-field appearance="outline" class="risk-filter">
            <mat-label>風險等級</mat-label>
            <mat-select [(ngModel)]="riskFilter" (selectionChange)="applyFilter()" multiple>
              <mat-option value="critical">嚴重</mat-option>
              <mat-option value="high">高風險</mat-option>
              <mat-option value="medium">中風險</mat-option>
              <mat-option value="low">低風險</mat-option>
              <mat-option value="safe">安全</mat-option>
            </mat-select>
          </mat-form-field>
          
          <div class="filter-summary" *ngIf="isFiltered()">
            <mat-chip-set>
              <mat-chip removable (removed)="clearFilters()">
                <mat-icon matChipRemove>cancel</mat-icon>
                {{ getFilterSummary() }}
              </mat-chip>
            </mat-chip-set>
          </div>
        </div>
        
        <!-- 套件統計 -->
        <div class="package-stats" *ngIf="dataSource.data.length > 0">
          <div class="stat-item main">
            <mat-icon>inventory</mat-icon>
            <span class="stat-number">{{ getTypeCount('dependency') }}</span>
            <span class="stat-label">主要相依</span>
          </div>
          <div class="stat-item dev">
            <mat-icon>build</mat-icon>
            <span class="stat-number">{{ getTypeCount('devDependency') }}</span>
            <span class="stat-label">開發相依</span>
          </div>
          <div class="stat-item transitive">
            <mat-icon>account_tree</mat-icon>
            <span class="stat-number">{{ getTypeCount('transitive') }}</span>
            <span class="stat-label">間接相依</span>
          </div>
          <div class="stat-item vulnerable">
            <mat-icon>warning</mat-icon>
            <span class="stat-number">{{ getVulnerableCount() }}</span>
            <span class="stat-label">有漏洞</span>
          </div>
        </div>
        
        <!-- 資料表格 -->
        <div class="table-container" *ngIf="dataSource.data.length > 0">
          <table mat-table [dataSource]="dataSource" matSort class="package-table">
            <!-- 套件名稱欄位 -->
            <ng-container matColumnDef="name">
              <th mat-header-cell *matHeaderCellDef mat-sort-header>套件名稱</th>
              <td mat-cell *matCellDef="let element">
                <div class="package-name-cell">
                  <span class="package-name">{{ element.packageInfo.name }}</span>
                </div>
              </td>
            </ng-container>
            
            <!-- 版本欄位 -->
            <ng-container matColumnDef="version">
              <th mat-header-cell *matHeaderCellDef>版本</th>
              <td mat-cell *matCellDef="let element">
                <span class="package-version">{{ element.packageInfo.version }}</span>
              </td>
            </ng-container>
            
            <!-- 類型欄位 -->
            <ng-container matColumnDef="type">
              <th mat-header-cell *matHeaderCellDef mat-sort-header>類型</th>
              <td mat-cell *matCellDef="let element">
                <mat-chip [class]="'type-' + element.packageInfo.type">
                  {{ getTypeLabel(element.packageInfo.type) }}
                </mat-chip>
              </td>
            </ng-container>
            
            <!-- 風險等級欄位 -->
            <ng-container matColumnDef="risk">
              <th mat-header-cell *matHeaderCellDef mat-sort-header>風險等級</th>
              <td mat-cell *matCellDef="let element">
                <mat-chip [class]="'risk-' + element.riskLevel">
                  {{ getRiskLabel(element.riskLevel) }}
                </mat-chip>
              </td>
            </ng-container>
            
            <!-- 漏洞數量欄位 -->
            <ng-container matColumnDef="vulnerabilities">
              <th mat-header-cell *matHeaderCellDef mat-sort-header>漏洞數量</th>
              <td mat-cell *matCellDef="let element">
                <div class="vulnerability-count-cell">
                  <span class="vulnerability-count" [class]="'count-' + element.riskLevel">
                    {{ element.vulnerabilityCount }}
                  </span>
                  <button mat-icon-button 
                          *ngIf="element.vulnerabilityCount > 0"
                          (click)="toggleRowExpansion(element)"
                          [attr.aria-label]="element.expanded ? '收合漏洞詳情' : '展開漏洞詳情'">
                    <mat-icon>{{ element.expanded ? 'expand_less' : 'expand_more' }}</mat-icon>
                  </button>
                </div>
              </td>
            </ng-container>
            
            <!-- 最高嚴重程度欄位 -->
            <ng-container matColumnDef="severity">
              <th mat-header-cell *matHeaderCellDef mat-sort-header>最高嚴重程度</th>
              <td mat-cell *matCellDef="let element">
                <mat-chip 
                  *ngIf="element.highestSeverity !== 'NONE'"
                  [class]="'severity-' + element.highestSeverity.toLowerCase()">
                  {{ getSeverityLabel(element.highestSeverity) }}
                </mat-chip>
                <span *ngIf="element.highestSeverity === 'NONE'" class="no-vulnerabilities">
                  安全
                </span>
              </td>
            </ng-container>
            
            <!-- 操作欄位 -->
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef>操作</th>
              <td mat-cell *matCellDef="let element">
                <div class="action-buttons">
                  <button mat-icon-button 
                          matTooltip="檢視詳細資訊"
                          (click)="viewPackageDetails(element)">
                    <mat-icon>info</mat-icon>
                  </button>
                  <button mat-icon-button 
                          *ngIf="element.packageInfo.type !== 'transitive'"
                          matTooltip="版本推薦"
                          (click)="loadVersionRecommendation(element)">
                    <mat-icon>upgrade</mat-icon>
                  </button>
                </div>
              </td>
            </ng-container>
            
            <!-- 表格標題列 -->
            <tr mat-header-row *matHeaderRowDef="displayedColumns; sticky: true"></tr>
            
            <!-- 資料列 -->
            <tr mat-row *matRowDef="let row; columns: displayedColumns;" 
                [class]="'risk-row-' + row.riskLevel"
                [class.expanded-row]="row.expanded"></tr>
          </table>
        </div>
        
        <!-- 展開詳情區域（在表格外部） -->
        <div class="expanded-details-container" *ngFor="let row of dataSource.data">
          <div class="expanded-content" *ngIf="row.expanded">
            <div class="vulnerability-details">
              <h4>{{ row.packageInfo.name }} 的漏洞詳情</h4>
              <div class="vulnerability-list">
                <div *ngFor="let vuln of row.vulnerabilities" class="vulnerability-item">
                  <div class="vulnerability-header">
                    <span class="cve-id">{{ vuln.cveId }}</span>
                    <mat-chip [class]="'severity-' + vuln.severity.toLowerCase()">
                      {{ getSeverityLabel(vuln.severity) }}
                    </mat-chip>
                    <span class="cvss-score">CVSS: {{ vuln.cvssScore || 'N/A' }}</span>
                  </div>
                  <div class="vulnerability-description">
                    {{ vuln.description }}
                  </div>
                  <div class="vulnerability-fix" *ngIf="vuln.fixedVersion">
                    <strong>修復版本:</strong> {{ vuln.fixedVersion }}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <!-- 分頁器 -->
        <mat-paginator 
          *ngIf="dataSource.data.length > 0"
          [pageSizeOptions]="[10, 25, 50]" 
          [pageSize]="25"
          [showFirstLastButtons]="true"
          aria-label="選擇頁面">
        </mat-paginator>
        
        <!-- 空狀態 -->
        <div class="empty-state" *ngIf="dataSource.data.length === 0">
          <mat-icon>inventory</mat-icon>
          <h3>沒有套件資料</h3>
          <p>請先上傳 package.json 檔案進行掃描。</p>
        </div>
      </mat-card-content>
    </mat-card>
  `,
  styles: [`
    .package-table-card {
      margin: 16px 0;
    }
    
    .filter-controls {
      display: flex;
      gap: 16px;
      margin-bottom: 16px;
      align-items: center;
      flex-wrap: wrap;
    }
    
    .search-field {
      flex: 1;
      min-width: 200px;
    }
    
    .type-filter, .risk-filter {
      min-width: 120px;
    }
    
    .package-stats {
      display: flex;
      gap: 16px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }
    
    .stat-item {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      border-radius: 8px;
      color: white;
      font-weight: 500;
    }
    
    .stat-item.main { background-color: #1976d2; }
    .stat-item.dev { background-color: #388e3c; }
    .stat-item.transitive { background-color: #f57c00; }
    .stat-item.vulnerable { background-color: #d32f2f; }
    
    .table-container {
      overflow-x: auto;
      max-height: 600px;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
    }
    
    .package-table {
      width: 100%;
    }
    
    .package-name {
      font-family: 'Roboto Mono', monospace;
      font-weight: 500;
      color: #1976d2;
    }
    
    .package-version {
      font-family: 'Roboto Mono', monospace;
      background-color: #f5f5f5;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 13px;
    }
    
    .vulnerability-count-cell {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .vulnerability-count {
      font-weight: 600;
      padding: 4px 8px;
      border-radius: 4px;
      color: white;
      min-width: 20px;
      text-align: center;
    }
    
    .count-critical { background-color: #d32f2f; }
    .count-high { background-color: #f57c00; }
    .count-medium { background-color: #e65100; }
    .count-low { background-color: #388e3c; }
    .count-safe { background-color: #4caf50; }
    
    .type-dependency { background-color: #1976d2; color: white; }
    .type-devDependency { background-color: #388e3c; color: white; }
    .type-transitive { background-color: #f57c00; color: white; }
    
    .risk-critical { background-color: #d32f2f; color: white; }
    .risk-high { background-color: #f57c00; color: white; }
    .risk-medium { background-color: #e65100; color: white; }
    .risk-low { background-color: #388e3c; color: white; }
    .risk-safe { background-color: #4caf50; color: white; }
    
    .severity-critical { background-color: #d32f2f; color: white; }
    .severity-high { background-color: #f57c00; color: white; }
    .severity-medium { background-color: #e65100; color: white; }
    .severity-low { background-color: #388e3c; color: white; }
    
    .risk-row-critical { border-left: 4px solid #d32f2f; }
    .risk-row-high { border-left: 4px solid #f57c00; }
    .risk-row-medium { border-left: 4px solid #e65100; }
    .risk-row-low { border-left: 4px solid #388e3c; }
    .risk-row-safe { border-left: 4px solid #4caf50; }
    
    .expanded-details-container {
      margin: 8px 0;
    }
    
    .expanded-content {
      padding: 16px;
      background-color: #fafafa;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
      margin-top: 8px;
    }
    
    .vulnerability-details h4 {
      margin-bottom: 16px;
      color: #333;
    }
    
    .vulnerability-item {
      margin-bottom: 16px;
      padding: 12px;
      background-color: white;
      border-radius: 8px;
      border: 1px solid #e0e0e0;
    }
    
    .vulnerability-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 8px;
      flex-wrap: wrap;
    }
    
    .cve-id {
      font-family: 'Roboto Mono', monospace;
      font-weight: 600;
      color: #1976d2;
    }
    
    .cvss-score {
      font-size: 14px;
      color: #666;
    }
    
    .vulnerability-description {
      margin-bottom: 8px;
      line-height: 1.5;
      color: #333;
    }
    
    .vulnerability-fix {
      font-size: 14px;
      color: #4caf50;
    }
    
    .action-buttons {
      display: flex;
      gap: 4px;
    }
    
    .no-vulnerabilities {
      color: #4caf50;
      font-weight: 500;
    }
    
    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 48px 16px;
      text-align: center;
      color: #757575;
    }
    
    .empty-state mat-icon {
      font-size: 64px;
      width: 64px;
      height: 64px;
      color: #1976d2;
      margin-bottom: 16px;
    }
  `]
})
export class PackageTableComponent implements OnInit, OnChanges, AfterViewInit {
  @Input() packages: PackageInfo[] = [];
  @Input() scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];
  
  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild(MatSort) sort!: MatSort;
  
  displayedColumns: string[] = ['name', 'version', 'type', 'risk', 'vulnerabilities', 'severity', 'actions'];
  dataSource = new MatTableDataSource<PackageTableRow>([]);
  
  searchTerm = '';
  typeFilter: string[] = [];
  riskFilter: string[] = [];
  
  constructor(private cdr: ChangeDetectorRef) {}
  
  ngOnInit(): void {
    this.processData();
  }
  
  ngOnChanges(): void {
    this.processData();
  }
  
  ngAfterViewInit(): void {
    this.dataSource.paginator = this.paginator;
    this.dataSource.sort = this.sort;
    
    this.dataSource.sortingDataAccessor = (data: PackageTableRow, sortHeaderId: string) => {
      switch (sortHeaderId) {
        case 'name':
          return data.packageInfo.name;
        case 'type':
          return data.packageInfo.type;
        case 'risk':
          return this.getRiskOrder(data.riskLevel);
        case 'vulnerabilities':
          return data.vulnerabilityCount;
        case 'severity':
          return this.getSeverityOrder(data.highestSeverity);
        default:
          return data.packageInfo[sortHeaderId as keyof PackageInfo] as string;
      }
    };
  }
  
  private processData(): void {
    const tableData: PackageTableRow[] = [];
    const scanResultsMap = new Map<string, Vulnerability[]>();
    
    // 建立掃描結果對照表
    this.scanResults.forEach(result => {
      scanResultsMap.set(result.packageName, result.vulnerabilities);
    });
    
    this.packages.forEach(pkg => {
      const packageKey = pkg.packageKey || `${pkg.name}@${pkg.version}`;
      const vulnerabilities = scanResultsMap.get(packageKey) || [];
      const vulnerabilityCount = vulnerabilities.length;
      
      let highestSeverity = 'NONE';
      let riskLevel = 'safe';
      
      if (vulnerabilityCount > 0) {
        const severities = vulnerabilities.map(v => v.severity);
        if (severities.includes('CRITICAL')) {
          highestSeverity = 'CRITICAL';
          riskLevel = 'critical';
        } else if (severities.includes('HIGH')) {
          highestSeverity = 'HIGH';
          riskLevel = 'high';
        } else if (severities.includes('MEDIUM')) {
          highestSeverity = 'MEDIUM';
          riskLevel = 'medium';
        } else if (severities.includes('LOW')) {
          highestSeverity = 'LOW';
          riskLevel = 'low';
        }
      }
      
      tableData.push({
        packageInfo: pkg,
        vulnerabilities,
        vulnerabilityCount,
        highestSeverity,
        riskLevel,
        expanded: false
      });
    });
    
    this.dataSource.data = tableData;
  }
  
  applyFilter(): void {
    this.dataSource.filterPredicate = (data: PackageTableRow, filter: string) => {
      const searchMatch = !this.searchTerm || 
        data.packageInfo.name.toLowerCase().includes(this.searchTerm.toLowerCase());
      
      const typeMatch = this.typeFilter.length === 0 || 
        this.typeFilter.includes(data.packageInfo.type);
      
      const riskMatch = this.riskFilter.length === 0 || 
        this.riskFilter.includes(data.riskLevel);
      
      return searchMatch && typeMatch && riskMatch;
    };
    
    // 觸發篩選並重置分頁
    this.dataSource.filter = Date.now().toString();
    
    // 重置到第一頁
    if (this.dataSource.paginator) {
      this.dataSource.paginator.firstPage();
    }
    
    // 觸發變更檢測
    this.cdr.markForCheck();
  }
  
  toggleRowExpansion(row: PackageTableRow): void {
    row.expanded = !row.expanded;
  }
  
  isFiltered(): boolean {
    return this.searchTerm.length > 0 || this.typeFilter.length > 0 || this.riskFilter.length > 0;
  }
  
  getFilterSummary(): string {
    const parts = [];
    if (this.searchTerm) parts.push(`搜尋: "${this.searchTerm}"`);
    if (this.typeFilter.length > 0) parts.push(`類型: ${this.typeFilter.join(', ')}`);
    if (this.riskFilter.length > 0) parts.push(`風險: ${this.riskFilter.join(', ')}`);
    return parts.join(', ');
  }
  
  clearFilters(): void {
    this.searchTerm = '';
    this.typeFilter = [];
    this.riskFilter = [];
    this.applyFilter();
  }
  
  getTypeLabel(type: string): string {
    const labels: { [key: string]: string } = {
      'dependency': '主要相依',
      'devDependency': '開發相依',
      'transitive': '間接相依'
    };
    return labels[type] || type;
  }
  
  getRiskLabel(risk: string): string {
    const labels: { [key: string]: string } = {
      'critical': '嚴重',
      'high': '高風險',
      'medium': '中風險',
      'low': '低風險',
      'safe': '安全'
    };
    return labels[risk] || risk;
  }
  
  getSeverityLabel(severity: string): string {
    const labels: { [key: string]: string } = {
      'CRITICAL': '嚴重',
      'HIGH': '高風險',
      'MEDIUM': '中風險',
      'LOW': '低風險'
    };
    return labels[severity] || severity;
  }
  
  getTypeCount(type: string): number {
    return this.dataSource.data.filter(row => row.packageInfo.type === type).length;
  }
  
  getVulnerableCount(): number {
    return this.dataSource.data.filter(row => row.vulnerabilityCount > 0).length;
  }
  
  private getRiskOrder(risk: string): number {
    const order: { [key: string]: number } = {
      'critical': 0,
      'high': 1,
      'medium': 2,
      'low': 3,
      'safe': 4
    };
    return order[risk] || 999;
  }
  
  private getSeverityOrder(severity: string): number {
    const order: { [key: string]: number } = {
      'CRITICAL': 0,
      'HIGH': 1,
      'MEDIUM': 2,
      'LOW': 3,
      'NONE': 4
    };
    return order[severity] || 999;
  }
  
  viewPackageDetails(row: PackageTableRow): void {
    // 這裡可以實作檢視套件詳細資訊的功能
    console.log('檢視套件詳情:', row.packageInfo);
  }
  
  loadVersionRecommendation(row: PackageTableRow): void {
    // 這裡可以實作版本推薦的功能
    console.log('載入版本推薦:', row.packageInfo);
  }
}