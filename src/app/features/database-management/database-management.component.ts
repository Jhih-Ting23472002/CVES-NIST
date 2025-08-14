import { Component, OnInit, OnDestroy, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatDialogModule, MatDialog, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatChipsModule } from '@angular/material/chips';
import { Subscription } from 'rxjs';
import { LoadingOverlayComponent } from '../../shared/components/loading-overlay.component';

import { NvdSyncService, SyncStatus } from '../../core/services/nvd-sync.service';
import { LocalScanService } from '../../core/services/local-scan.service';
import { DatabaseVersion } from '../../core/interfaces/nvd-database.interface';
import { DatabaseWorkerService } from '../../core/services/database-worker.service';

@Component({
  selector: 'app-database-management',
  standalone: true,
  imports: [
    CommonModule,
    RouterModule,
    MatCardModule,
    MatButtonModule,
    MatProgressBarModule,
    MatIconModule,
    MatSnackBarModule,
    MatDialogModule,
    MatTooltipModule,
    MatChipsModule,
    LoadingOverlayComponent
  ],
  template: `
    <div class="database-management">
      <!-- 載入遮罩 -->
      <app-loading-overlay
        [show]="showLoadingOverlay"
        [title]="loadingTitle"
        [message]="loadingMessage"
        [icon]="loadingIcon"
        [showProgress]="showProgress"
        [progress]="loadingProgress"
        [progressText]="progressText"
        [tips]="loadingTips"
        [fullscreen]="true">
      </app-loading-overlay>
      <!-- 說明資訊卡片 -->
      <mat-card class="info-card">
        <mat-card-header>
          <mat-card-title>
            <mat-icon>info</mat-icon>
            本地 NVD 資料庫管理
          </mat-card-title>
        </mat-card-header>
        <mat-card-content>
          <div class="info-grid">
            <div class="info-item">
              <mat-icon>download</mat-icon>
              <div class="info-content">
                <h4>初始同步</h4>
                <p>首次使用需下載近四年 NVD 資料，建立本地漏洞資料庫</p>
              </div>
            </div>
            <div class="info-item">
              <mat-icon>sync</mat-icon>
              <div class="info-content">
                <h4>增量更新</h4>
                <p>定期同步最新漏洞資訊，保持資料庫為最新狀態</p>
              </div>
            </div>
            <div class="info-item">
              <mat-icon>speed</mat-icon>
              <div class="info-content">
                <h4>快速掃描</h4>
                <p>本地掃描速度比 API 快 10-20 倍，支援離線使用</p>
              </div>
            </div>
          </div>
          <div class="info-actions">
            <button mat-raised-button color="primary" routerLink="/upload">
              <mat-icon>arrow_back</mat-icon>
              返回上傳頁面
            </button>
          </div>
        </mat-card-content>
      </mat-card>

      <mat-card class="status-card">
        <mat-card-header>
          <mat-card-title>
            <mat-icon>storage</mat-icon>
            本地漏洞資料庫
          </mat-card-title>
          <mat-card-subtitle>NVD 資料庫狀態與管理</mat-card-subtitle>
        </mat-card-header>
        
        <mat-card-content>
          <!-- 資料庫狀態 -->
          <div class="status-section" *ngIf="databaseStats">
            <h3>資料庫統計</h3>
            <div class="stats-grid">
              <div class="stat-item">
                <mat-icon>bug_report</mat-icon>
                <div class="stat-content">
                  <div class="stat-value">{{ databaseStats.totalCveCount | number }}</div>
                  <div class="stat-label">CVE 記錄</div>
                </div>
              </div>
              
              <div class="stat-item">
                <mat-icon>inventory</mat-icon>
                <div class="stat-content">
                  <div class="stat-value">{{ databaseStats.totalCpeCount | number }}</div>
                  <div class="stat-label">CPE 記錄</div>
                </div>
              </div>
              
              <div class="stat-item">
                <mat-icon>schedule</mat-icon>
                <div class="stat-content">
                  <div class="stat-value">{{ getLastSyncDisplay() }}</div>
                  <div class="stat-label">最後同步</div>
                </div>
              </div>
              
              <div class="stat-item">
                <mat-icon>calendar_today</mat-icon>
                <div class="stat-content">
                  <div class="stat-value">{{ databaseStats.dataYears.length }}</div>
                  <div class="stat-label">資料年度</div>
                </div>
              </div>
            </div>
            
            <div class="data-years" *ngIf="databaseStats.dataYears.length > 0">
              <span class="years-label">包含年度：</span>
              <mat-chip-set>
                <mat-chip *ngFor="let year of databaseStats.dataYears">{{ year }}</mat-chip>
              </mat-chip-set>
            </div>
          </div>

          <!-- 同步狀態 -->
          <div class="sync-section" *ngIf="syncStatus">
            <h3>同步狀態</h3>
            <div class="sync-status" [ngClass]="'sync-' + syncStatus.currentPhase">
              <mat-icon>{{ getSyncIcon() }}</mat-icon>
              <div class="sync-content">
                <div class="sync-message">{{ syncStatus.message }}</div>
                <div class="sync-phase" *ngIf="syncStatus.currentPhase !== 'idle'">
                  階段：{{ getSyncPhaseText() }}
                </div>
              </div>
            </div>
            
            <mat-progress-bar 
              *ngIf="syncStatus.progress && syncStatus.isRunning"
              mode="determinate" 
              [value]="syncStatus.progress.percentage"
              class="sync-progress">
            </mat-progress-bar>
            
            <div class="sync-details" *ngIf="syncStatus.progress && syncStatus.isRunning">
              <span>{{ syncStatus.progress.processed | number }} / {{ syncStatus.progress.total | number }}</span>
              <span class="progress-percent">({{ syncStatus.progress.percentage | number:'1.1-1' }}%)</span>
            </div>

            <div class="sync-times" *ngIf="syncStatus.lastSync || syncStatus.nextSync">
              <div *ngIf="syncStatus.lastSync" class="last-sync">
                <mat-icon>check_circle</mat-icon>
                上次同步：{{ syncStatus.lastSync | date:'yyyy-MM-dd HH:mm:ss' }}
              </div>
              <div *ngIf="syncStatus.nextSync" class="next-sync">
                <mat-icon>schedule</mat-icon>
                下次同步：{{ syncStatus.nextSync | date:'yyyy-MM-dd HH:mm:ss' }}
              </div>
            </div>
          </div>
        </mat-card-content>
        
        <mat-card-actions>
          <button mat-raised-button 
                  color="primary" 
                  (click)="performSync()"
                  [disabled]="syncStatus?.isRunning"
                  matTooltip="手動執行資料同步">
            <mat-icon>sync</mat-icon>
            {{ getSyncButtonText() }}
          </button>
          
          <button mat-raised-button 
                  color="warn"
                  (click)="clearDatabase()"
                  [disabled]="syncStatus?.isRunning"
                  matTooltip="清除所有本地資料">
            <mat-icon>delete_sweep</mat-icon>
            清除資料庫
          </button>
          
          <button mat-stroked-button 
                  (click)="refreshStatus()"
                  [disabled]="syncStatus?.isRunning"
                  matTooltip="重新載入狀態">
            <mat-icon>refresh</mat-icon>
            重新載入
          </button>
          
          <button mat-stroked-button 
                  color="accent"
                  (click)="smartCleanup()"
                  [disabled]="syncStatus?.isRunning || !workerService.isWorkerAvailable()"
                  matTooltip="使用 Web Worker 智慧清理過期資料">
            <mat-icon>auto_fix_high</mat-icon>
            智慧清理
          </button>
        </mat-card-actions>
      </mat-card>

      <!-- 連線測試 -->
      <mat-card class="connection-card">
        <mat-card-header>
          <mat-card-title>
            <mat-icon>wifi</mat-icon>
            連線測試
          </mat-card-title>
        </mat-card-header>
        
        <mat-card-content>
          <div class="connection-status" [ngClass]="connectionStatus">
            <mat-icon>{{ getConnectionIcon() }}</mat-icon>
            <span>{{ getConnectionText() }}</span>
          </div>
          
          <!-- Web Worker 狀態 -->
          <div class="worker-status" [ngClass]="getWorkerStatusClass()">
            <mat-icon>{{ getWorkerIcon() }}</mat-icon>
            <span>{{ getWorkerText() }}</span>
          </div>
        </mat-card-content>
        
        <mat-card-actions>
          <button mat-button (click)="testConnection()" [disabled]="isTestingConnection">
            <mat-icon>network_check</mat-icon>
            測試連線
          </button>
        </mat-card-actions>
      </mat-card>
    </div>
  `,
  styles: [`
    .database-management {
      padding: 20px;
      max-width: 800px;
      margin: 0 auto;
    }

    .info-card, .status-card, .connection-card {
      margin-bottom: 20px;
    }

    .info-card {
      background: linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%);
      
      .info-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 16px;
        margin: 16px 0;
      }

      .info-item {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        padding: 12px;
        background: rgba(255, 255, 255, 0.7);
        border-radius: 8px;
        
        mat-icon {
          color: #1976d2;
          font-size: 1.5rem;
          width: 1.5rem;
          height: 1.5rem;
          margin-top: 4px;
        }

        .info-content {
          flex: 1;
          
          h4 {
            margin: 0 0 4px 0;
            color: #1976d2;
            font-weight: 600;
            font-size: 1rem;
          }

          p {
            margin: 0;
            color: #666;
            font-size: 0.9rem;
            line-height: 1.4;
          }
        }
      }

      .info-actions {
        display: flex;
        justify-content: center;
        margin-top: 16px;
        padding-top: 16px;
        border-top: 1px solid rgba(0, 0, 0, 0.1);
      }
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 16px;
      margin: 16px 0;
    }

    .stat-item {
      display: flex;
      align-items: center;
      padding: 12px;
      border: 1px solid #e0e0e0;
      border-radius: 4px;
      background-color: #fafafa;
    }

    .stat-content {
      margin-left: 12px;
    }

    .stat-value {
      font-size: 24px;
      font-weight: bold;
      color: #1976d2;
    }

    .stat-label {
      font-size: 12px;
      color: #666;
    }

    .data-years {
      margin-top: 16px;
      padding: 12px;
      background-color: #f5f5f5;
      border-radius: 4px;
    }

    .years-label {
      font-weight: bold;
      margin-right: 8px;
    }

    .sync-section {
      margin-top: 24px;
      padding-top: 16px;
      border-top: 1px solid #e0e0e0;
    }

    .sync-status {
      display: flex;
      align-items: center;
      padding: 12px;
      border-radius: 4px;
      margin-bottom: 12px;
    }

    .sync-idle {
      background-color: #f5f5f5;
      color: #666;
    }

    .sync-download, .sync-parse, .sync-store {
      background-color: #e3f2fd;
      color: #1976d2;
    }

    .sync-complete {
      background-color: #e8f5e8;
      color: #388e3c;
    }

    .sync-error {
      background-color: #ffebee;
      color: #d32f2f;
    }

    .sync-content {
      margin-left: 12px;
      flex: 1;
    }

    .sync-message {
      font-weight: bold;
    }

    .sync-phase {
      font-size: 12px;
      color: #666;
      margin-top: 4px;
    }

    .sync-progress {
      margin: 12px 0;
    }

    .sync-details {
      font-size: 12px;
      color: #666;
      text-align: center;
    }

    .progress-percent {
      margin-left: 8px;
      font-weight: bold;
    }

    .sync-times {
      margin-top: 16px;
    }

    .last-sync, .next-sync {
      display: flex;
      align-items: center;
      margin-bottom: 8px;
      font-size: 14px;
      color: #666;
    }

    .last-sync mat-icon, .next-sync mat-icon {
      margin-right: 8px;
      font-size: 16px;
    }

    .connection-status {
      display: flex;
      align-items: center;
      padding: 12px;
      border-radius: 4px;
    }

    .connection-status.connected {
      background-color: #e8f5e8;
      color: #388e3c;
    }

    .connection-status.disconnected {
      background-color: #ffebee;
      color: #d32f2f;
    }

    .connection-status.unknown {
      background-color: #fff3e0;
      color: #f57c00;
    }

    .connection-status mat-icon {
      margin-right: 8px;
    }

    .worker-status {
      display: flex;
      align-items: center;
      padding: 12px;
      border-radius: 4px;
      margin-top: 12px;
    }

    .worker-status.available {
      background-color: #e8f5e8;
      color: #388e3c;
    }

    .worker-status.unavailable {
      background-color: #ffebee;
      color: #d32f2f;
    }

    .worker-status mat-icon {
      margin-right: 8px;
    }

    mat-card-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    mat-card-title {
      display: flex;
      align-items: center;
    }

    mat-card-title mat-icon {
      margin-right: 8px;
    }
  `]
})
export class DatabaseManagementComponent implements OnInit, OnDestroy {
  databaseStats: DatabaseVersion | null = null;
  syncStatus: SyncStatus | null = null;
  connectionStatus: 'connected' | 'disconnected' | 'unknown' = 'unknown';
  isTestingConnection = false;

  // 載入遮罩相關
  showLoadingOverlay = false;
  loadingTitle = '';
  loadingMessage = '';
  loadingIcon = '';
  showProgress = false;
  loadingProgress = 0;
  progressText = '';
  loadingTips: string[] = [];

  private syncStatusSubscription?: Subscription;
  private syncTimeoutTimer?: number;

  constructor(
    private syncService: NvdSyncService,
    private localScanService: LocalScanService,
    public workerService: DatabaseWorkerService, // 改為 public 以便模板存取
    private snackBar: MatSnackBar,
    private dialog: MatDialog
  ) {}

  ngOnInit(): void {
    this.loadDatabaseStats();
    this.subscribeToSyncStatus();
    this.testConnection();
    
    // 檢查是否有正在進行的同步
    this.checkExistingSync();
  }

  ngOnDestroy(): void {
    if (this.syncStatusSubscription) {
      this.syncStatusSubscription.unsubscribe();
    }
    this.clearSyncTimeout();
  }

  loadDatabaseStats(): void {
    // 先檢查資料庫是否準備好
    this.localScanService.isDatabaseReady().subscribe({
      next: (isReady) => {
        if (isReady) {
          // 資料庫準備好了，載入統計
          this.localScanService.getDatabaseStats().subscribe({
            next: (stats) => {
              this.databaseStats = stats;
            },
            error: (error) => {
              console.error('載入資料庫統計失敗:', error);
              // 設定預設值以避免 UI 錯誤
              this.databaseStats = {
                version: 1,
                lastSync: 'Never',
                dataYears: [],
                totalCveCount: 0,
                totalCpeCount: 0
              };
            }
          });
        } else {
          // 資料庫未準備好，設定預設統計
          this.databaseStats = {
            version: 1,
            lastSync: 'Never',
            dataYears: [],
            totalCveCount: 0,
            totalCpeCount: 0
          };
          console.log('資料庫尚未準備好，顯示預設統計');
        }
      },
      error: (error) => {
        console.error('檢查資料庫狀態失敗:', error);
        // 即使檢查失敗也要設定預設值
        this.databaseStats = {
          version: 1,
          lastSync: 'Never',
          dataYears: [],
          totalCveCount: 0,
          totalCpeCount: 0
        };
      }
    });
  }

  subscribeToSyncStatus(): void {
    this.syncStatusSubscription = this.syncService.getSyncStatus().subscribe({
      next: (status) => {
        const prevPhase = this.syncStatus?.currentPhase;
        this.syncStatus = status;
        
        // 當同步狀態改變時的處理
        if (status.isRunning) {
          // 如果同步正在執行且載入遮罩未顯示，則顯示
          if (!this.showLoadingOverlay) {
            this.showSyncLoadingOverlay();
            // 設置超時保護（10分鐘）
            this.setSyncTimeout();
          }
          // 更新載入遮罩進度
          this.updateSyncProgress(status);
        } else {
          // 同步已停止，清除超時定時器
          this.clearSyncTimeout();
          
          // 檢查是否需要隱藏遮罩
          if (status.currentPhase === 'complete') {
            // 確保在完成狀態時關閉遮罩
            this.hideLoadingOverlay();
            // 顯示成功訊息（避免重複顯示）
            if (prevPhase !== 'complete') {
              this.snackBar.open('資料同步完成！', '確定', {
                duration: 5000,
                panelClass: ['success-snackbar']
              });
            }
            // 延遲重新載入統計以確保資料已完全儲存
            setTimeout(() => this.loadDatabaseStats(), 1000);
          } else if (status.currentPhase === 'error') {
            // 確保在錯誤狀態時關閉遮罩
            this.hideLoadingOverlay();
            // 顯示錯誤訊息（避免重複顯示）
            if (prevPhase !== 'error') {
              this.snackBar.open(`同步失敗：${status.error || '未知錯誤'}`, '確定', {
                duration: 8000,
                panelClass: ['error-snackbar']
              });
            }
          } else if (status.currentPhase === 'idle' && this.showLoadingOverlay) {
            // 如果回到閒置狀態且遮罩仍在顯示，隱藏遮罩
            this.hideLoadingOverlay();
          }
          
          // 額外的安全檢查：如果 isRunning 為 false 且遮罩還在顯示，強制關閉
          if (this.showLoadingOverlay && !status.isRunning) {
            console.log('強制關閉載入遮罩 - 同步已停止但遮罩仍在顯示');
            this.hideLoadingOverlay();
          }
        }
      },
      error: (error) => {
        this.clearSyncTimeout();
        this.hideLoadingOverlay();
        console.error('取得同步狀態失敗:', error);
      }
    });
  }

  performSync(): void {
    // 不要在這裡顯示遮罩，讓 subscribeToSyncStatus 統一處理
    // 這樣可以避免重複顯示和狀態不一致的問題
    
    this.syncService.forceSyncNow().subscribe({
      next: (status) => {
        // 狀態更新由 subscribeToSyncStatus 統一處理
        console.log('同步狀態更新:', status.currentPhase, status.message);
      },
      error: (error) => {
        // 確保錯誤時關閉遮罩和清除超時定時器
        this.clearSyncTimeout();
        this.hideLoadingOverlay();
        console.error('同步失敗:', error);
        this.snackBar.open(`同步失敗：${error.message}`, '確定', {
          duration: 8000,
          panelClass: ['error-snackbar']
        });
        
        // 錯誤已處理，狀態將由服務內部管理
      },
      complete: () => {
        // 確保完成時關閉遮罩（雙重保險）
        console.log('forceSyncNow Observable 完成');
      }
    });
  }

  clearDatabase(): void {
    const dialogRef = this.dialog.open(ConfirmDialogComponent, {
      data: {
        title: '確認清除資料庫',
        message: '此操作將刪除所有本地 NVD 資料，您確定要繼續嗎？',
        confirmText: '清除',
        cancelText: '取消'
      }
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.syncService.clearLocalDatabase().subscribe({
          next: () => {
            this.snackBar.open('資料庫已清除', '確定', {
              duration: 3000,
              panelClass: ['success-snackbar']
            });
            this.loadDatabaseStats();
          },
          error: (error) => {
            console.error('清除資料庫失敗:', error);
            this.snackBar.open('清除資料庫失敗', '確定', {
              duration: 5000,
              panelClass: ['error-snackbar']
            });
          }
        });
      }
    });
  }

  refreshStatus(): void {
    this.loadDatabaseStats();
    this.testConnection();
  }

  testConnection(): void {
    this.isTestingConnection = true;
    this.connectionStatus = 'unknown';

    this.syncService.testConnection().subscribe({
      next: (isConnected) => {
        this.connectionStatus = isConnected ? 'connected' : 'disconnected';
        this.isTestingConnection = false;
      },
      error: () => {
        this.connectionStatus = 'disconnected';
        this.isTestingConnection = false;
      }
    });
  }

  getSyncButtonText(): string {
    if (!this.databaseStats || this.databaseStats.totalCveCount === 0) {
      return '初始同步';
    }
    return this.syncStatus?.isRunning ? '同步中...' : '增量同步';
  }

  getSyncIcon(): string {
    if (!this.syncStatus) return 'sync';
    
    switch (this.syncStatus.currentPhase) {
      case 'idle': return 'sync';
      case 'download': return 'cloud_download';
      case 'parse': return 'data_usage';
      case 'store': return 'storage';
      case 'complete': return 'check_circle';
      case 'error': return 'error';
      default: return 'sync';
    }
  }

  getSyncPhaseText(): string {
    if (!this.syncStatus) return '';
    
    const phaseMap: { [key: string]: string } = {
      'idle': '閒置',
      'download': '下載中',
      'parse': '解析中',
      'store': '儲存中',
      'complete': '完成',
      'error': '錯誤'
    };
    
    return phaseMap[this.syncStatus.currentPhase] || this.syncStatus.currentPhase;
  }

  getConnectionIcon(): string {
    switch (this.connectionStatus) {
      case 'connected': return 'wifi';
      case 'disconnected': return 'wifi_off';
      case 'unknown': return 'help_outline';
      default: return 'help_outline';
    }
  }

  getConnectionText(): string {
    switch (this.connectionStatus) {
      case 'connected': return 'NVD 服務連線正常';
      case 'disconnected': return 'NVD 服務連線失敗';
      case 'unknown': return '連線狀態未知';
      default: return '連線狀態未知';
    }
  }

  getLastSyncDisplay(): string {
    if (!this.databaseStats || this.databaseStats.lastSync === 'Never') {
      return '從未同步';
    }
    
    const lastSync = new Date(this.databaseStats.lastSync);
    const now = new Date();
    const diffHours = Math.floor((now.getTime() - lastSync.getTime()) / (1000 * 60 * 60));
    
    if (diffHours < 1) {
      return '不到 1 小時前';
    } else if (diffHours < 24) {
      return `${diffHours} 小時前`;
    } else {
      const diffDays = Math.floor(diffHours / 24);
      return `${diffDays} 天前`;
    }
  }

  getWorkerStatusClass(): string {
    return this.workerService.isWorkerAvailable() ? 'available' : 'unavailable';
  }

  getWorkerIcon(): string {
    return this.workerService.isWorkerAvailable() ? 'build' : 'build_circle';
  }

  getWorkerText(): string {
    return this.workerService.isWorkerAvailable() ? 
      'Web Worker 可用 - 支援大量資料處理' : 
      'Web Worker 不可用 - 將使用主執行緒處理';
  }

  /**
   * 智慧清理過期資料
   */
  smartCleanup(): void {
    if (!this.workerService.isWorkerAvailable()) {
      this.snackBar.open('Web Worker 不可用，無法執行智慧清理', '確定', {
        duration: 5000,
        panelClass: ['warning-snackbar']
      });
      return;
    }

    const dialogRef = this.dialog.open(ConfirmDialogComponent, {
      data: {
        title: '智慧清理資料',
        message: '此操作將清理 7 天前的過期資料，並壓縮資料庫。是否繼續？',
        confirmText: '開始清理',
        cancelText: '取消'
      }
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.workerService.prepareForNewData({
          newDataVersion: 'cleanup-' + new Date().toISOString().split('T')[0],
          keepRecentDays: 7
        }).subscribe({
          next: (progress) => {
            this.snackBar.open(progress.message, '確定', {
              duration: 3000
            });

            if (progress.phase === 'complete') {
              this.loadDatabaseStats(); // 重新載入統計
            }
          },
          error: (error) => {
            this.snackBar.open(`清理失敗: ${error.message}`, '確定', {
              duration: 5000,
              panelClass: ['error-snackbar']
            });
          }
        });
      }
    });
  }

  /**
   * 顯示同步載入遮罩
   */
  private showSyncLoadingOverlay(): void {
    this.loadingTitle = '正在同步 NVD 資料庫';
    this.loadingMessage = '正在下載最新的漏洞資料庫，這可能需要幾分鐘時間...';
    this.loadingIcon = 'sync';
    this.showProgress = true;
    this.loadingProgress = 0;
    this.progressText = '';
    this.loadingTips = [
      '初始同步需要下載近四年的 NVD 資料',
      '同步過程中請保持網路連接',
      '同步完成後即可使用本地掃描功能',
      '您可以在其他頁面繼續操作'
    ];
    this.showLoadingOverlay = true;
  }

  /**
   * 更新同步進度
   */
  private updateSyncProgress(status: SyncStatus): void {
    if (status.progress) {
      this.loadingProgress = status.progress.percentage;
      this.progressText = `${status.progress.processed} / ${status.progress.total}`;
    }
    
    // 根據階段更新訊息
    const phaseMessages = {
      'download': '正在下載 NVD 資料檔案...',
      'parse': '正在解析漏洞資料...',
      'store': '正在儲存到本地資料庫...'
    };
    
    if (phaseMessages[status.currentPhase as keyof typeof phaseMessages]) {
      this.loadingMessage = phaseMessages[status.currentPhase as keyof typeof phaseMessages];
    }
  }

  /**
   * 隱藏載入遮罩
   */
  private hideLoadingOverlay(): void {
    this.clearSyncTimeout(); // 清除超時定時器
    this.showLoadingOverlay = false;
    this.loadingTitle = '';
    this.loadingMessage = '';
    this.loadingIcon = '';
    this.showProgress = false;
    this.loadingProgress = 0;
    this.progressText = '';
    this.loadingTips = [];
  }

  /**
   * 檢查是否有現有的同步進程
   */
  private checkExistingSync(): void {
    // 取得當前同步狀態
    this.syncService.getSyncStatus().subscribe(status => {
      if (status.isRunning) {
        // 如果有正在執行的同步，顯示遮罩
        this.showSyncLoadingOverlay();
        this.updateSyncProgress(status);
        // 設置超時保護
        this.setSyncTimeout();
      }
    });
  }

  /**
   * 設置同步超時保護（10分鐘）
   */
  private setSyncTimeout(): void {
    this.clearSyncTimeout(); // 先清除舊的定時器
    
    this.syncTimeoutTimer = window.setTimeout(() => {
      console.warn('同步操作超時，強制關閉載入遮罩');
      this.hideLoadingOverlay();
      this.snackBar.open('同步操作超時，請重試或檢查網路連線', '確定', {
        duration: 10000,
        panelClass: ['warning-snackbar']
      });
    }, 10 * 60 * 1000); // 10分鐘
  }

  /**
   * 清除同步超時定時器
   */
  private clearSyncTimeout(): void {
    if (this.syncTimeoutTimer) {
      clearTimeout(this.syncTimeoutTimer);
      this.syncTimeoutTimer = undefined;
    }
  }
}

// 確認對話框元件（可以單獨提取到 shared 目錄）
@Component({
  selector: 'app-confirm-dialog',
  standalone: true,
  imports: [
    CommonModule,
    MatDialogModule,
    MatButtonModule
  ],
  template: `
    <h2 mat-dialog-title>{{ data.title }}</h2>
    <mat-dialog-content>
      <p>{{ data.message }}</p>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button [mat-dialog-close]="false">{{ data.cancelText }}</button>
      <button mat-raised-button color="warn" [mat-dialog-close]="true">{{ data.confirmText }}</button>
    </mat-dialog-actions>
  `
})
export class ConfirmDialogComponent {
  constructor(
    @Inject(MAT_DIALOG_DATA) public data: {
      title: string;
      message: string;
      confirmText: string;
      cancelText: string;
    }
  ) {}
}

