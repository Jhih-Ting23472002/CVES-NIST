import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBarModule, MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatDialogModule } from '@angular/material/dialog';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { Subscription } from 'rxjs';

import { NistApiService } from '../../core/services/nist-api.service';
import { BackgroundScanService } from '../../core/services/background-scan.service';
import { getDatabaseConfig } from '../../core/config/database.config';
import { LoadingOverlayComponent } from '../../shared/components/loading-overlay.component';
import { FileParserService } from '../../core/services/file-parser.service';
import { LocalScanService } from '../../core/services/local-scan.service';
import { 
  PackageInfo, 
  Vulnerability, 
  ScanProgress, 
  ScanTask, 
  ScanConfig, 
  DEFAULT_SCAN_CONFIGS 
} from '../../core/models/vulnerability.model';

@Component({
  selector: 'app-scan',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    RouterModule,
    MatCardModule,
    MatButtonModule,
    MatProgressBarModule,
    MatIconModule,
    MatSnackBarModule,
    MatTableModule,
    MatDialogModule,
    MatSlideToggleModule,
    MatTooltipModule,
    LoadingOverlayComponent,
    MatFormFieldModule,
    MatInputModule
  ],
  templateUrl: './scan.component.html',
  styleUrls: ['./scan.component.scss']
})
export class ScanComponent implements OnInit, OnDestroy {
  packages: PackageInfo[] = [];
  isScanning = false;
  scanCompleted = false;
  scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];
  scanTimestamp: Date = new Date();
  scanProgress: ScanProgress = {
    current: 0,
    total: 0,
    percentage: 0,
    currentPackage: ''
  };
  
  // 背景掃描相關
  useBackgroundScan = true;
  currentTask: ScanTask | null = null;
  scanConfig: ScanConfig = DEFAULT_SCAN_CONFIGS['balanced'];
  
  // 本地掃描相關
  useLocalScan = false;
  isLocalDatabaseReady = false;
  isCheckingDatabase = false;
  
  // 載入遮罩相關
  showLoadingOverlay = false;
  loadingTitle = '';
  loadingMessage = '';
  loadingIcon = '';
  loadingTips: string[] = [];
  
  displayedColumns = ['package', 'vulnerabilities', 'highestSeverity'];
  private scanSubscription?: Subscription;
  private backgroundStateSubscription?: Subscription;
  private currentTaskSubscription?: Subscription;
  
  constructor(
    private router: Router,
    private nistApiService: NistApiService,
    public backgroundScanService: BackgroundScanService,
    public fileParserService: FileParserService,
    private localScanService: LocalScanService,
    private snackBar: MatSnackBar
  ) {
    // 從路由狀態取得套件清單和背景任務資訊
    const navigation = this.router.getCurrentNavigation();
    if (navigation?.extras?.state?.['packages']) {
      this.packages = navigation.extras.state['packages'];
    }
    
    // 檢查是否來自背景任務頁面的前景顯示請求
    if (navigation?.extras?.state?.['backgroundTaskId']) {
      const taskId = navigation.extras.state['backgroundTaskId'];
      const showInForeground = navigation.extras.state['showInForeground'];
      
      if (showInForeground) {
        // 將背景任務切換為前景顯示
        const task = this.backgroundScanService.getTask(taskId);
        if (task) {
          this.currentTask = task;
          this.syncWithBackgroundTask(task);
        }
      }
    }
  }
  
  ngOnInit(): void {
    if (this.packages.length === 0) {
      // Allow text scanning even if no packages are passed
    }

    // 檢查本地資料庫狀態
    this.checkLocalDatabaseStatus();

    // 訂閱背景掃描狀態
    this.backgroundStateSubscription = this.backgroundScanService.state$.subscribe(() => {
      // 檢查是否有與當前套件相關的任務
      this.updateCurrentTaskStatus();
    });

    // 訂閱當前執行中的任務
    this.currentTaskSubscription = this.backgroundScanService.currentTask$.subscribe(task => {
      this.currentTask = task;
      if (task) {
        this.syncWithBackgroundTask(task);
      }
    });

    // 檢查是否已有相關的背景任務
    this.checkExistingBackgroundTask();
    
    // 如果沒有現有任務，顯示掃描選項
    if (!this.currentTask) {
      this.showScanOptions();
    }
  }
  
  ngOnDestroy(): void {
    if (this.scanSubscription) {
      this.scanSubscription.unsubscribe();
    }
    if (this.backgroundStateSubscription) {
      this.backgroundStateSubscription.unsubscribe();
    }
    if (this.currentTaskSubscription) {
      this.currentTaskSubscription.unsubscribe();
    }
  }
  
  getScanTitle(): string {
    if (this.currentTask) {
      switch (this.currentTask.status) {
        case 'running': return '背景掃描進行中';
        case 'paused': return '掃描已暫停';
        case 'completed': return '背景掃描完成';
        case 'failed': return '掃描失敗';
        case 'cancelled': return '掃描已取消';
        default: return '準備掃描';
      }
    }
    
    if (this.isScanning) return '掃描進度';
    if (this.scanCompleted) return '掃描完成';
    return '準備掃描';
  }
  
  getScanSubtitle(): string {
    if (this.currentTask) {
      switch (this.currentTask.status) {
        case 'running': 
          return `${this.currentTask.progress.currentPackage} (${this.currentTask.progress.current}/${this.currentTask.progress.total})`;
        case 'paused': 
          return `已暫停 - 進度：${this.currentTask.progress.current}/${this.currentTask.progress.total}`;
        case 'completed': 
          const totalVulnerabilities = this.currentTask.results?.reduce((sum, r) => sum + r.vulnerabilities.length, 0) || 0;
          return totalVulnerabilities > 0 ? `發現 ${totalVulnerabilities} 個漏洞` : '未發現漏洞';
        case 'failed': return `掃描失敗：${this.currentTask.error || '未知錯誤'}`;
        case 'cancelled': return '已取消掃描';
      }
    }
    
    if (this.isScanning) return '正在檢查套件漏洞...';
    if (this.scanCompleted) return `掃描了 ${this.packages.length} 個套件`;
    return `準備掃描 ${this.packages.length} 個套件`;
  }
  
  startScan(): void {
    if (this.packages.length === 0) return;
    
    if (this.useBackgroundScan) {
      this.startBackgroundScan();
    } else {
      this.startForegroundScan();
    }
  }


  /**
   * 開始背景掃描
   */
  startBackgroundScan(): void {
    // API 配置已在 startScan() 中設定
    const taskName = `掃描任務 - ${new Date().toLocaleString()}`;
    this.backgroundScanService.createScanTask(
      taskName,
      this.packages,
      this.scanConfig,
      true
    );

    this.snackBar.open(
      `背景掃描已開始，您可以繼續使用其他功能。掃描完成時會收到通知。`,
      '確定',
      { duration: 6000, panelClass: ['info-snackbar'] }
    );
    
    // 導航到背景任務頁面或回到上傳頁面
    setTimeout(() => {
      this.goBack();
    }, 2000);
  }

  /**
   * 開始前景掃描（支援本地掃描和 API 掃描）
   */
  startForegroundScan(): void {
    this.isScanning = true;
    this.scanCompleted = false;
    this.scanResults = [];
    this.scanTimestamp = new Date();
    this.scanProgress = {
      current: 0,
      total: this.packages.length,
      percentage: 0,
      currentPackage: '準備開始掃描...'
    };
    
    // 根據設置選擇掃描方法
    if (this.useLocalScan && this.isLocalDatabaseReady) {
      this.scanSubscription = this.localScanService.scanMultiplePackagesWithProgress(this.packages).subscribe({
        next: (response) => this.handleScanResponse(response),
        error: (error) => this.handleScanError(error, '本地掃描失敗，將改為 API 掃描')
      });
    } else {
      this.scanSubscription = this.nistApiService.searchMultiplePackagesWithProgress(this.packages).subscribe({
        next: (response) => this.handleScanResponse(response),
        error: (error) => this.handleScanError(error, 'API 掃描失敗')
      });
    }
  }

  /**
   * 處理掃描響應（通用方法）
   */
  private handleScanResponse(response: any): void {
    if (response.type === 'progress' && response.progress) {
      this.scanProgress = {
        current: response.progress.current + 1,
        total: response.progress.total,
        percentage: ((response.progress.current + 1) / response.progress.total) * 100,
        currentPackage: response.progress.currentPackage.includes('等待') 
          ? response.progress.currentPackage 
          : `正在掃描: ${response.progress.currentPackage}`
      };
    } else if (response.type === 'result' && response.results) {
      this.scanResults = response.results;
      this.isScanning = false;
      this.scanCompleted = true;
      
      const vulnerableCount = response.results.filter((r: any) => r.vulnerabilities.length > 0).length;
      const totalVulnerabilities = response.results.reduce((sum: number, r: any) => sum + r.vulnerabilities.length, 0);
      const failedCount = response.results.filter((r: any) => r.vulnerabilities.length === 0).length;
      
      let message = '';
      const scanType = this.useLocalScan && this.isLocalDatabaseReady ? '本地掃描' : 'API 掃描';
      if (totalVulnerabilities > 0) {
        message = `${scanType}完成！在 ${vulnerableCount} 個套件中發現 ${totalVulnerabilities} 個漏洞`;
        if (failedCount > 0) {
          message += `，${failedCount} 個套件掃描失敗或無資料`;
        }
        this.snackBar.open(message, '確定', {
          duration: 8000,
          panelClass: ['warning-snackbar']
        });
      } else {
        message = `${scanType}完成！沒有發現任何已知漏洞`;
        if (failedCount > 0) {
          message += `（${failedCount} 個套件掃描失敗或無資料）`;
        }
        this.snackBar.open(message, '確定', {
          duration: 5000,
          panelClass: ['success-snackbar']
        });
      }
    } else if (response.type === 'error' && response.error) {
      console.warn('掃描過程中發生錯誤:', response.error);
    }
  }

  /**
   * 處理掃描錯誤（通用方法）
   */
  private handleScanError(error: any, context: string): void {
    this.isScanning = false;
    console.error(`${context}:`, error);
    
    // 如果本地掃描失敗，自動切換到 API 掃描
    if (context.includes('本地掃描失敗')) {
      this.snackBar.open('本地掃描失敗，正在改為 API 掃描...', '確定', {
        duration: 3000,
        panelClass: ['info-snackbar']
      });
      // 重置狀態並使用 API 掃描
      this.useLocalScan = false;
      setTimeout(() => {
        this.startForegroundScan();
      }, 1000);
    } else {
      this.snackBar.open(`${context}: ${error.message}`, '確定', {
        duration: 8000,
        panelClass: ['error-snackbar']
      });
    }
  }

  /**
   * 檢查本地資料庫狀態
   */
  private checkLocalDatabaseStatus(): void {
    this.isCheckingDatabase = true;
    this.showDatabaseCheckingOverlay();
    
    this.localScanService.isDatabaseReady().subscribe({
      next: (isReady) => {
        this.isLocalDatabaseReady = isReady;
        this.isCheckingDatabase = false;
        this.hideLoadingOverlay();
        
        if (isReady) {
          // 預設使用本地掃描（如果可用）
          this.useLocalScan = true;
          console.log('本地資料庫可用，預設啟用本地掃描');
          this.snackBar.open('本地資料庫準備就緒，已啟用本地掃描模式', '確定', {
            duration: 3000,
            panelClass: ['success-snackbar']
          });
        } else {
          this.useLocalScan = false;
          console.log('本地資料庫不可用，將使用 API 掃描');
        }
      },
      error: (error) => {
        console.warn('檢查本地資料庫狀態失敗:', error);
        this.isLocalDatabaseReady = false;
        this.useLocalScan = false;
        this.isCheckingDatabase = false;
        this.hideLoadingOverlay();
      }
    });
  }
  
  getSeverityCount(severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'): number {
    return this.scanResults.reduce((count, result) => {
      return count + result.vulnerabilities.filter(v => v.severity === severity).length;
    }, 0);
  }
  
  getSafePackagesCount(): number {
    return this.scanResults.filter(result => result.vulnerabilities.length === 0).length;
  }
  
  getVulnerablePackages(): {packageName: string, vulnerabilities: Vulnerability[]}[] {
    return this.scanResults.filter(result => result.vulnerabilities.length > 0);
  }
  
  getHighestSeverity(vulnerabilities: Vulnerability[]): string {
    if (vulnerabilities.length === 0) return 'NONE';
    
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];
    
    for (const severity of severityOrder) {
      if (vulnerabilities.some(v => v.severity === severity)) {
        return severity;
      }
    }
    
    return 'NONE';
  }
  
  viewReport(): void {
    // 如果有背景任務結果，使用背景任務的結果
    const results = this.currentTask?.results || this.scanResults;
    const timestamp = this.currentTask?.completedAt || this.scanTimestamp;
    
    this.router.navigate(['/report'], {
      state: { 
        packages: this.packages,
        scanResults: results,
        scanTimestamp: timestamp,
        taskId: this.currentTask?.id
      }
    });
  }
  
  /**
   * 暫停背景掃描
   */
  pauseBackgroundScan(): void {
    if (this.currentTask && this.currentTask.status === 'running') {
      this.backgroundScanService.pauseScanTask(this.currentTask.id);
      this.snackBar.open('已暫停背景掃描', '確定', { duration: 3000 });
    }
  }

  /**
   * 恢復背景掃描
   */
  resumeBackgroundScan(): void {
    if (this.currentTask && this.currentTask.status === 'paused') {
      this.backgroundScanService.startScanTask(this.currentTask.id);
      this.snackBar.open('已恢復背景掃描', '確定', { duration: 3000 });
    }
  }

  /**
   * 取消背景掃描
   */
  cancelBackgroundScan(): void {
    if (this.currentTask && ['running', 'paused'].includes(this.currentTask.status)) {
      this.backgroundScanService.cancelScanTask(this.currentTask.id);
      this.snackBar.open('已取消背景掃描', '確定', { duration: 3000 });
      this.currentTask = null;
    }
  }

  /**
   * 顯示掃描選項
   */
  showScanOptions(): void {
    // 顯示掃描設定選項，讓使用者可以選擇掃描模式
    // 不再自動開始掃描，等使用者點擊開始掃描按鈕
  }

  /**
   * 檢查是否有相關的現有背景任務
   */
  private checkExistingBackgroundTask(): void {
    // 需要先取得當前狀態
    this.backgroundScanService.state$.subscribe(state => {
      // 檢查是否有相同套件的現有任務
      const existingTask = state.activeTasks.find((task: ScanTask) => 
        task.packages.length === this.packages.length &&
        task.packages.every((pkg: PackageInfo) => 
          this.packages.some(p => p.name === pkg.name && p.version === pkg.version)
        )
      ) || state.completedTasks.find((task: ScanTask) => 
        task.packages.length === this.packages.length &&
        task.packages.every((pkg: PackageInfo) => 
          this.packages.some(p => p.name === pkg.name && p.version === pkg.version)
        )
      );

      if (existingTask) {
        this.currentTask = existingTask;
        this.syncWithBackgroundTask(existingTask);
      }
    }).unsubscribe(); // 只需要取得一次即可
  }

  /**
   * 與背景任務同步狀態
   */
  private syncWithBackgroundTask(task: ScanTask): void {
    this.scanProgress = task.progress;
    this.scanTimestamp = task.startedAt || task.createdAt;
    
    if (task.results) {
      this.scanResults = task.results;
      this.scanCompleted = task.status === 'completed';
    }
    
    this.isScanning = task.status === 'running';
  }

  /**
   * 更新當前任務狀態
   */
  private updateCurrentTaskStatus(): void {
    if (this.currentTask) {
      const updatedTask = this.backgroundScanService.getTask(this.currentTask.id);
      if (updatedTask) {
        this.currentTask = updatedTask;
        this.syncWithBackgroundTask(updatedTask);
      }
    }
  }

  /**
   * 取得進度百分比
   */
  getProgressPercentage(): number {
    if (this.currentTask) {
      return this.currentTask.progress.percentage;
    }
    return this.scanProgress.percentage;
  }

  /**
   * 檢查是否可以檢視報告
   */
  canViewReport(): boolean {
    return this.scanCompleted || 
           (this.currentTask?.status === 'completed' && !!this.currentTask.results);
  }

  /**
   * 取得掃描配置說明
   */
  getScanConfigDescription(): string {
    const config = this.scanConfig;
    const parts: string[] = [];
    
    if (config.includeDirectDeps) parts.push('直接相依');
    if (config.includeDevDeps) parts.push('開發相依');
    if (config.includeTransitive) parts.push('間接相依');
    if (config.skipCommonTools) parts.push('跳過常見工具');
    
    return parts.join('、') || '預設設定';
  }

  /**
   * 取得任務狀態文字
   */
  getTaskStatusText(): string {
    if (!this.currentTask) return '';
    
    const statusMap: { [key: string]: string } = {
      'pending': '等待中',
      'running': '執行中',
      'paused': '已暫停',
      'completed': '已完成',
      'failed': '失敗',
      'cancelled': '已取消'
    };
    
    return statusMap[this.currentTask.status] || this.currentTask.status;
  }

  /**
   * 顯示資料庫檢查載入遮罩
   */
  private showDatabaseCheckingOverlay(): void {
    this.loadingTitle = '檢查本地資料庫狀態';
    this.loadingMessage = '正在檢查本地 NVD 資料庫是否可用...';
    this.loadingIcon = 'storage';
    this.loadingTips = [
      '首次使用需要同步 NVD 資料庫',
      '本地掃描速度比 API 掃描快 10-20 倍',
      '本地掃描支援離線使用'
    ];
    this.showLoadingOverlay = true;
  }

  /**
   * 顯示資料庫同步載入遮罩
   */
  showDatabaseSyncOverlay(): void {
    this.loadingTitle = '正在同步 NVD 資料庫';
    this.loadingMessage = '正在下載最新的漏洞資料庫，這可能需要幾分鐘時間...';
    this.loadingIcon = 'sync';
    this.loadingTips = [
      `初始同步需要下載近${getDatabaseConfig().downloadYearsRange}年的 NVD 資料`,
      '同步過程中請保持網路連接',
      '同步完成後即可使用本地掃描功能'
    ];
    this.showLoadingOverlay = true;
  }

  /**
   * 隱藏載入遮罩
   */
  private hideLoadingOverlay(): void {
    this.showLoadingOverlay = false;
    this.loadingTitle = '';
    this.loadingMessage = '';
    this.loadingIcon = '';
    this.loadingTips = [];
  }

  goBack(): void {
    this.router.navigate(['/upload']);
  }
}
