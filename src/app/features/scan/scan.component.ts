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
import { MatDialogModule, MatDialog } from '@angular/material/dialog';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatTooltipModule } from '@angular/material/tooltip';
import { Subscription } from 'rxjs';

import { NistApiService } from '../../core/services/nist-api.service';
import { BackgroundScanService } from '../../core/services/background-scan.service';
import { FileParserService } from '../../core/services/file-parser.service';
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
    MatTooltipModule
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
  
  displayedColumns = ['package', 'vulnerabilities', 'highestSeverity'];
  private scanSubscription?: Subscription;
  private backgroundStateSubscription?: Subscription;
  private currentTaskSubscription?: Subscription;
  
  constructor(
    private router: Router,
    private nistApiService: NistApiService,
    public backgroundScanService: BackgroundScanService,
    public fileParserService: FileParserService,
    private snackBar: MatSnackBar,
    private dialog: MatDialog
  ) {
    // 從路由狀態取得套件清單
    const navigation = this.router.getCurrentNavigation();
    if (navigation?.extras?.state?.['packages']) {
      this.packages = navigation.extras.state['packages'];
    }
  }
  
  ngOnInit(): void {
    if (this.packages.length === 0) {
      this.snackBar.open('沒有套件資料，請先上傳 package.json 檔案', '確定', {
        duration: 5000
      });
      this.goBack();
      return;
    }

    // 訂閱背景掃描狀態
    this.backgroundStateSubscription = this.backgroundScanService.state$.subscribe(state => {
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
          const vulnerableCount = this.currentTask.results?.filter(r => r.vulnerabilities.length > 0).length || 0;
          const totalVulns = this.currentTask.results?.reduce((sum, r) => sum + r.vulnerabilities.length, 0) || 0;
          return totalVulns > 0 ? `發現 ${totalVulns} 個漏洞` : '未發現漏洞';
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
    const taskName = `掃描任務 - ${new Date().toLocaleString()}`;
    const taskId = this.backgroundScanService.createScanTask(
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
   * 開始前景掃描（原有邏輯）
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
    
    this.scanSubscription = this.nistApiService.searchMultiplePackagesWithProgress(this.packages).subscribe({
      next: (response) => {
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
          
          const vulnerableCount = response.results.filter(r => r.vulnerabilities.length > 0).length;
          const totalVulnerabilities = response.results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
          const failedCount = response.results.filter(r => r.vulnerabilities.length === 0).length;
          
          let message = '';
          if (totalVulnerabilities > 0) {
            message = `掃描完成！在 ${vulnerableCount} 個套件中發現 ${totalVulnerabilities} 個漏洞`;
            if (failedCount > 0) {
              message += `，${failedCount} 個套件掃描失敗或無資料`;
            }
            this.snackBar.open(message, '確定', {
              duration: 8000,
              panelClass: ['warning-snackbar']
            });
          } else {
            message = '掃描完成！沒有發現任何已知漏洞';
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
      },
      error: (error) => {
        this.isScanning = false;
        this.snackBar.open(`掃描失敗: ${error.message}`, '確定', {
          duration: 8000,
          panelClass: ['error-snackbar']
        });
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
   * 顯示掃描選項對話框
   */
  showScanOptions(): void {
    // 這裡可以實作一個設定對話框，讓使用者選擇掃描模式
    // 目前先直接開始掃描
    this.startScan();
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

  goBack(): void {
    this.router.navigate(['/upload']);
  }
}