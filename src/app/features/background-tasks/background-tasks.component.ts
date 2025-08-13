import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTableModule } from '@angular/material/table';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatMenuModule } from '@angular/material/menu';
import { Subscription } from 'rxjs';

import { BackgroundScanService } from '../../core/services/background-scan.service';
import { 
  ScanTask, 
  BackgroundScanState,
  ScanTaskStatus 
} from '../../core/models/vulnerability.model';

@Component({
  selector: 'app-background-tasks',
  standalone: true,
  imports: [
    CommonModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatTableModule,
    MatProgressBarModule,
    MatSnackBarModule,
    MatChipsModule,
    MatTooltipModule,
    MatMenuModule
  ],
  templateUrl: './background-tasks.component.html',
  styleUrls: ['./background-tasks.component.scss']
})
export class BackgroundTasksComponent implements OnInit, OnDestroy {
  state: BackgroundScanState = { activeTasks: [], completedTasks: [] };
  currentTask: ScanTask | null = null;
  
  displayedActiveColumns = ['name', 'progress', 'status', 'actions'];
  displayedCompletedColumns = ['name', 'duration', 'status', 'results', 'actions'];
  
  // 快取清理時間，避免變更檢測錯誤
  nextCleanupTime: string = '';
  
  private stateSubscription?: Subscription;
  private currentTaskSubscription?: Subscription;

  constructor(
    public backgroundScanService: BackgroundScanService,
    private router: Router,
    private snackBar: MatSnackBar
  ) {}

  ngOnInit(): void {
    // 訂閱背景掃描狀態
    this.stateSubscription = this.backgroundScanService.state$.subscribe(
      state => this.state = state
    );

    // 訂閱當前執行任務
    this.currentTaskSubscription = this.backgroundScanService.currentTask$.subscribe(
      task => this.currentTask = task
    );
    
    // 初始化清理時間並設定定期更新
    this.updateNextCleanupTime();
    setInterval(() => this.updateNextCleanupTime(), 60000); // 每分鐘更新一次
  }

  ngOnDestroy(): void {
    this.stateSubscription?.unsubscribe();
    this.currentTaskSubscription?.unsubscribe();
  }

  /**
   * 開始任務
   */
  startTask(taskId: string): void {
    this.backgroundScanService.startScanTask(taskId);
    this.snackBar.open('已開始執行任務', '確定', { duration: 2000 });
  }

  /**
   * 暫停任務
   */
  pauseTask(taskId: string): void {
    this.backgroundScanService.pauseScanTask(taskId);
    this.snackBar.open('已暫停任務', '確定', { duration: 2000 });
  }

  /**
   * 取消任務
   */
  cancelTask(taskId: string): void {
    this.backgroundScanService.cancelScanTask(taskId);
    this.snackBar.open('已取消任務', '確定', { duration: 2000 });
  }

  /**
   * 刪除已完成的任務
   */
  deleteTask(taskId: string): void {
    this.backgroundScanService.deleteCompletedTask(taskId);
    this.snackBar.open('已刪除任務', '確定', { duration: 2000 });
  }

  /**
   * 查看任務結果（前景顯示）
   */
  viewTaskInForeground(task: ScanTask): void {
    if (task.status === 'completed' && task.results) {
      // 導航到報告頁面並顯示結果
      this.router.navigate(['/report'], {
        state: {
          packages: task.packages,
          scanResults: task.results,
          scanTimestamp: task.completedAt || task.createdAt,
          taskId: task.id,
          taskName: task.name
        }
      });
    } else if (task.status === 'running' || task.status === 'paused') {
      // 導航到掃描頁面並顯示當前進度
      this.router.navigate(['/scan'], {
        state: {
          packages: task.packages,
          backgroundTaskId: task.id,
          showInForeground: true
        }
      });
    }
  }

  /**
   * 取得任務狀態圖示
   */
  getTaskStatusIcon(status: ScanTaskStatus): string {
    const iconMap: { [key: string]: string } = {
      'pending': 'schedule',
      'running': 'play_circle',
      'paused': 'pause_circle',
      'completed': 'check_circle',
      'failed': 'error',
      'cancelled': 'cancel'
    };
    return iconMap[status] || 'help';
  }

  /**
   * 取得任務狀態文字
   */
  getTaskStatusText(status: ScanTaskStatus): string {
    const statusMap: { [key: string]: string } = {
      'pending': '等待中',
      'running': '執行中',
      'paused': '已暫停',
      'completed': '已完成',
      'failed': '失敗',
      'cancelled': '已取消'
    };
    return statusMap[status] || status;
  }

  /**
   * 取得任務狀態顏色
   */
  getTaskStatusColor(status: ScanTaskStatus): string {
    const colorMap: { [key: string]: string } = {
      'pending': 'primary',
      'running': 'accent',
      'paused': 'warn',
      'completed': '',
      'failed': 'warn',
      'cancelled': ''
    };
    return colorMap[status] || 'primary';
  }

  /**
   * 格式化持續時間
   */
  formatDuration(minutes?: number): string {
    if (!minutes) return '-';
    
    if (minutes < 1) {
      return '< 1 分鐘';
    } else if (minutes < 60) {
      return `${Math.round(minutes)} 分鐘`;
    } else {
      const hours = Math.floor(minutes / 60);
      const remainingMinutes = Math.round(minutes % 60);
      return remainingMinutes > 0 
        ? `${hours} 小時 ${remainingMinutes} 分鐘`
        : `${hours} 小時`;
    }
  }

  /**
   * 取得結果摘要
   */
  getResultSummary(task: ScanTask): string {
    if (!task.results) return '-';
    
    const vulnerableCount = task.results.filter(r => r.vulnerabilities.length > 0).length;
    const totalVulns = task.results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
    
    if (totalVulns === 0) {
      return '無漏洞';
    }
    
    return `${totalVulns} 個漏洞 (${vulnerableCount} 個套件)`;
  }

  /**
   * 檢查是否可以開始任務
   */
  canStartTask(task: ScanTask): boolean {
    return task.status === 'pending' || task.status === 'paused';
  }

  /**
   * 檢查是否可以暫停任務
   */
  canPauseTask(task: ScanTask): boolean {
    return task.status === 'running';
  }

  /**
   * 檢查是否可以取消任務
   */
  canCancelTask(task: ScanTask): boolean {
    return task.status === 'running' || task.status === 'paused';
  }

  /**
   * 檢查是否可以檢視任務
   */
  canViewTask(task: ScanTask): boolean {
    return task.status === 'completed' || task.status === 'running' || task.status === 'paused';
  }

  /**
   * 清除所有已完成任務
   */
  clearCompletedTasks(): void {
    this.backgroundScanService.clearCompletedTasks();
    this.snackBar.open('已清除所有已完成任務', '確定', { duration: 2000 });
  }

  /**
   * 取得任務統計
   */
  getTaskStats() {
    return this.backgroundScanService.getTaskStats();
  }

  /**
   * 手動清理過期任務
   */
  cleanupExpiredTasks(): void {
    const removedCount = this.backgroundScanService.manualCleanupExpiredTasks();
    if (removedCount > 0) {
      this.snackBar.open(`已清理 ${removedCount} 個超過24小時的過期任務`, '確定', { duration: 3000 });
    } else {
      this.snackBar.open('沒有需要清理的過期任務', '確定', { duration: 2000 });
    }
  }

  /**
   * 更新下次清理時間
   */
  private updateNextCleanupTime(): void {
    const nextTime = this.backgroundScanService.getNextCleanupTime();
    this.nextCleanupTime = nextTime.toLocaleString();
  }

  /**
   * 取得下次自動清理時間 (返回快取值避免變更檢測錯誤)
   */
  getNextCleanupTime(): string {
    return this.nextCleanupTime;
  }

  /**
   * 返回首頁
   */
  goHome(): void {
    this.router.navigate(['/upload']);
  }
}
