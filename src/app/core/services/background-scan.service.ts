import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, Subject, timer, EMPTY } from 'rxjs';
import { takeUntil, tap, finalize } from 'rxjs/operators';
import { 
  ScanTask, 
  ScanTaskStatus, 
  BackgroundScanState, 
  PackageInfo, 
  ScanConfig, 
  ScanProgress, 
  Vulnerability,
  NotificationConfig
} from '../models/vulnerability.model';
import { NistApiService } from './nist-api.service';
import { FileParserService } from './file-parser.service';

@Injectable({
  providedIn: 'root'
})
export class BackgroundScanService {
  private readonly STORAGE_KEY = 'cve_background_scan_state';
  private readonly NOTIFICATION_CONFIG_KEY = 'cve_notification_config';
  private readonly TASK_EXPIRY_HOURS = 24; // 24小時後自動刪除
  private readonly CLEANUP_INTERVAL = 60 * 60 * 1000; // 每小時檢查一次 (毫秒)
  
  private state: BackgroundScanState = {
    activeTasks: [],
    completedTasks: []
  };

  private stateSubject = new BehaviorSubject<BackgroundScanState>(this.state);
  private currentTaskSubject = new Subject<ScanTask | null>();
  private stopCurrentScan$ = new Subject<void>();
  private cleanupTimer?: any;

  public state$ = this.stateSubject.asObservable();
  public currentTask$ = this.currentTaskSubject.asObservable();

  constructor(
    private nistApiService: NistApiService,
    private fileParserService: FileParserService
  ) {
    this.loadState();
    this.requestNotificationPermission();
    
    // 頁面載入時檢查是否有未完成的掃描任務
    this.resumeActiveTasks();
    
    // 立即執行一次清理，然後啟動定期清理
    this.cleanupExpiredTasks();
    this.startCleanupTimer();
  }

  /**
   * 創建新的背景掃描任務
   */
  createScanTask(
    name: string, 
    packages: PackageInfo[], 
    config: ScanConfig,
    startImmediately: boolean = true
  ): string {
    const taskId = this.generateTaskId();
    const estimatedTime = this.fileParserService.estimateScanTime(packages);
    
    const task: ScanTask = {
      id: taskId,
      name: name || `掃描任務 - ${new Date().toLocaleDateString()}`,
      packages,
      config,
      status: 'pending',
      progress: {
        current: 0,
        total: packages.length,
        percentage: 0,
        currentPackage: '等待開始...'
      },
      createdAt: new Date(),
      estimatedDuration: estimatedTime.estimatedMinutes
    };

    this.state.activeTasks.push(task);
    this.state.lastScanId = taskId;
    this.saveState();
    this.stateSubject.next(this.state);

    if (startImmediately) {
      this.startScanTask(taskId);
    }

    return taskId;
  }

  /**
   * 開始執行掃描任務
   */
  startScanTask(taskId: string): void {
    const task = this.getTask(taskId);
    if (!task) return;

    if (task.status === 'running') {
      console.log(`任務 ${taskId} 已在執行中`);
      return;
    }

    // 停止其他正在執行的任務（同時只能執行一個）
    this.pauseAllTasks();

    task.status = 'running';
    task.startedAt = new Date();
    this.saveState();
    this.stateSubject.next(this.state);
    this.currentTaskSubject.next(task);

    console.log(`開始背景掃描任務: ${task.name}`);

    // 執行掃描
    this.executeScan(task);
  }

  /**
   * 暫停掃描任務
   */
  pauseScanTask(taskId: string): void {
    const task = this.getTask(taskId);
    if (!task || task.status !== 'running') return;

    task.status = 'paused';
    this.stopCurrentScan$.next();
    this.saveState();
    this.stateSubject.next(this.state);
    this.currentTaskSubject.next(null);

    console.log(`暫停掃描任務: ${task.name}`);
  }

  /**
   * 取消掃描任務
   */
  cancelScanTask(taskId: string): void {
    const task = this.getTask(taskId);
    if (!task) return;

    if (task.status === 'running') {
      this.stopCurrentScan$.next();
    }

    task.status = 'cancelled';
    task.completedAt = new Date();
    
    // 移動到已完成清單
    this.moveToCompleted(task);
    this.currentTaskSubject.next(null);

    console.log(`取消掃描任務: ${task.name}`);
  }

  /**
   * 刪除已完成的任務
   */
  deleteCompletedTask(taskId: string): void {
    this.state.completedTasks = this.state.completedTasks.filter(t => t.id !== taskId);
    this.saveState();
    this.stateSubject.next(this.state);
  }

  /**
   * 取得任務詳情
   */
  getTask(taskId: string): ScanTask | undefined {
    return this.state.activeTasks.find(t => t.id === taskId) || 
           this.state.completedTasks.find(t => t.id === taskId);
  }

  /**
   * 取得正在執行的任務
   */
  getRunningTask(): ScanTask | undefined {
    return this.state.activeTasks.find(t => t.status === 'running');
  }

  /**
   * 檢查是否有正在執行的任務
   */
  hasRunningTask(): boolean {
    return this.state.activeTasks.some(t => t.status === 'running');
  }

  /**
   * 取得任務結果
   */
  getTaskResults(taskId: string): {packageName: string, vulnerabilities: Vulnerability[]}[] | undefined {
    const task = this.getTask(taskId);
    return task?.results;
  }

  /**
   * 執行實際的掃描邏輯
   */
  private executeScan(task: ScanTask): void {
    const startTime = Date.now();
    
    this.nistApiService.searchMultiplePackagesWithProgress(task.packages)
      .pipe(
        takeUntil(this.stopCurrentScan$),
        tap(response => {
          if (response.type === 'progress' && response.progress) {
            task.progress = {
              current: response.progress.current + 1,
              total: response.progress.total,
              percentage: ((response.progress.current + 1) / response.progress.total) * 100,
              currentPackage: response.progress.currentPackage.includes('等待') 
                ? response.progress.currentPackage 
                : `正在掃描: ${response.progress.currentPackage}`
            };
            this.saveState();
            this.stateSubject.next(this.state);
          }
        }),
        finalize(() => {
          // 清理停止信號
          this.stopCurrentScan$ = new Subject<void>();
        })
      )
      .subscribe({
        next: (response) => {
          if (response.type === 'result' && response.results) {
            // 掃描完成
            task.status = 'completed';
            task.results = response.results;
            task.completedAt = new Date();
            task.actualDuration = Math.round((Date.now() - startTime) / 60000); // 分鐘

            this.moveToCompleted(task);
            this.currentTaskSubject.next(null);

            // 發送通知
            this.sendCompletionNotification(task);
            
            console.log(`背景掃描完成: ${task.name}`);
          }
        },
        error: (error) => {
          task.status = 'failed';
          task.error = error.message;
          task.completedAt = new Date();
          task.actualDuration = Math.round((Date.now() - startTime) / 60000);

          this.moveToCompleted(task);
          this.currentTaskSubject.next(null);

          // 發送錯誤通知
          this.sendErrorNotification(task);
          
          console.error(`背景掃描失敗: ${task.name}`, error);
        }
      });
  }

  /**
   * 暫停所有正在執行的任務
   */
  private pauseAllTasks(): void {
    this.state.activeTasks.forEach(task => {
      if (task.status === 'running') {
        task.status = 'paused';
      }
    });
    this.stopCurrentScan$.next();
  }

  /**
   * 將任務移動到已完成清單
   */
  private moveToCompleted(task: ScanTask): void {
    this.state.activeTasks = this.state.activeTasks.filter(t => t.id !== task.id);
    this.state.completedTasks.unshift(task);
    
    // 限制已完成任務數量（最多保留10個）
    if (this.state.completedTasks.length > 10) {
      this.state.completedTasks = this.state.completedTasks.slice(0, 10);
    }
    
    this.saveState();
    this.stateSubject.next(this.state);
  }

  /**
   * 恢復未完成的任務
   */
  private resumeActiveTasks(): void {
    const runningTask = this.getRunningTask();
    if (runningTask) {
      // 將正在執行的任務標記為暫停，因為頁面重新載入了
      runningTask.status = 'paused';
      this.saveState();
      this.stateSubject.next(this.state);
    }
  }

  /**
   * 發送完成通知
   */
  private sendCompletionNotification(task: ScanTask): void {
    if (!this.isNotificationEnabled('scanCompleted')) return;
    
    const vulnerableCount = task.results?.filter(r => r.vulnerabilities.length > 0).length || 0;
    const totalVulnerabilities = task.results?.reduce((sum, r) => sum + r.vulnerabilities.length, 0) || 0;
    
    const title = '掃描完成';
    const body = totalVulnerabilities > 0 
      ? `${task.name} 完成！發現 ${totalVulnerabilities} 個漏洞`
      : `${task.name} 完成！未發現漏洞`;

    this.showNotification(title, body);
  }

  /**
   * 發送錯誤通知
   */
  private sendErrorNotification(task: ScanTask): void {
    if (!this.isNotificationEnabled('scanFailed')) return;
    
    this.showNotification('掃描失敗', `${task.name} 掃描過程中發生錯誤`);
  }

  /**
   * 顯示瀏覽器通知
   */
  private showNotification(title: string, body: string): void {
    if ('Notification' in window && Notification.permission === 'granted') {
      const notification = new Notification(title, {
        body,
        icon: '/assets/icons/icon-192x192.png', // 確保圖示路徑正確
        badge: '/assets/icons/icon-72x72.png',
        tag: 'cve-scan',
        requireInteraction: false
      });

      // 點擊通知時聚焦到應用程式
      notification.onclick = () => {
        window.focus();
        notification.close();
      };

      // 3秒後自動關閉
      setTimeout(() => notification.close(), 3000);
    }
  }

  /**
   * 請求通知權限
   */
  private requestNotificationPermission(): void {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }

  /**
   * 檢查通知是否啟用
   */
  private isNotificationEnabled(type: keyof NotificationConfig['types']): boolean {
    const config = this.getNotificationConfig();
    return config.enabled && config.types[type];
  }

  /**
   * 取得通知設定
   */
  private getNotificationConfig(): NotificationConfig {
    try {
      const stored = localStorage.getItem(this.NOTIFICATION_CONFIG_KEY);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (error) {
      console.warn('載入通知設定失敗:', error);
    }

    // 預設設定
    return {
      enabled: true,
      types: {
        scanCompleted: true,
        scanFailed: true,
        highSeverityFound: true
      }
    };
  }

  /**
   * 儲存狀態到 localStorage
   */
  private saveState(): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(this.state));
    } catch (error) {
      console.error('儲存背景掃描狀態失敗:', error);
    }
  }

  /**
   * 從 localStorage 載入狀態
   */
  private loadState(): void {
    try {
      const stored = localStorage.getItem(this.STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        // 轉換日期字串回 Date 物件
        this.state = {
          ...parsed,
          activeTasks: parsed.activeTasks.map((task: any) => ({
            ...task,
            createdAt: new Date(task.createdAt),
            startedAt: task.startedAt ? new Date(task.startedAt) : undefined,
            completedAt: task.completedAt ? new Date(task.completedAt) : undefined
          })),
          completedTasks: parsed.completedTasks.map((task: any) => ({
            ...task,
            createdAt: new Date(task.createdAt),
            startedAt: task.startedAt ? new Date(task.startedAt) : undefined,
            completedAt: task.completedAt ? new Date(task.completedAt) : undefined
          }))
        };
        this.stateSubject.next(this.state);
      }
    } catch (error) {
      console.error('載入背景掃描狀態失敗:', error);
      this.state = { activeTasks: [], completedTasks: [] };
    }
  }

  /**
   * 生成唯一任務 ID
   */
  private generateTaskId(): string {
    return `scan_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * 清理所有已完成的任務
   */
  clearCompletedTasks(): void {
    this.state.completedTasks = [];
    this.saveState();
    this.stateSubject.next(this.state);
  }

  /**
   * 取得任務統計
   */
  getTaskStats(): {
    active: number;
    running: number;
    paused: number;
    completed: number;
    failed: number;
  } {
    return {
      active: this.state.activeTasks.length,
      running: this.state.activeTasks.filter(t => t.status === 'running').length,
      paused: this.state.activeTasks.filter(t => t.status === 'paused').length,
      completed: this.state.completedTasks.filter(t => t.status === 'completed').length,
      failed: this.state.completedTasks.filter(t => t.status === 'failed').length
    };
  }

  /**
   * 啟動定期清理計時器
   */
  private startCleanupTimer(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanupExpiredTasks();
    }, this.CLEANUP_INTERVAL);
  }

  /**
   * 停止清理計時器
   */
  private stopCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
  }

  /**
   * 清理過期的任務
   */
  private cleanupExpiredTasks(): void {
    const now = new Date();
    const expiryThreshold = new Date(now.getTime() - (this.TASK_EXPIRY_HOURS * 60 * 60 * 1000));
    
    let hasChanges = false;
    
    // 清理活動任務中超過24小時的已暫停或失敗任務
    const originalActiveCount = this.state.activeTasks.length;
    this.state.activeTasks = this.state.activeTasks.filter(task => {
      // 保留正在執行的任務，不管多久
      if (task.status === 'running') {
        return true;
      }
      
      // 檢查任務是否超過24小時
      const taskTime = task.completedAt || task.startedAt || task.createdAt;
      const isExpired = taskTime < expiryThreshold;
      
      if (isExpired) {
        console.log(`🗑️ 自動清理過期任務: ${task.name} (創建於: ${taskTime.toLocaleString()})`);
        return false; // 移除任務
      }
      
      return true; // 保留任務
    });
    
    if (this.state.activeTasks.length !== originalActiveCount) {
      hasChanges = true;
    }
    
    // 清理已完成任務中超過24小時的任務
    const originalCompletedCount = this.state.completedTasks.length;
    this.state.completedTasks = this.state.completedTasks.filter(task => {
      const taskTime = task.completedAt || task.createdAt;
      const isExpired = taskTime < expiryThreshold;
      
      if (isExpired) {
        console.log(`🗑️ 自動清理過期完成任務: ${task.name} (完成於: ${taskTime.toLocaleString()})`);
        return false; // 移除任務
      }
      
      return true; // 保留任務
    });
    
    if (this.state.completedTasks.length !== originalCompletedCount) {
      hasChanges = true;
    }
    
    // 如果有任務被清理，更新狀態和儲存
    if (hasChanges) {
      const removedCount = (originalActiveCount - this.state.activeTasks.length) + 
                          (originalCompletedCount - this.state.completedTasks.length);
      console.log(`✨ 自動清理完成，移除了 ${removedCount} 個過期任務`);
      
      this.saveState();
      this.stateSubject.next(this.state);
    }
  }

  /**
   * 檢查任務是否過期
   */
  private isTaskExpired(task: ScanTask): boolean {
    const now = new Date();
    const expiryThreshold = new Date(now.getTime() - (this.TASK_EXPIRY_HOURS * 60 * 60 * 1000));
    const taskTime = task.completedAt || task.startedAt || task.createdAt;
    
    return taskTime < expiryThreshold;
  }

  /**
   * 手動觸發過期任務清理
   */
  public manualCleanupExpiredTasks(): number {
    const beforeCount = this.state.activeTasks.length + this.state.completedTasks.length;
    this.cleanupExpiredTasks();
    const afterCount = this.state.activeTasks.length + this.state.completedTasks.length;
    
    return beforeCount - afterCount;
  }

  /**
   * 取得下次清理時間
   */
  public getNextCleanupTime(): Date {
    return new Date(Date.now() + this.CLEANUP_INTERVAL);
  }

  /**
   * 服務銷毀時清理資源
   */
  public ngOnDestroy(): void {
    this.stopCleanupTimer();
  }
}