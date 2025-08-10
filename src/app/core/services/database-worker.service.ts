import { Injectable, OnDestroy } from '@angular/core';
import { Observable, Subject, BehaviorSubject } from 'rxjs';
import { filter, take, map } from 'rxjs/operators';
import { CveRecord, CpeRecord } from '../interfaces/nvd-database.interface';
import { DatabaseWorkerMessage, DatabaseWorkerResponse } from '../workers/database-worker';

export interface WorkerProgress {
  phase: string;
  processed: number;
  total: number;
  percentage?: number;
  message: string;
}

@Injectable({
  providedIn: 'root'
})
export class DatabaseWorkerService implements OnDestroy {
  private worker: Worker | null = null;
  private workerReady = false;
  private requestCounter = 0;
  private responseSubject = new Subject<DatabaseWorkerResponse>();
  private progressSubject = new BehaviorSubject<WorkerProgress | null>(null);

  constructor() {
    this.initWorker();
  }

  ngOnDestroy(): void {
    this.terminateWorker();
  }

  /**
   * 初始化 Web Worker
   */
  private initWorker(): void {
    if (typeof Worker !== 'undefined') {
      try {
        this.worker = new Worker(new URL('../workers/database-worker.ts', import.meta.url), {
          type: 'module'
        });

        this.worker.onmessage = (event: MessageEvent<DatabaseWorkerResponse>) => {
          const response = event.data;
          
          if (response.type === 'progress') {
            this.progressSubject.next(response.data as WorkerProgress);
          }
          
          this.responseSubject.next(response);

          // 檢查是否為就緒訊息
          if (response.type === 'complete' && 
              response.data?.message === 'Database Worker 已就緒') {
            this.workerReady = true;
          }
        };

        this.worker.onerror = (error) => {
          console.error('Database Worker 錯誤:', error);
          this.responseSubject.next({
            type: 'error',
            error: error.message || 'Worker 執行錯誤'
          });
        };

      } catch (error) {
        console.warn('無法建立 Database Worker:', error);
        this.worker = null;
      }
    } else {
      console.warn('此環境不支援 Web Workers');
    }
  }

  /**
   * 終止 Worker
   */
  private terminateWorker(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
      this.workerReady = false;
    }
  }

  /**
   * 檢查 Worker 是否可用
   */
  isWorkerAvailable(): boolean {
    return this.worker !== null && this.workerReady;
  }

  /**
   * 取得進度 Observable
   */
  getProgress(): Observable<WorkerProgress | null> {
    return this.progressSubject.asObservable();
  }

  /**
   * 清理過期資料
   */
  cleanupOldData(options: {
    keepDays?: number;
    dataVersion?: string;
    batchSize?: number;
  }): Observable<{ deletedCount: number; cveDeleted: number; cpeDeleted: number }> {
    if (!this.isWorkerAvailable()) {
      throw new Error('Database Worker 不可用');
    }

    const requestId = `cleanup_${++this.requestCounter}`;
    
    this.worker!.postMessage({
      type: 'cleanupOldData',
      data: options,
      requestId
    } as DatabaseWorkerMessage);

    return this.responseSubject.pipe(
      filter(response => response.requestId === requestId || response.type === 'complete'),
      take(1),
      filter(response => response.type === 'complete'),
      map(response => response.data)
    );
  }

  /**
   * 按版本刪除資料
   */
  deleteByVersion(version: string): Observable<{ deletedCount: number }> {
    if (!this.isWorkerAvailable()) {
      throw new Error('Database Worker 不可用');
    }

    const requestId = `delete_version_${++this.requestCounter}`;
    
    this.worker!.postMessage({
      type: 'deleteByVersion',
      data: { version },
      requestId
    } as DatabaseWorkerMessage);

    return this.responseSubject.pipe(
      filter(response => response.requestId === requestId || response.type === 'complete'),
      take(1),
      filter(response => response.type === 'complete'),
      map(response => response.data)
    );
  }

  /**
   * 批次插入資料
   */
  bulkInsert(data: {
    cveRecords?: CveRecord[];
    cpeRecords?: CpeRecord[];
    batchSize?: number;
  }): Observable<{ cveInserted: number; cpeInserted: number }> {
    if (!this.isWorkerAvailable()) {
      throw new Error('Database Worker 不可用');
    }

    const requestId = `bulk_insert_${++this.requestCounter}`;
    
    this.worker!.postMessage({
      type: 'bulkInsert',
      data,
      requestId
    } as DatabaseWorkerMessage);

    return this.responseSubject.pipe(
      filter(response => response.requestId === requestId || response.type === 'complete'),
      take(1),
      filter(response => response.type === 'complete'),
      map(response => response.data)
    );
  }

  /**
   * 資料庫壓縮
   */
  compactDatabase(): Observable<{ message: string }> {
    if (!this.isWorkerAvailable()) {
      throw new Error('Database Worker 不可用');
    }

    const requestId = `compact_${++this.requestCounter}`;
    
    this.worker!.postMessage({
      type: 'compactDatabase',
      requestId
    } as DatabaseWorkerMessage);

    return this.responseSubject.pipe(
      filter(response => response.requestId === requestId || response.type === 'complete'),
      take(1),
      filter(response => response.type === 'complete'),
      map(response => response.data)
    );
  }

  /**
   * 預處理新資料前的清理工作
   */
  prepareForNewData(options: {
    newDataVersion: string;
    keepRecentDays?: number;
  }): Observable<{
    phase: 'cleanup' | 'compact' | 'complete';
    deletedCount?: number;
    message: string;
  }> {
    if (!this.isWorkerAvailable()) {
      throw new Error('Database Worker 不可用');
    }

    return new Observable(observer => {
      const { newDataVersion, keepRecentDays = 7 } = options;

      // 步驟 1: 清理過期資料
      this.cleanupOldData({
        keepDays: keepRecentDays,
        batchSize: 1000
      }).subscribe({
        next: (result) => {
          observer.next({
            phase: 'cleanup',
            deletedCount: result.deletedCount,
            message: `清理完成：刪除 ${result.deletedCount} 筆過期記錄`
          });

          // 步驟 2: 壓縮資料庫
          this.compactDatabase().subscribe({
            next: (compactResult) => {
              observer.next({
                phase: 'compact',
                message: compactResult.message
              });

              observer.next({
                phase: 'complete',
                message: `資料庫準備完成，可以載入版本 ${newDataVersion} 的新資料`
              });

              observer.complete();
            },
            error: (error) => observer.error(error)
          });
        },
        error: (error) => observer.error(error)
      });
    });
  }

  /**
   * 智慧資料更新
   * 比較新舊資料版本，只更新有變化的記錄
   */
  smartUpdate(options: {
    newCveRecords: CveRecord[];
    newCpeRecords: CpeRecord[];
    currentVersion: string;
    newVersion: string;
  }): Observable<{
    phase: 'analyze' | 'delete_old' | 'insert_new' | 'complete';
    processed?: number;
    total?: number;
    message: string;
  }> {
    return new Observable(observer => {
      const { newCveRecords, newCpeRecords, currentVersion, newVersion } = options;

      observer.next({
        phase: 'analyze',
        message: `分析資料差異: ${currentVersion} -> ${newVersion}`
      });

      // 步驟 1: 刪除舊版本資料
      if (currentVersion !== newVersion) {
        observer.next({
          phase: 'delete_old',
          message: `刪除舊版本資料: ${currentVersion}`
        });

        this.deleteByVersion(currentVersion).subscribe({
          next: (deleteResult) => {
            observer.next({
              phase: 'delete_old',
              message: `已刪除 ${deleteResult.deletedCount} 筆舊資料`
            });

            // 步驟 2: 插入新資料
            this.performSmartInsert(newCveRecords, newCpeRecords, newVersion, observer);
          },
          error: (error) => observer.error(error)
        });
      } else {
        // 相同版本，直接更新
        this.performSmartInsert(newCveRecords, newCpeRecords, newVersion, observer);
      }
    });
  }

  /**
   * 執行智慧插入
   */
  private performSmartInsert(
    cveRecords: CveRecord[],
    cpeRecords: CpeRecord[],
    version: string,
    observer: any
  ): void {
    observer.next({
      phase: 'insert_new',
      total: cveRecords.length + cpeRecords.length,
      processed: 0,
      message: '開始插入新資料'
    });

    this.bulkInsert({
      cveRecords,
      cpeRecords,
      batchSize: 1000
    }).subscribe({
      next: (insertResult) => {
        observer.next({
          phase: 'complete',
          message: `更新完成：新增 ${insertResult.cveInserted} 筆 CVE 和 ${insertResult.cpeInserted} 筆 CPE 記錄`
        });
        observer.complete();
      },
      error: (error) => observer.error(error)
    });
  }

  /**
   * 清除進度狀態
   */
  clearProgress(): void {
    this.progressSubject.next(null);
  }

  /**
   * 重新啟動 Worker
   */
  restartWorker(): void {
    this.terminateWorker();
    this.initWorker();
  }
}