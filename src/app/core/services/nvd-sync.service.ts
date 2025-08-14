import { Injectable } from '@angular/core';
import { Observable, BehaviorSubject, forkJoin, of } from 'rxjs';
import { switchMap, map, catchError, tap } from 'rxjs/operators';
import { NvdDownloadService } from './nvd-download.service';
import { NvdParserService } from './nvd-parser.service';
import { NvdDatabaseService } from './nvd-database.service';
import {
  CveRecord,
  CpeRecord,
  BatchProcessProgress,
  DatabaseVersion,
  IncrementalUpdate
} from '../interfaces/nvd-database.interface';

export interface SyncStatus {
  isRunning: boolean;
  currentPhase: 'idle' | 'download' | 'parse' | 'store' | 'complete' | 'error';
  progress: BatchProcessProgress | null;
  message: string;
  error?: string;
  lastSync?: Date;
  nextSync?: Date;
}

@Injectable({
  providedIn: 'root'
})
export class NvdSyncService {
  private readonly syncStatus$ = new BehaviorSubject<SyncStatus>({
    isRunning: false,
    currentPhase: 'idle',
    progress: null,
    message: '尚未開始同步'
  });

  private readonly SYNC_INTERVAL = 24 * 60 * 60 * 1000; // 24小時
  private syncTimer?: number;

  constructor(
    private downloadService: NvdDownloadService,
    private parserService: NvdParserService,
    private databaseService: NvdDatabaseService
  ) {
    this.initAutoSync();
  }

  /**
   * 取得同步狀態
   */
  getSyncStatus(): Observable<SyncStatus> {
    return this.syncStatus$.asObservable();
  }

  /**
   * 執行初始資料同步（近四年完整資料）
   */
  performInitialSync(): Observable<SyncStatus> {
    return new Observable(observer => {
      this.updateSyncStatus({
        isRunning: true,
        currentPhase: 'download',
        progress: null,
        message: '開始下載近四年 NVD 資料...'
      });

      const startTime = new Date();

      // 步驟 1: 下載資料
      this.downloadService.downloadRecentYearsData().subscribe({
        next: (downloadProgress) => {
          this.updateSyncStatus({
            isRunning: true,
            currentPhase: 'download',
            progress: downloadProgress,
            message: downloadProgress.message
          });
        },
        complete: () => {
          this.processDownloadedData(observer, startTime);
        },
        error: (error) => {
          this.handleSyncError(observer, error, '下載失敗');
        }
      });
    });
  }

  /**
   * 執行增量更新
   */
  performIncrementalSync(): Observable<SyncStatus> {
    return new Observable(observer => {
      this.updateSyncStatus({
        isRunning: true,
        currentPhase: 'download',
        progress: null,
        message: '檢查增量更新...'
      });

      // 檢查是否需要更新
      this.downloadService.checkForUpdates().subscribe({
        next: (needsUpdate) => {
          if (!needsUpdate) {
            this.updateSyncStatus({
              isRunning: false,
              currentPhase: 'complete',
              progress: null,
              message: '資料已是最新版本',
              lastSync: new Date()
            });
            observer.next(this.syncStatus$.value);
            observer.complete();
            return;
          }

          this.performIncrementalUpdate(observer);
        },
        error: (error) => {
          this.handleSyncError(observer, error, '檢查更新失敗');
        }
      });
    });
  }

  /**
   * 執行增量更新處理
   */
  private performIncrementalUpdate(observer: any): void {
    forkJoin({
      modified: this.downloadService.downloadIncrementalUpdate(),
      recent: this.downloadService.downloadRecentUpdate()
    }).subscribe({
      next: ({ modified, recent }) => {
        this.processIncrementalData(modified, recent, observer);
      },
      error: (error) => {
        this.handleSyncError(observer, error, '增量更新下載失敗');
      }
    });
  }

  /**
   * 處理下載的完整資料
   */
  private async processDownloadedData(observer: any, startTime: Date): Promise<void> {
    try {
      this.updateSyncStatus({
        isRunning: true,
        currentPhase: 'parse',
        progress: null,
        message: '開始解析下載的資料...'
      });

      // 取得下載的真實資料
      const downloadedData = this.downloadService.getDownloadedData();
      
      if (downloadedData.size === 0) {
        observer.error(new Error('沒有找到下載的資料'));
        return;
      }

      // 合併所有年度的 CVE 資料
      const combinedData = this.combineYearlyData(downloadedData);
      
      let dataToStore: CveRecord[] = [];
      let isParsingComplete = false;
      
      this.parserService.parseNvdData(combinedData, this.generateDataVersion()).subscribe({
        next: (parseResult) => {
          if (parseResult.type === 'progress' && parseResult.progress) {
            this.updateSyncStatus({
              isRunning: true,
              currentPhase: 'parse',
              progress: parseResult.progress,
              message: parseResult.progress.message
            });
          } else if (parseResult.type === 'cve' && parseResult.data) {
            // 累積要儲存的資料，而不是立即儲存
            dataToStore.push(...(parseResult.data as CveRecord[]));
          } else if (parseResult.type === 'cpe' && parseResult.data) {
            // CPE 資料可以立即儲存，因為通常較少
            this.storeCpeData(parseResult.data as CpeRecord[], observer);
          } else if (parseResult.type === 'complete') {
            isParsingComplete = true;
            // 解析完成後，開始批次儲存所有 CVE 資料
            if (dataToStore.length > 0) {
              this.storeCveDataAndComplete(dataToStore, observer, startTime);
            } else {
              this.completeSyncProcess(observer, startTime);
            }
          }
        },
        error: (error) => {
          this.handleSyncError(observer, error, '資料解析失敗');
        }
      });
    } catch (error) {
      this.handleSyncError(observer, error as Error, '處理下載資料失敗');
    } finally {
      // 清理下載的資料以釋放記憶體
      this.downloadService.clearDownloadedData();
    }
  }

  /**
   * 處理增量資料
   */
  private processIncrementalData(
    modifiedUpdate: IncrementalUpdate,
    recentData: any,
    observer: any
  ): void {
    this.updateSyncStatus({
      isRunning: true,
      currentPhase: 'parse',
      progress: null,
      message: '解析增量更新資料...'
    });

    let dataToStore: CveRecord[] = [];
    let isParsingComplete = false;

    // 解析 modified 資料
    this.parserService.parseNvdData(recentData).subscribe({
      next: (parseResult) => {
        if (parseResult.type === 'progress' && parseResult.progress) {
          this.updateSyncStatus({
            isRunning: true,
            currentPhase: 'parse',
            progress: parseResult.progress,
            message: parseResult.progress.message
          });
        } else if (parseResult.type === 'cve' && parseResult.data) {
          // 累積要儲存的資料，而不是立即儲存
          dataToStore.push(...(parseResult.data as CveRecord[]));
        } else if (parseResult.type === 'complete') {
          isParsingComplete = true;
          // 解析完成後，開始批次儲存所有 CVE 資料
          if (dataToStore.length > 0) {
            this.updateCveRecordsAndComplete(dataToStore, observer, modifiedUpdate);
          } else {
            this.completeIncrementalSync(observer, modifiedUpdate);
          }
        }
      },
      error: (error) => {
        this.handleSyncError(observer, error, '增量資料解析失敗');
      }
    });
  }

  /**
   * 儲存 CVE 資料
   */
  private storeCveData(records: CveRecord[], observer: any): void {
    this.updateSyncStatus({
      isRunning: true,
      currentPhase: 'store',
      progress: null,
      message: '儲存 CVE 資料到本地資料庫...'
    });

    this.databaseService.storeCveRecords(records).subscribe({
      next: (storeProgress) => {
        this.updateSyncStatus({
          isRunning: true,
          currentPhase: 'store',
          progress: storeProgress,
          message: storeProgress.message
        });
      },
      error: (error) => {
        this.handleSyncError(observer, error, 'CVE 資料儲存失敗');
      }
    });
  }

  /**
   * 儲存 CVE 資料並完成同步流程
   */
  private storeCveDataAndComplete(records: CveRecord[], observer: any, startTime: Date): void {
    this.updateSyncStatus({
      isRunning: true,
      currentPhase: 'store',
      progress: null,
      message: '儲存 CVE 資料到本地資料庫...'
    });

    this.databaseService.storeCveRecords(records).subscribe({
      next: (storeProgress) => {
        this.updateSyncStatus({
          isRunning: true,
          currentPhase: 'store',
          progress: storeProgress,
          message: storeProgress.message
        });
      },
      complete: () => {
        // CVE 資料儲存完成，開始完成同步流程
        this.completeSyncProcess(observer, startTime);
      },
      error: (error) => {
        this.handleSyncError(observer, error, 'CVE 資料儲存失敗');
      }
    });
  }

  /**
   * 儲存 CPE 資料
   */
  private storeCpeData(records: CpeRecord[], observer: any): void {
    this.updateSyncStatus({
      isRunning: true,
      currentPhase: 'store',
      progress: null,
      message: '儲存 CPE 資料到本地資料庫...'
    });

    this.databaseService.storeCpeRecords(records).subscribe({
      next: (storeProgress) => {
        this.updateSyncStatus({
          isRunning: true,
          currentPhase: 'store',
          progress: storeProgress,
          message: storeProgress.message
        });
      },
      error: (error) => {
        this.handleSyncError(observer, error, 'CPE 資料儲存失敗');
      }
    });
  }

  /**
   * 更新 CVE 記錄（增量更新用）
   */
  private updateCveRecords(records: CveRecord[], observer: any): void {
    this.updateSyncStatus({
      isRunning: true,
      currentPhase: 'store',
      progress: null,
      message: '更新 CVE 記錄...'
    });

    // 這裡可以實作更智慧的更新邏輯，比較現有記錄與新記錄的差異
    this.databaseService.storeCveRecords(records).subscribe({
      next: (storeProgress) => {
        this.updateSyncStatus({
          isRunning: true,
          currentPhase: 'store',
          progress: storeProgress,
          message: `更新中... ${storeProgress.message}`
        });
      },
      error: (error) => {
        this.handleSyncError(observer, error, 'CVE 記錄更新失敗');
      }
    });
  }

  /**
   * 更新 CVE 記錄並完成增量同步流程
   */
  private updateCveRecordsAndComplete(records: CveRecord[], observer: any, updateInfo: IncrementalUpdate): void {
    this.updateSyncStatus({
      isRunning: true,
      currentPhase: 'store',
      progress: null,
      message: '更新 CVE 記錄...'
    });

    // 更新記錄數量資訊
    updateInfo.itemsUpdated = records.length;

    this.databaseService.storeCveRecords(records).subscribe({
      next: (storeProgress) => {
        this.updateSyncStatus({
          isRunning: true,
          currentPhase: 'store',
          progress: storeProgress,
          message: `更新中... ${storeProgress.message}`
        });
      },
      complete: () => {
        // CVE 資料更新完成，開始完成增量同步流程
        this.completeIncrementalSync(observer, updateInfo);
      },
      error: (error) => {
        this.handleSyncError(observer, error, 'CVE 記錄更新失敗');
      }
    });
  }

  /**
   * 完成同步程序
   */
  private completeSyncProcess(observer: any, startTime: Date): void {
    const duration = Date.now() - startTime.getTime();
    const durationMinutes = Math.round(duration / 60000);

    // 儲存同步時間記錄
    this.databaseService.storeMetadata('last_sync', new Date().toISOString()).subscribe({
      next: () => {
        const nextSync = new Date(Date.now() + this.SYNC_INTERVAL);
        
        this.updateSyncStatus({
          isRunning: false,
          currentPhase: 'complete',
          progress: null,
          message: `同步完成！耗時 ${durationMinutes} 分鐘`,
          lastSync: new Date(),
          nextSync: nextSync
        });

        observer.next(this.syncStatus$.value);
        observer.complete();
        
        // 設定下次自動同步
        this.scheduleNextSync();
      },
      error: (error) => {
        this.handleSyncError(observer, error, '儲存同步記錄失敗');
      }
    });
  }

  /**
   * 完成增量同步
   */
  private completeIncrementalSync(observer: any, updateInfo: IncrementalUpdate): void {
    this.databaseService.storeMetadata('last_sync', updateInfo.lastSync).subscribe({
      next: () => {
        const nextSync = new Date(Date.now() + this.SYNC_INTERVAL);
        
        this.updateSyncStatus({
          isRunning: false,
          currentPhase: 'complete',
          progress: null,
          message: `增量更新完成！更新了 ${updateInfo.itemsUpdated} 筆記錄`,
          lastSync: new Date(),
          nextSync: nextSync
        });

        observer.next(this.syncStatus$.value);
        observer.complete();
        
        this.scheduleNextSync();
      },
      error: (error) => {
        this.handleSyncError(observer, error, '儲存增量更新記錄失敗');
      }
    });
  }

  /**
   * 處理同步錯誤
   */
  private handleSyncError(observer: any, error: Error, context: string): void {
    const errorMessage = `${context}: ${error.message}`;
    
    this.updateSyncStatus({
      isRunning: false,
      currentPhase: 'error',
      progress: null,
      message: errorMessage,
      error: errorMessage
    });

    observer.next(this.syncStatus$.value);
    observer.error(error);
    
    // 即使失敗也要設定下次同步（延長間隔）
    this.scheduleNextSync(60 * 60 * 1000); // 1小時後重試
  }

  /**
   * 更新同步狀態
   */
  private updateSyncStatus(update: Partial<SyncStatus>): void {
    const currentStatus = this.syncStatus$.value;
    const newStatus = { ...currentStatus, ...update };
    console.log('同步狀態更新:', {
      前一狀態: `${currentStatus.currentPhase} (isRunning: ${currentStatus.isRunning})`,
      新狀態: `${newStatus.currentPhase} (isRunning: ${newStatus.isRunning})`,
      訊息: newStatus.message
    });
    this.syncStatus$.next(newStatus);
  }

  /**
   * 初始化自動同步
   */
  private initAutoSync(): void {
    // 檢查是否需要初始同步
    this.databaseService.getDatabaseStats().subscribe({
      next: (stats) => {
        if (stats.totalCveCount === 0) {
          console.log('檢測到空資料庫，建議執行初始同步');
        } else {
          console.log(`本地資料庫包含 ${stats.totalCveCount} 筆 CVE 記錄`);
          // 設定定期增量更新
          this.scheduleNextSync();
        }
      },
      error: (error) => {
        console.warn('無法檢查資料庫狀態:', error);
      }
    });
  }

  /**
   * 排程下次同步
   */
  private scheduleNextSync(customInterval?: number): void {
    if (this.syncTimer) {
      clearTimeout(this.syncTimer);
    }

    const interval = customInterval || this.SYNC_INTERVAL;
    this.syncTimer = window.setTimeout(() => {
      this.performIncrementalSync().subscribe({
        next: () => console.log('自動增量同步完成'),
        error: (error) => console.error('自動增量同步失敗:', error)
      });
    }, interval);

    console.log(`已排程下次同步：${new Date(Date.now() + interval).toLocaleString()}`);
  }

  /**
   * 合併年度資料
   */
  private combineYearlyData(downloadedData: Map<number, any>): any {
    const combinedVulnerabilities: any[] = [];
    
    // 合併所有年度的 CVE 資料
    for (const [, yearData] of downloadedData.entries()) {
      if (yearData && yearData.CVE_Items) {
        // 舊格式 (API 1.1)
        combinedVulnerabilities.push(...yearData.CVE_Items);
      } else if (yearData && yearData.vulnerabilities) {
        // 新格式 (API 2.0)
        combinedVulnerabilities.push(...yearData.vulnerabilities);
      }
    }
    
    console.log(`合併了 ${combinedVulnerabilities.length} 筆 CVE 資料從 ${downloadedData.size} 個年度檔案`);
    
    return {
      vulnerabilities: combinedVulnerabilities,
      CVE_Items: combinedVulnerabilities // 支援舊格式
    };
  }

  /**
   * 產生資料版本標識
   */
  private generateDataVersion(): string {
    const now = new Date();
    return `${now.getFullYear()}-${(now.getMonth() + 1).toString().padStart(2, '0')}-${now.getDate().toString().padStart(2, '0')}`;
  }

  /**
   * 取消自動同步
   */
  cancelAutoSync(): void {
    if (this.syncTimer) {
      clearTimeout(this.syncTimer);
      this.syncTimer = undefined;
    }
  }

  /**
   * 強制執行同步（手動觸發）
   */
  forceSyncNow(): Observable<SyncStatus> {
    return this.databaseService.getDatabaseStats().pipe(
      switchMap((stats) => {
        if (stats.totalCveCount === 0) {
          return this.performInitialSync();
        } else {
          return this.performIncrementalSync();
        }
      })
    );
  }

  /**
   * 取得資料庫統計資訊
   */
  getDatabaseStats(): Observable<DatabaseVersion> {
    return this.databaseService.getDatabaseStats();
  }

  /**
   * 清除本地資料庫
   */
  clearLocalDatabase(): Observable<void> {
    return this.databaseService.clearAllData().pipe(
      tap(() => {
        this.updateSyncStatus({
          isRunning: false,
          currentPhase: 'idle',
          progress: null,
          message: '本地資料庫已清除'
        });
      })
    );
  }

  /**
   * 檢查網路連線
   */
  testConnection(): Observable<boolean> {
    return this.downloadService.testConnection();
  }
}