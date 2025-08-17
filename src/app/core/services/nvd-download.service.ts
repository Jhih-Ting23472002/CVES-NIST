import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpEventType } from '@angular/common/http';
import { Observable, of, throwError, BehaviorSubject } from 'rxjs';
import { map, catchError, tap } from 'rxjs/operators';
import * as pako from 'pako';
import {
  NvdDataFile,
  BatchProcessProgress,
  IncrementalUpdate
} from '../interfaces/nvd-database.interface';
import { getDatabaseConfig, getYearsList } from '../config/database.config';

@Injectable({
  providedIn: 'root'
})
export class NvdDownloadService {
  private readonly NVD_BASE_URL = 'https://nvd.nist.gov/feeds/json/cve/2.0';
  private readonly databaseConfig = getDatabaseConfig();
  
  private downloadProgress$ = new BehaviorSubject<BatchProcessProgress | null>(null);
  private downloadedData: Map<number, any> = new Map(); // 儲存下載的資料
  
  constructor(private http: HttpClient) {}

  /**
   * 取得下載進度 Observable
   */
  getDownloadProgress(): Observable<BatchProcessProgress | null> {
    return this.downloadProgress$.asObservable();
  }

  /**
   * 下載並解析配置年限的 NVD 資料
   */
  downloadRecentYearsData(): Observable<BatchProcessProgress> {
    const years = getYearsList(this.databaseConfig);
    const totalFiles = years.length;
    let processedFiles = 0;

    return new Observable(observer => {
      const processYear = async (yearIndex: number) => {
        if (yearIndex >= years.length) {
          observer.next({
            type: 'download',
            processed: totalFiles,
            total: totalFiles,
            percentage: 100,
            message: '所有年度資料下載完成',
            startTime: new Date(),
          });
          observer.complete();
          return;
        }

        const year = years[yearIndex];
        const progress: BatchProcessProgress = {
          type: 'download',
          currentFile: `nvdcve-1.1-${year}.json.gz`,
          processed: processedFiles,
          total: totalFiles,
          percentage: (processedFiles / totalFiles) * 100,
          message: `正在下載 ${year} 年度資料...`,
          startTime: new Date(),
        };
        
        this.downloadProgress$.next(progress);
        observer.next(progress);

        try {
          const data = await this.downloadYearData(year);
          // 儲存下載的資料
          this.downloadedData.set(year, data);
          processedFiles++;
          
          // 更新進度
          const completeProgress: BatchProcessProgress = {
            type: 'download',
            currentFile: `nvdcve-1.1-${year}.json.gz`,
            processed: processedFiles,
            total: totalFiles,
            percentage: (processedFiles / totalFiles) * 100,
            message: `${year} 年度資料下載完成 (${data.vulnerabilities?.length || 0} 筆 CVE)`,
            startTime: new Date(),
          };
          
          this.downloadProgress$.next(completeProgress);
          observer.next(completeProgress);

          // 延遲一下再下載下一個檔案，避免對伺服器造成過大負擔
          setTimeout(() => processYear(yearIndex + 1), 1000);
        } catch (error) {
          observer.error(error);
        }
      };

      processYear(0);
    });
  }

  /**
   * 下載特定年份的 CVE 資料 (使用 NVD 2.0 JSON 格式)
   */
  downloadYearData(year: number): Promise<any> {
    const url = `${this.NVD_BASE_URL}/nvdcve-2.0-${year}.json.gz`;
    
    return new Promise((resolve, reject) => {
      // 使用原生 fetch 以支援串流處理
      fetch(url)
        .then(response => {
          if (!response.ok) {
            throw new Error(`下載 ${year} 年度資料失敗: ${response.status}`);
          }
          return response.arrayBuffer();
        })
        .then(buffer => {
          // 解壓縮 gzip 檔案
          const compressed = new Uint8Array(buffer);
          const decompressed = pako.inflate(compressed, { to: 'string' });
          
          // 解析 JSON
          const jsonData = JSON.parse(decompressed);
          resolve(jsonData);
        })
        .catch(error => {
          console.error(`下載 ${year} 年度資料時發生錯誤:`, error);
          reject(new Error(`下載 ${year} 年度資料失敗: ${error.message}`));
        });
    });
  }

  /**
   * 下載增量更新資料（modified.json.gz）
   */
  downloadIncrementalUpdate(): Observable<IncrementalUpdate> {
    const url = `${this.NVD_BASE_URL}/nvdcve-2.0-modified.json.gz`;
    
    return new Observable(observer => {
      fetch(url)
        .then(response => {
          if (!response.ok) {
            throw new Error(`下載增量更新失敗: ${response.status}`);
          }
          return response.arrayBuffer();
        })
        .then(buffer => {
          // 解壓縮
          const compressed = new Uint8Array(buffer);
          const decompressed = pako.inflate(compressed, { to: 'string' });
          
          // 解析 JSON
          const jsonData = JSON.parse(decompressed);
          
          const incrementalUpdate: IncrementalUpdate = {
            type: 'modified',
            url: url,
            lastSync: new Date().toISOString(),
            itemsUpdated: jsonData.vulnerabilities?.length || 0,
            itemsAdded: 0, // 需要與現有資料比較才能知道
            itemsRemoved: 0
          };
          
          observer.next(incrementalUpdate);
          observer.complete();
        })
        .catch(error => {
          console.error('下載增量更新時發生錯誤:', error);
          observer.error(new Error(`下載增量更新失敗: ${error.message}`));
        });
    });
  }

  /**
   * 下載最近更新的 CVE（recent.json.gz）
   */
  downloadRecentUpdate(): Observable<any> {
    const url = `${this.NVD_BASE_URL}/nvdcve-2.0-recent.json.gz`;
    
    return new Observable(observer => {
      fetch(url)
        .then(response => {
          if (!response.ok) {
            throw new Error(`下載最近更新失敗: ${response.status}`);
          }
          return response.arrayBuffer();
        })
        .then(buffer => {
          const compressed = new Uint8Array(buffer);
          const decompressed = pako.inflate(compressed, { to: 'string' });
          const jsonData = JSON.parse(decompressed);
          
          observer.next(jsonData);
          observer.complete();
        })
        .catch(error => {
          console.error('下載最近更新時發生錯誤:', error);
          observer.error(error);
        });
    });
  }

  /**
   * 檢查 NVD 資料檔案的元資料
   */
  checkDataFileMetadata(year: number): Observable<any> {
    const metaUrl = `${this.NVD_BASE_URL}/nvdcve-2.0-${year}.meta`;
    
    return this.http.get(metaUrl, { 
      responseType: 'text',
      headers: new HttpHeaders({
        'Accept': 'text/plain'
      })
    }).pipe(
      map(response => this.parseMetadata(response)),
      catchError(error => {
        console.error(`取得 ${year} 年度檔案元資料失敗:`, error);
        return throwError(() => error);
      })
    );
  }

  /**
   * 取得資料檔案清單
   */
  getDataFileList(): NvdDataFile[] {
    const years = getYearsList(this.databaseConfig);
    return years.map(year => ({
      year,
      url: `${this.NVD_BASE_URL}/nvdcve-2.0-${year}.json.gz`,
      expectedSize: this.getExpectedFileSize(year),
      isIncremental: false
    }));
  }

  /**
   * 取得增量更新檔案清單
   */
  getIncrementalFileList(): NvdDataFile[] {
    return [
      {
        year: 0, // 特殊標記為增量檔案
        url: `${this.NVD_BASE_URL}/nvdcve-2.0-modified.json.gz`,
        expectedSize: 50 * 1024 * 1024, // 預估 50MB
        isIncremental: true
      },
      {
        year: 0,
        url: `${this.NVD_BASE_URL}/nvdcve-2.0-recent.json.gz`,
        expectedSize: 10 * 1024 * 1024, // 預估 10MB
        isIncremental: true
      }
    ];
  }

  /**
   * 檢查是否需要更新本地資料
   */
  checkForUpdates(): Observable<boolean> {
    // 檢查 modified.json.gz 的最後修改時間
    const metaUrl = `${this.NVD_BASE_URL}/nvdcve-2.0-modified.meta`;
    
    return this.http.get(metaUrl, { responseType: 'text' }).pipe(
      map(response => {
        const metadata = this.parseMetadata(response);
        const lastModified = new Date(metadata.lastModifiedDate);
        
        // 與本地記錄的最後同步時間比較
        const lastSync = localStorage.getItem('nvd_last_sync');
        if (!lastSync) {
          return true; // 從未同步過，需要更新
        }
        
        const lastSyncDate = new Date(lastSync);
        return lastModified > lastSyncDate;
      }),
      catchError(error => {
        console.error('檢查更新時發生錯誤:', error);
        return of(true); // 發生錯誤時假設需要更新
      })
    );
  }

  /**
   * 取得配置的資料庫配置
   */
  getDatabaseConfig() {
    return this.databaseConfig;
  }

  /**
   * 取得配置年限的年份清單
   */
  getConfiguredYears(): number[] {
    return getYearsList(this.databaseConfig);
  }

  /**
   * 解析元資料檔案
   */
  private parseMetadata(metaText: string): any {
    const lines = metaText.split('\n');
    const metadata: any = {};
    
    for (const line of lines) {
      const [key, ...valueParts] = line.split(':');
      if (key && valueParts.length > 0) {
        const value = valueParts.join(':').trim();
        metadata[key.trim()] = value;
      }
    }
    
    return metadata;
  }

  /**
   * 取得預期檔案大小（根據歷史經驗估算）
   */
  private getExpectedFileSize(year: number): number {
    // 根據年份估算檔案大小（MB）
    const sizeMB = year >= 2020 ? 300 : year >= 2015 ? 200 : 100;
    return sizeMB * 1024 * 1024;
  }

  /**
   * 取得下載的資料
   */
  getDownloadedData(): Map<number, any> {
    return new Map(this.downloadedData);
  }

  /**
   * 清除下載的資料
   */
  clearDownloadedData(): void {
    this.downloadedData.clear();
  }

  /**
   * 清除下載進度
   */
  clearProgress(): void {
    this.downloadProgress$.next(null);
  }

  /**
   * 測試網路連線和 NVD 服務可用性
   */
  testConnection(): Observable<boolean> {
    const currentYear = new Date().getFullYear();
    const testUrl = `${this.NVD_BASE_URL}/nvdcve-2.0-${currentYear}.meta`;
    
    return this.http.head(testUrl).pipe(
      map(() => true),
      catchError(() => of(false))
    );
  }
}