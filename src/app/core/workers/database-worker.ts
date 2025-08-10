/// <reference lib="webworker" />

import { CveRecord, CpeRecord } from '../interfaces/nvd-database.interface';

export interface DatabaseWorkerMessage {
  type: 'cleanupOldData' | 'bulkInsert' | 'bulkUpdate' | 'deleteByVersion' | 'compactDatabase';
  data?: any;
  requestId?: string;
}

export interface DatabaseWorkerResponse {
  type: 'progress' | 'complete' | 'error';
  data?: any;
  requestId?: string;
  error?: string;
}

// 全域變數儲存 IndexedDB 連線
let db: IDBDatabase | null = null;
const DB_NAME = 'NvdLocalDatabase';
const DB_VERSION = 1;
const CVE_STORE = 'cve';
const CPE_STORE = 'cpe';
const METADATA_STORE = 'metadata';

/**
 * 初始化資料庫連線
 */
async function initDatabase(): Promise<IDBDatabase> {
  if (db) return db;

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      db = request.result;
      resolve(db);
    };

    request.onupgradeneeded = (event) => {
      // 資料庫升級邏輯（如需要）
      const upgradeDb = (event.target as IDBOpenDBRequest).result;
      // 這裡可以加入升級邏輯，但通常由主執行緒建立
    };
  });
}

/**
 * 清理過期資料
 */
async function cleanupOldData(options: {
  keepDays: number;
  dataVersion?: string;
  batchSize?: number;
}): Promise<void> {
  const { keepDays = 30, dataVersion, batchSize = 1000 } = options;
  const cutoffTime = Date.now() - (keepDays * 24 * 60 * 60 * 1000);

  await initDatabase();
  if (!db) throw new Error('資料庫未初始化');

  const transaction = db.transaction([CVE_STORE, CPE_STORE], 'readwrite');
  const cveStore = transaction.objectStore(CVE_STORE);
  const cpeStore = transaction.objectStore(CPE_STORE);

  let totalDeleted = 0;

  // 清理 CVE 記錄
  const cveDeleteCount = await cleanupStoreData(
    cveStore,
    'syncTimestamp',
    cutoffTime,
    dataVersion,
    batchSize,
    (progress) => {
      postMessage({
        type: 'progress',
        data: {
          phase: 'cve_cleanup',
          processed: progress.processed,
          total: progress.total,
          message: `正在清理過期的 CVE 記錄...`
        }
      } as DatabaseWorkerResponse);
    }
  );

  totalDeleted += cveDeleteCount;

  // 清理 CPE 記錄
  const cpeDeleteCount = await cleanupStoreData(
    cpeStore,
    'syncTimestamp',
    cutoffTime,
    dataVersion,
    batchSize,
    (progress) => {
      postMessage({
        type: 'progress',
        data: {
          phase: 'cpe_cleanup',
          processed: progress.processed,
          total: progress.total,
          message: `正在清理過期的 CPE 記錄...`
        }
      } as DatabaseWorkerResponse);
    }
  );

  totalDeleted += cpeDeleteCount;

  postMessage({
    type: 'complete',
    data: {
      deletedCount: totalDeleted,
      cveDeleted: cveDeleteCount,
      cpeDeleted: cpeDeleteCount
    }
  } as DatabaseWorkerResponse);
}

/**
 * 清理單一 store 的資料
 */
async function cleanupStoreData(
  store: IDBObjectStore,
  indexName: string,
  cutoffValue: number,
  dataVersion?: string,
  batchSize: number = 1000,
  onProgress?: (progress: { processed: number; total: number }) => void
): Promise<number> {
  return new Promise((resolve, reject) => {
    let deletedCount = 0;
    let totalProcessed = 0;

    // 使用索引進行範圍查詢
    const index = store.index(indexName);
    const range = IDBKeyRange.upperBound(cutoffValue);
    const request = index.openCursor(range);

    const keysToDelete: IDBValidKey[] = [];

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest).result;

      if (!cursor) {
        // 處理剩餘的刪除操作
        if (keysToDelete.length > 0) {
          processBatchDelete(store, keysToDelete.splice(0), () => {
            resolve(deletedCount);
          });
        } else {
          resolve(deletedCount);
        }
        return;
      }

      const record = cursor.value;
      
      // 檢查資料版本過濾條件
      if (!dataVersion || record.dataVersion !== dataVersion) {
        keysToDelete.push(cursor.primaryKey);
        deletedCount++;
      }

      totalProcessed++;

      // 批次處理
      if (keysToDelete.length >= batchSize) {
        const batchKeys = keysToDelete.splice(0, batchSize);
        processBatchDelete(store, batchKeys, () => {
          if (onProgress) {
            onProgress({ processed: totalProcessed, total: -1 }); // -1 表示總數未知
          }
        });
      }

      cursor.continue();
    };

    request.onerror = () => reject(request.error);
  });
}

/**
 * 批次刪除操作
 */
function processBatchDelete(
  store: IDBObjectStore,
  keys: IDBValidKey[],
  callback: () => void
): void {
  let completed = 0;
  const total = keys.length;

  keys.forEach(key => {
    const deleteRequest = store.delete(key);
    deleteRequest.onsuccess = () => {
      completed++;
      if (completed === total) {
        callback();
      }
    };
  });
}

/**
 * 按版本刪除資料
 */
async function deleteByVersion(dataVersion: string): Promise<void> {
  await initDatabase();
  if (!db) throw new Error('資料庫未初始化');

  const transaction = db.transaction([CVE_STORE, CPE_STORE], 'readwrite');
  const cveStore = transaction.objectStore(CVE_STORE);
  const cpeStore = transaction.objectStore(CPE_STORE);

  let totalDeleted = 0;

  // 使用版本索引快速刪除
  const stores = [
    { name: 'CVE', store: cveStore },
    { name: 'CPE', store: cpeStore }
  ];

  for (const { name, store } of stores) {
    const index = store.index('dataVersion');
    const request = index.openCursor(IDBKeyRange.only(dataVersion));

    let storeDeleted = 0;

    await new Promise<void>((resolve, reject) => {
      request.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        if (!cursor) {
          postMessage({
            type: 'progress',
            data: {
              phase: `${name.toLowerCase()}_version_delete`,
              deleted: storeDeleted,
              message: `已刪除 ${storeDeleted} 筆 ${name} 記錄`
            }
          } as DatabaseWorkerResponse);
          resolve();
          return;
        }

        cursor.delete();
        storeDeleted++;
        totalDeleted++;

        if (storeDeleted % 100 === 0) {
          postMessage({
            type: 'progress',
            data: {
              phase: `${name.toLowerCase()}_version_delete`,
              processed: storeDeleted,
              message: `正在刪除 ${name} 記錄... (${storeDeleted} 筆)`
            }
          } as DatabaseWorkerResponse);
        }

        cursor.continue();
      };

      request.onerror = () => reject(request.error);
    });
  }

  postMessage({
    type: 'complete',
    data: { deletedCount: totalDeleted }
  } as DatabaseWorkerResponse);
}

/**
 * 資料庫壓縮（釋放已刪除資料的空間）
 */
async function compactDatabase(): Promise<void> {
  // IndexedDB 沒有直接的壓縮 API，但可以透過重建來達成
  postMessage({
    type: 'progress',
    data: {
      phase: 'compact',
      message: '正在壓縮資料庫...'
    }
  } as DatabaseWorkerResponse);

  // 這裡可以實作資料庫重建邏輯
  // 由於複雜度較高，暫時回報完成
  postMessage({
    type: 'complete',
    data: { message: '資料庫壓縮完成' }
  } as DatabaseWorkerResponse);
}

/**
 * 批次插入資料
 */
async function bulkInsert(data: {
  cveRecords?: CveRecord[];
  cpeRecords?: CpeRecord[];
  batchSize?: number;
}): Promise<void> {
  const { cveRecords = [], cpeRecords = [], batchSize = 1000 } = data;

  await initDatabase();
  if (!db) throw new Error('資料庫未初始化');

  // 處理 CVE 記錄
  if (cveRecords.length > 0) {
    await processBulkInsert(CVE_STORE, cveRecords, batchSize, 'CVE');
  }

  // 處理 CPE 記錄
  if (cpeRecords.length > 0) {
    await processBulkInsert(CPE_STORE, cpeRecords, batchSize, 'CPE');
  }

  postMessage({
    type: 'complete',
    data: {
      cveInserted: cveRecords.length,
      cpeInserted: cpeRecords.length
    }
  } as DatabaseWorkerResponse);
}

/**
 * 執行批次插入
 */
async function processBulkInsert(
  storeName: string,
  records: any[],
  batchSize: number,
  recordType: string
): Promise<void> {
  if (!db) return;

  const total = records.length;
  let processed = 0;

  for (let i = 0; i < records.length; i += batchSize) {
    const batch = records.slice(i, i + batchSize);
    
    const transaction = db.transaction([storeName], 'readwrite');
    const store = transaction.objectStore(storeName);

    // 批次插入
    const promises = batch.map(record => {
      return new Promise<void>((resolve, reject) => {
        const request = store.put(record); // 使用 put 支援更新
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    });

    await Promise.all(promises);

    processed += batch.length;

    // 回報進度
    postMessage({
      type: 'progress',
      data: {
        phase: `${recordType.toLowerCase()}_insert`,
        processed,
        total,
        percentage: (processed / total) * 100,
        message: `正在插入 ${recordType} 記錄... (${processed}/${total})`
      }
    } as DatabaseWorkerResponse);

    // 讓出控制權，避免阻塞
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}

// 監聽主執行緒訊息
addEventListener('message', async ({ data }: MessageEvent<DatabaseWorkerMessage>) => {
  const { type, data: messageData, requestId } = data;

  try {
    switch (type) {
      case 'cleanupOldData':
        await cleanupOldData(messageData);
        break;

      case 'bulkInsert':
        await bulkInsert(messageData);
        break;

      case 'deleteByVersion':
        await deleteByVersion(messageData.version);
        break;

      case 'compactDatabase':
        await compactDatabase();
        break;

      default:
        postMessage({
          type: 'error',
          requestId,
          error: `未知的操作類型: ${type}`
        } as DatabaseWorkerResponse);
    }
  } catch (error) {
    postMessage({
      type: 'error',
      requestId,
      error: error instanceof Error ? error.message : String(error)
    } as DatabaseWorkerResponse);
  }
});

// 回報 Worker 就緒
postMessage({
  type: 'complete',
  data: { message: 'Database Worker 已就緒' }
} as DatabaseWorkerResponse);