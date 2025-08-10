import { Injectable } from '@angular/core';
import { ICacheService } from '../interfaces/services.interface';

interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
  accessCount: number;
  lastAccessed: number;
  source: 'api' | 'local' | 'hybrid';
  isFallback?: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class CacheService implements ICacheService {
  private cache = new Map<string, CacheEntry<any>>();
  private readonly DEFAULT_TTL = 24 * 60 * 60 * 1000; // 24 小時
  private readonly LOCAL_TTL = 7 * 24 * 60 * 60 * 1000; // 7 天 (本地掃描結果)
  private readonly MAX_CACHE_SIZE = 1000;
  private hits = 0;
  private misses = 0;

  get<T>(key: string): T | null {
    const entry = this.cache.get(key);
    
    if (!entry) {
      this.misses++;
      return null;
    }

    // 檢查是否過期
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      this.misses++;
      return null;
    }

    // 更新存取統計
    entry.accessCount++;
    entry.lastAccessed = Date.now();
    this.hits++;

    return entry.data as T;
  }

  set<T>(key: string, value: T, ttl: number = this.DEFAULT_TTL, source: 'api' | 'local' | 'hybrid' = 'api'): void {
    // 如果快取已滿，清除最舊的項目
    if (this.cache.size >= this.MAX_CACHE_SIZE) {
      this.evictOldestEntries();
    }

    const entry: CacheEntry<T> = {
      data: value,
      timestamp: Date.now(),
      ttl,
      accessCount: 1,
      lastAccessed: Date.now(),
      source,
      isFallback: false
    };

    this.cache.set(key, entry);
  }

  has(key: string): boolean {
    const entry = this.cache.get(key);
    
    if (!entry) {
      return false;
    }

    // 檢查是否過期
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  remove(key: string): void {
    this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
  }

  getKeys(): string[] {
    // 清理過期項目
    this.cleanupExpired();
    return Array.from(this.cache.keys());
  }

  // 取得快取統計資訊
  getStats(): {
    size: number;
    maxSize: number;
    hitRate: number;
    memoryUsage: string;
    sourceDistribution: { api: number; local: number; hybrid: number };
    averageAge: number;
    frequentlyUsed: string[];
  } {
    const sourceStats = { api: 0, local: 0, hybrid: 0 };
    let totalAge = 0;
    const accessCounts = new Map<string, number>();
    const now = Date.now();

    for (const [key, entry] of this.cache.entries()) {
      sourceStats[entry.source]++;
      totalAge += now - entry.timestamp;
      accessCounts.set(key, entry.accessCount);
    }

    // 取得最常存取的 5 個項目
    const sortedByAccess = Array.from(accessCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([key]) => key);

    return {
      size: this.cache.size,
      maxSize: this.MAX_CACHE_SIZE,
      hitRate: this.calculateHitRate(),
      memoryUsage: this.estimateMemoryUsage(),
      sourceDistribution: sourceStats,
      averageAge: this.cache.size > 0 ? totalAge / this.cache.size : 0,
      frequentlyUsed: sortedByAccess
    };
  }

  // 清理過期的快取項目
  private cleanupExpired(): void {
    const now = Date.now();
    const keysToDelete: string[] = [];

    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp > entry.ttl) {
        keysToDelete.push(key);
      }
    }

    keysToDelete.forEach(key => this.cache.delete(key));
  }

  // 清除最舊的項目以騰出空間
  private evictOldestEntries(): void {
    const entries = Array.from(this.cache.entries());
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
    
    // 清除最舊的 10% 項目
    const toEvict = Math.ceil(entries.length * 0.1);
    for (let i = 0; i < toEvict; i++) {
      this.cache.delete(entries[i][0]);
    }
  }

  // 計算命中率
  private calculateHitRate(): number {
    const total = this.hits + this.misses;
    return total === 0 ? 0 : (this.hits / total) * 100;
  }

  // 估算記憶體使用量
  private estimateMemoryUsage(): string {
    const estimatedSize = this.cache.size * 1024; // 每個項目約 1KB
    if (estimatedSize < 1024 * 1024) {
      return `${Math.round(estimatedSize / 1024)}KB`;
    } else {
      return `${Math.round(estimatedSize / (1024 * 1024))}MB`;
    }
  }

  // 建立特定的快取 key
  static createVulnerabilityKey(packageName: string, version: string, noRejected: boolean = true): string {
    const baseKey = `vuln:${packageName}@${version}`;
    return noRejected ? `${baseKey}:noRejected` : baseKey;
  }

  static createPackageKey(packageName: string): string {
    return `pkg:${packageName}`;
  }

  static createScanKey(scanId: string): string {
    return `scan:${scanId}`;
  }

  // 快取漏洞資料（支援來源標記）
  cacheVulnerabilities(packageName: string, version: string, vulnerabilities: any[], source: 'api' | 'local' | 'hybrid' = 'api'): void {
    const key = CacheService.createVulnerabilityKey(packageName, version);
    const ttl = source === 'local' ? this.LOCAL_TTL : this.DEFAULT_TTL;
    this.set(key, vulnerabilities, ttl, source);
  }

  // 取得快取的漏洞資料
  getCachedVulnerabilities(packageName: string, version: string): any[] | null {
    const key = CacheService.createVulnerabilityKey(packageName, version);
    return this.get(key);
  }

  // 快取本地掃描結果
  cacheLocalScanResult(packageName: string, version: string, vulnerabilities: any[]): void {
    this.cacheVulnerabilities(packageName, version, vulnerabilities, 'local');
  }

  // 快取混合掃描結果（本地 + API）
  cacheHybridScanResult(packageName: string, version: string, vulnerabilities: any[]): void {
    this.cacheVulnerabilities(packageName, version, vulnerabilities, 'hybrid');
  }

  // 設定回退快取（當主要掃描失敗時使用）
  setFallbackCache<T>(key: string, value: T, source: 'api' | 'local'): void {
    const entry: CacheEntry<T> = {
      data: value,
      timestamp: Date.now(),
      ttl: this.DEFAULT_TTL,
      accessCount: 1,
      lastAccessed: Date.now(),
      source,
      isFallback: true
    };
    this.cache.set(key + ':fallback', entry);
  }

  // 取得回退快取
  getFallbackCache<T>(key: string): T | null {
    return this.get(key + ':fallback');
  }

  // 快取套件資訊
  cachePackageInfo(packageName: string, info: any): void {
    const key = CacheService.createPackageKey(packageName);
    this.set(key, info, 12 * 60 * 60 * 1000); // 12 小時
  }

  // 取得快取的套件資訊
  getCachedPackageInfo(packageName: string): any | null {
    const key = CacheService.createPackageKey(packageName);
    return this.get(key);
  }

  // 定期清理過期項目（可由外部定時器呼叫）
  performMaintenance(): void {
    this.cleanupExpired();
    
    // 如果快取使用量過高，主動清理
    if (this.cache.size > this.MAX_CACHE_SIZE * 0.8) {
      this.evictOldestEntries();
    }
  }

  // 優先保留本地掃描結果的智慧清理
  performSmartCleanup(): void {
    const entries = Array.from(this.cache.entries());
    
    // 按優先級排序：本地 > 混合 > API，然後按存取次數和時間
    entries.sort((a, b) => {
      const [keyA, entryA] = a;
      const [keyB, entryB] = b;
      
      // 優先級權重
      const sourceWeight = { local: 3, hybrid: 2, api: 1 };
      const weightA = sourceWeight[entryA.source];
      const weightB = sourceWeight[entryB.source];
      
      if (weightA !== weightB) {
        return weightB - weightA; // 較高權重在前
      }
      
      // 權重相同時，按存取次數排序
      if (entryA.accessCount !== entryB.accessCount) {
        return entryB.accessCount - entryA.accessCount;
      }
      
      // 最後按時間排序（較新的在前）
      return entryB.timestamp - entryA.timestamp;
    });
    
    // 清除最低優先級的 10% 項目
    const toEvict = Math.ceil(entries.length * 0.1);
    const toRemove = entries.slice(-toEvict);
    
    toRemove.forEach(([key]) => {
      this.cache.delete(key);
    });
  }

  // 清除特定來源的快取
  clearBySource(source: 'api' | 'local' | 'hybrid'): void {
    const keysToDelete: string[] = [];
    
    for (const [key, entry] of this.cache.entries()) {
      if (entry.source === source) {
        keysToDelete.push(key);
      }
    }
    
    keysToDelete.forEach(key => this.cache.delete(key));
  }

  // 取得特定來源的快取統計
  getSourceStats(source: 'api' | 'local' | 'hybrid'): {
    count: number;
    averageAge: number;
    totalAccess: number;
  } {
    let count = 0;
    let totalAge = 0;
    let totalAccess = 0;
    const now = Date.now();
    
    for (const [key, entry] of this.cache.entries()) {
      if (entry.source === source) {
        count++;
        totalAge += now - entry.timestamp;
        totalAccess += entry.accessCount;
      }
    }
    
    return {
      count,
      averageAge: count > 0 ? totalAge / count : 0,
      totalAccess
    };
  }

  // 重設統計資料
  resetStats(): void {
    this.hits = 0;
    this.misses = 0;
  }
}