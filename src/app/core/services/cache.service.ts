import { Injectable } from '@angular/core';
import { ICacheService } from '../interfaces/services.interface';

interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
}

@Injectable({
  providedIn: 'root'
})
export class CacheService implements ICacheService {
  private cache = new Map<string, CacheEntry<any>>();
  private readonly DEFAULT_TTL = 24 * 60 * 60 * 1000; // 24 小時
  private readonly MAX_CACHE_SIZE = 1000;

  get<T>(key: string): T | null {
    const entry = this.cache.get(key);
    
    if (!entry) {
      return null;
    }

    // 檢查是否過期
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry.data as T;
  }

  set<T>(key: string, value: T, ttl: number = this.DEFAULT_TTL): void {
    // 如果快取已滿，清除最舊的項目
    if (this.cache.size >= this.MAX_CACHE_SIZE) {
      this.evictOldestEntries();
    }

    const entry: CacheEntry<T> = {
      data: value,
      timestamp: Date.now(),
      ttl
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
  } {
    return {
      size: this.cache.size,
      maxSize: this.MAX_CACHE_SIZE,
      hitRate: this.calculateHitRate(),
      memoryUsage: this.estimateMemoryUsage()
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

  // 計算命中率（簡化版本）
  private calculateHitRate(): number {
    // 這裡只是示例，實際實作需要追蹤命中/未命中次數
    return 0.85; // 假設 85% 命中率
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

  // 快取漏洞資料
  cacheVulnerabilities(packageName: string, version: string, vulnerabilities: any[]): void {
    const key = CacheService.createVulnerabilityKey(packageName, version);
    this.set(key, vulnerabilities, this.DEFAULT_TTL);
  }

  // 取得快取的漏洞資料
  getCachedVulnerabilities(packageName: string, version: string): any[] | null {
    const key = CacheService.createVulnerabilityKey(packageName, version);
    return this.get(key);
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
}