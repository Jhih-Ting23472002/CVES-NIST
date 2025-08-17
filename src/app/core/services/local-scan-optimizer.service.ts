import { Injectable } from '@angular/core';
import { Observable, from, forkJoin } from 'rxjs';
import { map, mergeMap, tap } from 'rxjs/operators';
import { CveOptimizationService } from './cve-optimization.service';
import { NvdDatabaseService } from './nvd-database.service';
import { 
  PackageInfo, 
  Vulnerability, 
  ScanProgress 
} from '../models/vulnerability.model';
import {
  PackageVulnerabilityQuery,
  VulnerabilityQueryResult
} from '../interfaces/nvd-database.interface';

// 索引策略介面
interface IndexStrategy {
  name: string;
  priority: number;
  canHandle: (query: PackageVulnerabilityQuery) => boolean;
  execute: (query: PackageVulnerabilityQuery) => Observable<VulnerabilityQueryResult[]>;
}

// 批次查詢結果
interface BatchQueryResult {
  packageName: string;
  vulnerabilities: Vulnerability[];
  queryTime: number;
  cacheHit: boolean;
  strategy: string;
}

@Injectable({
  providedIn: 'root'
})
export class LocalScanOptimizerService {
  
  // 批次查詢優化配置
  private readonly optimalBatchSize = 8;
  private readonly maxConcurrentQueries = 4;
  
  // 智慧快取系統
  private readonly resultCache = new Map<string, { result: Vulnerability[]; timestamp: number; accessCount: number }>();
  private readonly maxCacheSize = 1000;
  private readonly cacheExpiry = 15 * 60 * 1000; // 15 分鐘
  
  // 效能統計
  private metrics = {
    totalQueries: 0,
    cacheHits: 0,
    cacheMisses: 0,
    averageQueryTime: 0,
    totalQueryTime: 0,
    indexStrategiesUsed: new Map<string, number>(),
    batchOptimizations: 0
  };
  
  // 索引策略
  private indexStrategies: IndexStrategy[] = [];

  constructor(
    private cveOptimization: CveOptimizationService,
    private databaseService: NvdDatabaseService
  ) {
    this.initializeIndexStrategies();
  }

  /**
   * 優化的批次掃描方法
   */
  optimizedBatchScan(packages: PackageInfo[]): Observable<BatchQueryResult[]> {
    const startTime = Date.now();
    
    return new Observable(observer => {
      console.log(`[LocalScanOptimizer] 開始優化批次掃描 ${packages.length} 個套件`);
      
      // 步驟 1: 檢查快取
      const { cachedResults, uncachedPackages } = this.separateCachedPackages(packages);
      console.log(`[LocalScanOptimizer] 快取命中: ${cachedResults.length}, 需要查詢: ${uncachedPackages.length}`);
      
      if (uncachedPackages.length === 0) {
        // 全部命中快取
        observer.next(cachedResults);
        observer.complete();
        return;
      }
      
      // 步驟 2: 分組優化（按生態系統分組）
      const groupedPackages = this.groupPackagesByEcosystem(uncachedPackages);
      
      // 步驟 3: 並行處理各組
      const groupQueries = Object.entries(groupedPackages).map(([ecosystem, pkgs]) => 
        this.processPackageGroup(ecosystem, pkgs)
      );
      
      forkJoin(groupQueries).subscribe({
        next: (groupResults) => {
          const flatResults = groupResults.flat();
          
          // 合併快取結果和新查詢結果
          const allResults = [...cachedResults, ...flatResults];
          
          // 更新效能統計
          this.updateMetrics(allResults, Date.now() - startTime);
          
          observer.next(allResults);
          observer.complete();
        },
        error: (error) => observer.error(error)
      });
    });
  }

  /**
   * 分離已快取和未快取的套件
   */
  private separateCachedPackages(packages: PackageInfo[]): {
    cachedResults: BatchQueryResult[];
    uncachedPackages: PackageInfo[];
  } {
    const cachedResults: BatchQueryResult[] = [];
    const uncachedPackages: PackageInfo[] = [];
    
    packages.forEach(pkg => {
      const cacheKey = this.generateCacheKey(pkg.name, pkg.version);
      
      if (this.resultCache.has(cacheKey)) {
        const cached = this.resultCache.get(cacheKey)!;
        
        // 檢查是否過期
        if (Date.now() - cached.timestamp < this.cacheExpiry) {
          cached.accessCount++;
          this.metrics.cacheHits++;
          
          cachedResults.push({
            packageName: pkg.packageKey || `${pkg.name}@${pkg.version}`,
            vulnerabilities: cached.result,
            queryTime: 0, // 快取查詢時間為 0
            cacheHit: true,
            strategy: 'cache'
          });
          return;
        } else {
          // 清理過期快取
          this.resultCache.delete(cacheKey);
        }
      }
      
      this.metrics.cacheMisses++;
      uncachedPackages.push(pkg);
    });
    
    return { cachedResults, uncachedPackages };
  }

  /**
   * 按生態系統分組套件
   */
  private groupPackagesByEcosystem(packages: PackageInfo[]): Record<string, PackageInfo[]> {
    const groups: Record<string, PackageInfo[]> = {};
    
    packages.forEach(pkg => {
      const ecosystem = this.detectEcosystem(pkg.name);
      
      if (!groups[ecosystem]) {
        groups[ecosystem] = [];
      }
      groups[ecosystem].push(pkg);
    });
    
    return groups;
  }

  /**
   * 處理套件組（生態系統特定優化）
   */
  private processPackageGroup(ecosystem: string, packages: PackageInfo[]): Observable<BatchQueryResult[]> {
    console.log(`[LocalScanOptimizer] 處理 ${ecosystem} 生態系統的 ${packages.length} 個套件`);
    
    // 根據批次大小分割
    const batches = this.createOptimalBatches(packages);
    
    // 序列處理批次（避免資料庫過載）
    return from(batches).pipe(
      mergeMap((batch, batchIndex) => 
        this.processBatchWithOptimization(batch, ecosystem, batchIndex), 
        this.maxConcurrentQueries
      ),
      map(results => results.flat())
    );
  }

  /**
   * 使用優化策略處理批次
   */
  private processBatchWithOptimization(
    batch: PackageInfo[], 
    ecosystem: string, 
    batchIndex: number
  ): Observable<BatchQueryResult[]> {
    
    return new Observable(observer => {
      const batchStart = Date.now();
      const results: BatchQueryResult[] = [];
      let completed = 0;
      
      console.log(`[LocalScanOptimizer] 處理批次 ${batchIndex + 1}，包含 ${batch.length} 個套件`);
      
      batch.forEach(async (pkg, index) => {
        try {
          const queryStart = Date.now();
          const query: PackageVulnerabilityQuery = {
            packageName: pkg.name,
            version: pkg.version,
            searchType: 'exact'
          };
          
          // 選擇最佳索引策略
          const strategy = this.selectOptimalStrategy(query, ecosystem);
          
          const vulnerabilityResults = await strategy.execute(query).toPromise();
          const vulnerabilities = this.transformResults(vulnerabilityResults || [], pkg.version);
          
          const queryTime = Date.now() - queryStart;
          
          // 更新快取
          this.updateCache(pkg.name, pkg.version, vulnerabilities);
          
          // 記錄策略使用
          const strategyCount = this.metrics.indexStrategiesUsed.get(strategy.name) || 0;
          this.metrics.indexStrategiesUsed.set(strategy.name, strategyCount + 1);
          
          results.push({
            packageName: pkg.packageKey || `${pkg.name}@${pkg.version}`,
            vulnerabilities,
            queryTime,
            cacheHit: false,
            strategy: strategy.name
          });
          
          completed++;
          
          if (completed === batch.length) {
            const batchTime = Date.now() - batchStart;
            console.log(`[LocalScanOptimizer] 批次 ${batchIndex + 1} 完成，耗時 ${batchTime}ms`);
            
            observer.next(results);
            observer.complete();
          }
          
        } catch (error) {
          console.error(`[LocalScanOptimizer] 套件 ${pkg.name} 查詢失敗:`, error);
          
          // 添加空結果
          results.push({
            packageName: pkg.packageKey || `${pkg.name}@${pkg.version}`,
            vulnerabilities: [],
            queryTime: 0,
            cacheHit: false,
            strategy: 'error'
          });
          
          completed++;
          
          if (completed === batch.length) {
            observer.next(results);
            observer.complete();
          }
        }
      });
    });
  }

  /**
   * 選擇最佳索引策略
   */
  private selectOptimalStrategy(query: PackageVulnerabilityQuery, ecosystem: string): IndexStrategy {
    // 根據生態系統和查詢類型選擇最佳策略
    const availableStrategies = this.indexStrategies
      .filter(strategy => strategy.canHandle(query))
      .sort((a, b) => b.priority - a.priority);
    
    if (availableStrategies.length === 0) {
      return this.indexStrategies[0]; // 預設策略
    }
    
    // 根據生態系統調整優先級
    if (ecosystem === 'npm' && query.packageName.startsWith('@')) {
      // 有作用域的 npm 套件優先使用精確匹配
      return availableStrategies.find(s => s.name === 'exact_indexed') || availableStrategies[0];
    }
    
    return availableStrategies[0];
  }

  /**
   * 創建最佳化批次
   */
  private createOptimalBatches(packages: PackageInfo[]): PackageInfo[][] {
    const batches: PackageInfo[][] = [];
    
    for (let i = 0; i < packages.length; i += this.optimalBatchSize) {
      batches.push(packages.slice(i, i + this.optimalBatchSize));
    }
    
    return batches;
  }

  /**
   * 初始化索引策略
   */
  private initializeIndexStrategies(): void {
    this.indexStrategies = [
      {
        name: 'exact_indexed',
        priority: 100,
        canHandle: (query) => query.searchType === 'exact',
        execute: (query) => this.databaseService.queryPackageVulnerabilities(query)
      },
      {
        name: 'optimized_fuzzy',
        priority: 80,
        canHandle: (query) => query.searchType === 'fuzzy',
        execute: (query) => this.executeOptimizedFuzzySearch(query)
      },
      {
        name: 'cpe_mapping',
        priority: 90,
        canHandle: (query) => query.searchType === 'cpe',
        execute: (query) => this.databaseService.queryPackageVulnerabilities(query)
      },
      {
        name: 'combined_search',
        priority: 70,
        canHandle: () => true, // 預設策略，總是可用
        execute: (query) => this.databaseService.queryPackageVulnerabilities({
          ...query,
          searchType: 'exact'
        })
      }
    ];
  }

  /**
   * 執行優化的模糊搜尋
   */
  private executeOptimizedFuzzySearch(query: PackageVulnerabilityQuery): Observable<VulnerabilityQueryResult[]> {
    // 使用 CVE 優化服務的智慧搜尋功能
    return this.databaseService.queryPackageVulnerabilities(query).pipe(
      map(results => {
        // 可以在這裡添加額外的模糊匹配邏輯
        return results;
      })
    );
  }

  /**
   * 轉換查詢結果為漏洞格式
   */
  private transformResults(results: VulnerabilityQueryResult[], version?: string): Vulnerability[] {
    return results.map(result => ({
      cveId: result.cveId,
      description: result.description,
      severity: result.severity,
      cvssScore: result.cvssScore,
      cvssVector: result.cvssVector,
      publishedDate: result.publishedDate,
      lastModifiedDate: result.lastModifiedDate,
      references: result.references,
      affectedVersions: result.affectedVersions,
      fixedVersion: result.fixedVersion
    }));
  }

  /**
   * 更新快取
   */
  private updateCache(packageName: string, version: string | undefined, vulnerabilities: Vulnerability[]): void {
    const cacheKey = this.generateCacheKey(packageName, version);
    
    // 如果快取已滿，清理最少使用的項目
    if (this.resultCache.size >= this.maxCacheSize) {
      this.cleanupCache();
    }
    
    this.resultCache.set(cacheKey, {
      result: vulnerabilities,
      timestamp: Date.now(),
      accessCount: 1
    });
  }

  /**
   * 產生快取鍵
   */
  private generateCacheKey(packageName: string, version?: string): string {
    return `${packageName}@${version || 'latest'}`;
  }

  /**
   * 清理快取
   */
  private cleanupCache(): void {
    const entries = Array.from(this.resultCache.entries());
    
    // 按使用頻率和時間排序，移除最少使用的 20%
    entries.sort((a, b) => {
      const scoreA = a[1].accessCount / (Date.now() - a[1].timestamp);
      const scoreB = b[1].accessCount / (Date.now() - b[1].timestamp);
      return scoreA - scoreB;
    });
    
    const removeCount = Math.floor(entries.length * 0.2);
    for (let i = 0; i < removeCount; i++) {
      this.resultCache.delete(entries[i][0]);
    }
    
    console.log(`[LocalScanOptimizer] 清理了 ${removeCount} 個快取項目`);
  }

  /**
   * 檢測套件生態系統
   */
  private detectEcosystem(packageName: string): string {
    if (packageName.startsWith('@')) {
      return 'npm';
    }
    
    if (packageName.includes('-') || packageName.includes('.js')) {
      return 'npm';
    }
    
    if (packageName.includes('_') || packageName.includes('-python')) {
      return 'pypi';
    }
    
    if (packageName.includes('::')) {
      return 'rubygems';
    }
    
    return 'npm'; // 預設
  }

  /**
   * 更新效能統計
   */
  private updateMetrics(results: BatchQueryResult[], totalTime: number): void {
    this.metrics.totalQueries += results.length;
    this.metrics.totalQueryTime += totalTime;
    this.metrics.averageQueryTime = this.metrics.totalQueryTime / this.metrics.totalQueries;
    this.metrics.batchOptimizations++;
    
    console.log(`[LocalScanOptimizer] 批次掃描完成，總時間: ${totalTime}ms，平均每個套件: ${(totalTime / results.length).toFixed(2)}ms`);
  }

  /**
   * 取得效能統計
   */
  public getOptimizationMetrics() {
    const cacheHitRate = this.metrics.totalQueries > 0 ? 
      (this.metrics.cacheHits / this.metrics.totalQueries * 100).toFixed(2) + '%' : '0%';
    
    return {
      ...this.metrics,
      cacheHitRate,
      cacheSize: this.resultCache.size,
      maxCacheSize: this.maxCacheSize,
      strategiesUsage: Object.fromEntries(this.metrics.indexStrategiesUsed),
      cveOptimizationMetrics: this.cveOptimization.getPerformanceMetrics()
    };
  }

  /**
   * 清理所有快取
   */
  public clearCaches(): void {
    this.resultCache.clear();
    this.cveOptimization.clearCaches();
    console.log('[LocalScanOptimizer] 已清理所有快取');
  }

  /**
   * 重置效能統計
   */
  public resetMetrics(): void {
    this.metrics = {
      totalQueries: 0,
      cacheHits: 0,
      cacheMisses: 0,
      averageQueryTime: 0,
      totalQueryTime: 0,
      indexStrategiesUsed: new Map<string, number>(),
      batchOptimizations: 0
    };
    this.cveOptimization.resetPerformanceMetrics();
  }

  /**
   * 預熱快取（載入常用套件）
   */
  public warmupCache(commonPackages: string[]): Observable<void> {
    console.log(`[LocalScanOptimizer] 開始預熱快取，載入 ${commonPackages.length} 個常用套件`);
    
    const packages: PackageInfo[] = commonPackages.map(name => ({
      name,
      version: 'latest',
      type: 'dependency'
    }));
    
    return this.optimizedBatchScan(packages).pipe(
      map(() => {
        console.log('[LocalScanOptimizer] 快取預熱完成');
      })
    );
  }
}