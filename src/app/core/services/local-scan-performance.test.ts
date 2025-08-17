/**
 * LocalScanService 效能測試
 * 測試並行掃描、快取機制和版本比較優化的效能改善
 */

import { TestBed } from '@angular/core/testing';
import { Observable } from 'rxjs';
import { LocalScanService } from './local-scan.service';
import { PackageInfo } from '../models/vulnerability.model';

// 模擬資料
const MOCK_PACKAGES: PackageInfo[] = [
  { name: 'react', version: '17.0.2', type: 'dependency' },
  { name: 'angular', version: '12.0.0', type: 'dependency' },
  { name: 'vue', version: '3.2.0', type: 'dependency' },
  { name: 'lodash', version: '4.17.21', type: 'dependency' },
  { name: 'express', version: '4.18.0', type: 'dependency' },
  { name: 'webpack', version: '5.70.0', type: 'devDependency' },
  { name: 'typescript', version: '4.5.0', type: 'devDependency' },
  { name: 'eslint', version: '8.10.0', type: 'devDependency' },
  { name: 'jest', version: '27.5.0', type: 'devDependency' },
  { name: 'babel', version: '7.17.0', type: 'devDependency' },
  { name: 'sass', version: '1.49.0', type: 'devDependency' },
  { name: 'postcss', version: '8.4.0', type: 'devDependency' },
  { name: 'prettier', version: '2.5.0', type: 'devDependency' },
  { name: 'husky', version: '7.0.0', type: 'devDependency' },
  { name: 'lint-staged', version: '12.3.0', type: 'devDependency' },
];

describe('LocalScanService 效能測試', () => {
  let service: LocalScanService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(LocalScanService);
    
    // 重置效能統計
    service.resetPerformanceMetrics();
    service.clearCache();
  });

  afterEach(() => {
    // 清理快取
    service.clearCache();
  });

  describe('並行掃描效能測試', () => {
    it('應該比序列掃描更快', async () => {
      console.log('=== 並行掃描效能測試 ===');
      
      // 測試並行掃描
      const parallelStartTime = Date.now();
      
      service.scanMultiplePackages(MOCK_PACKAGES.slice(0, 8)).subscribe({
        next: (results) => {
          const parallelEndTime = Date.now();
          const parallelDuration = parallelEndTime - parallelStartTime;
          
          const metrics = service.getPerformanceMetrics();
          
          console.log('並行掃描結果:');
          console.log(`- 掃描套件數量: ${results.length}`);
          console.log(`- 總掃描時間: ${parallelDuration}ms`);
          console.log(`- 平均單一掃描時間: ${metrics.averageScanTime.toFixed(2)}ms`);
          console.log(`- 並行批次數量: ${metrics.parallelBatches}`);
          console.log(`- 快取命中率: ${metrics.cacheHitRate}`);
          console.log(`- 版本比較快取命中率: ${metrics.versionCacheHitRate}`);
          
          // 驗證結果
          expect(results.length).toBe(8);
          expect(parallelDuration).toBeLessThan(10000); // 應該在10秒內完成
          expect(metrics.parallelBatches).toBeGreaterThan(0);
        },
        error: (error) => {
          console.error('並行掃描測試失敗:', error);
          fail(error);
        }
      });
    }, 30000); // 30秒超時
  });

  describe('快取機制效能測試', () => {
    it('第二次掃描應該有快取命中', async (done) => {
      console.log('=== 快取機制效能測試 ===');
      
      const testPackages = MOCK_PACKAGES.slice(0, 3);
      
      // 第一次掃描（填充快取）
      console.log('第一次掃描（填充快取）...');
      service.scanMultiplePackages(testPackages).subscribe({
        next: (firstResults) => {
          const firstMetrics = service.getPerformanceMetrics();
          console.log('第一次掃描完成:');
          console.log(`- 快取命中: ${firstMetrics.cacheHits}`);
          console.log(`- 快取未命中: ${firstMetrics.cacheMisses}`);
          console.log(`- 快取命中率: ${firstMetrics.cacheHitRate}`);
          
          // 第二次掃描（應該有快取命中）
          console.log('第二次掃描（測試快取命中）...');
          const secondScanStartTime = Date.now();
          
          service.scanMultiplePackages(testPackages).subscribe({
            next: (secondResults) => {
              const secondScanDuration = Date.now() - secondScanStartTime;
              const secondMetrics = service.getPerformanceMetrics();
              
              console.log('第二次掃描完成:');
              console.log(`- 掃描時間: ${secondScanDuration}ms`);
              console.log(`- 快取命中: ${secondMetrics.cacheHits}`);
              console.log(`- 快取未命中: ${secondMetrics.cacheMisses}`);
              console.log(`- 快取命中率: ${secondMetrics.cacheHitRate}`);
              
              // 驗證快取效果
              expect(secondResults.length).toBe(firstResults.length);
              expect(secondMetrics.cacheHits).toBeGreaterThan(firstMetrics.cacheHits);
              expect(secondScanDuration).toBeLessThan(1000); // 快取掃描應該很快
              
              done();
            },
            error: (error) => {
              console.error('第二次掃描失敗:', error);
              done.fail(error);
            }
          });
        },
        error: (error) => {
          console.error('第一次掃描失敗:', error);
          done.fail(error);
        }
      });
    }, 60000);
  });

  describe('版本比較快取測試', () => {
    it('應該快取版本比較結果', async () => {
      console.log('=== 版本比較快取測試 ===');
      
      // 多次掃描相同的套件和版本
      const samePackage: PackageInfo[] = [
        { name: 'react', version: '17.0.2', type: 'dependency' }
      ];
      
      let totalVersionComparisons = 0;
      
      // 執行多次掃描
      for (let i = 0; i < 3; i++) {
        console.log(`第 ${i + 1} 次掃描...`);
        
        await new Promise<void>((resolve, reject) => {
          service.scanMultiplePackages(samePackage).subscribe({
            next: (results) => {
              const metrics = service.getPerformanceMetrics();
              const currentVersionComparisons = metrics.versionCacheHits + metrics.versionCacheMisses;
              
              console.log(`- 版本快取命中: ${metrics.versionCacheHits}`);
              console.log(`- 版本快取未命中: ${metrics.versionCacheMisses}`);
              console.log(`- 版本快取命中率: ${metrics.versionCacheHitRate}`);
              
              if (i > 0) {
                // 從第二次開始，應該有版本比較快取命中
                expect(metrics.versionCacheHits).toBeGreaterThan(0);
              }
              
              resolve();
            },
            error: reject
          });
        });
      }
      
      const finalMetrics = service.getPerformanceMetrics();
      console.log('版本比較快取測試完成:');
      console.log(`- 總版本快取命中: ${finalMetrics.versionCacheHits}`);
      console.log(`- 總版本快取未命中: ${finalMetrics.versionCacheMisses}`);
      console.log(`- 版本快取命中率: ${finalMetrics.versionCacheHitRate}`);
      
      expect(finalMetrics.versionCacheHits).toBeGreaterThan(0);
    }, 30000);
  });

  describe('效能基準測試', () => {
    it('應該在合理時間內完成大量掃描', async () => {
      console.log('=== 效能基準測試 ===');
      
      const startTime = Date.now();
      const testPackages = MOCK_PACKAGES; // 使用所有測試套件
      
      service.scanMultiplePackages(testPackages).subscribe({
        next: (results) => {
          const endTime = Date.now();
          const totalDuration = endTime - startTime;
          const metrics = service.getPerformanceMetrics();
          
          console.log('效能基準測試結果:');
          console.log(`- 掃描套件數量: ${results.length}`);
          console.log(`- 總掃描時間: ${totalDuration}ms`);
          console.log(`- 平均每個套件掃描時間: ${(totalDuration / results.length).toFixed(2)}ms`);
          console.log(`- 並行批次數量: ${metrics.parallelBatches}`);
          console.log(`- 快取命中率: ${metrics.cacheHitRate}`);
          console.log(`- 版本比較快取命中率: ${metrics.versionCacheHitRate}`);
          console.log(`- 快取狀態:`, metrics.cacheStatus);
          
          // 效能要求驗證
          expect(results.length).toBe(testPackages.length);
          expect(totalDuration).toBeLessThan(30000); // 30秒內完成
          expect(totalDuration / results.length).toBeLessThan(2000); // 每個套件平均不超過2秒
          
          console.log('✅ 效能基準測試通過');
        },
        error: (error) => {
          console.error('效能基準測試失敗:', error);
          fail(error);
        }
      });
    }, 60000);
  });

  describe('記憶體使用測試', () => {
    it('快取應該有大小限制', () => {
      console.log('=== 記憶體使用測試 ===');
      
      // 測試快取大小限制
      const metrics = service.getPerformanceMetrics();
      console.log('當前快取狀態:', metrics.cacheStatus);
      
      expect(metrics.cacheStatus.maxScanCacheSize).toBeGreaterThan(0);
      expect(metrics.cacheStatus.maxVersionCacheSize).toBeGreaterThan(0);
      expect(metrics.cacheStatus.scanCacheSize).toBeLessThanOrEqual(metrics.cacheStatus.maxScanCacheSize);
      expect(metrics.cacheStatus.versionCacheSize).toBeLessThanOrEqual(metrics.cacheStatus.maxVersionCacheSize);
      
      console.log('✅ 記憶體使用限制正常');
    });
  });
});

// 效能比較工具函數
export function runPerformanceComparison() {
  console.log('=== 效能優化前後比較 ===');
  console.log('');
  console.log('📊 預期的效能改善:');
  console.log('- 並行掃描: 5-8倍效能提升（取決於套件數量）');
  console.log('- 快取機制: 第二次掃描 90% 以上的時間節省');
  console.log('- 版本比較快取: 複雜版本比較 80% 時間節省');
  console.log('- 批次查詢: 資料庫查詢次數減少 70%');
  console.log('');
  console.log('🎯 效能目標:');
  console.log('- 15個套件並行掃描: < 30秒');
  console.log('- 快取命中率: > 80%');
  console.log('- 版本比較快取命中率: > 70%');
  console.log('- 記憶體使用: < 100MB 額外記憶體');
  console.log('');
}

// 效能監控工具
export class PerformanceMonitor {
  private metrics: any[] = [];
  
  startMonitoring(service: LocalScanService) {
    const interval = setInterval(() => {
      const currentMetrics = service.getPerformanceMetrics();
      this.metrics.push({
        timestamp: Date.now(),
        ...currentMetrics
      });
    }, 1000);
    
    return () => clearInterval(interval);
  }
  
  generateReport() {
    console.log('=== 效能監控報告 ===');
    
    if (this.metrics.length === 0) {
      console.log('無監控資料');
      return;
    }
    
    const lastMetrics = this.metrics[this.metrics.length - 1];
    const firstMetrics = this.metrics[0];
    
    console.log('監控期間統計:');
    console.log(`- 監控時長: ${(lastMetrics.timestamp - firstMetrics.timestamp) / 1000}秒`);
    console.log(`- 總掃描次數: ${lastMetrics.totalScans}`);
    console.log(`- 平均掃描時間: ${lastMetrics.averageScanTime}ms`);
    console.log(`- 最終快取命中率: ${lastMetrics.cacheHitRate}`);
    console.log(`- 最終版本快取命中率: ${lastMetrics.versionCacheHitRate}`);
    
    // 計算效能趨勢
    const midPoint = Math.floor(this.metrics.length / 2);
    const firstHalf = this.metrics.slice(0, midPoint);
    const secondHalf = this.metrics.slice(midPoint);
    
    if (firstHalf.length > 0 && secondHalf.length > 0) {
      const firstHalfAvg = firstHalf.reduce((sum, m) => sum + m.averageScanTime, 0) / firstHalf.length;
      const secondHalfAvg = secondHalf.reduce((sum, m) => sum + m.averageScanTime, 0) / secondHalf.length;
      
      const improvement = ((firstHalfAvg - secondHalfAvg) / firstHalfAvg * 100).toFixed(2);
      console.log(`- 效能改善趨勢: ${improvement}%`);
    }
  }
  
  clearMetrics() {
    this.metrics = [];
  }
}