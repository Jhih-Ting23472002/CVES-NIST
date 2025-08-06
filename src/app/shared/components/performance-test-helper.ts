import { Vulnerability } from '../../core/models/vulnerability.model';

/**
 * 用於測試虛擬滾動效能的輔助類別
 * 提供大量測試資料來驗證虛擬滾動的效能優勢
 */
export class PerformanceTestHelper {
  
  /**
   * 生成大量測試漏洞資料
   * @param packageCount 套件數量
   * @param vulnerabilitiesPerPackage 每個套件的漏洞數量
   * @returns 測試用的掃描結果
   */
  static generateLargeDataset(
    packageCount: number = 100, 
    vulnerabilitiesPerPackage: number = 10
  ): {packageName: string, vulnerabilities: Vulnerability[]}[] {
    const results: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];
    
    const severities: ('CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW')[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const packageNames = [
      'react', 'vue', 'angular', 'lodash', 'axios', 'express', 'moment', 'webpack',
      'typescript', 'babel', 'eslint', 'prettier', 'jest', 'mocha', 'chai',
      'node-fetch', 'fs-extra', 'commander', 'inquirer', 'chalk', 'ora',
      'yargs', 'minimist', 'glob', 'rimraf', 'mkdirp', 'path', 'url',
      'querystring', 'crypto-js', 'jsonwebtoken', 'bcrypt', 'cors', 'helmet',
      'morgan', 'compression', 'body-parser', 'cookie-parser', 'multer',
      'sharp', 'jimp', 'canvas', 'pdf2pic', 'd3', 'three', 'pixi.js',
      'socket.io', 'ws', 'mysql', 'mongodb', 'redis', 'postgresql'
    ];
    
    for (let i = 0; i < packageCount; i++) {
      const packageName = packageNames[i % packageNames.length] + 
                         (i >= packageNames.length ? `-v${Math.floor(i / packageNames.length)}` : '');
      
      const vulnerabilities: Vulnerability[] = [];
      
      for (let j = 0; j < vulnerabilitiesPerPackage; j++) {
        const severity = severities[Math.floor(Math.random() * severities.length)];
        const cveYear = 2020 + Math.floor(Math.random() * 4);
        const cveNumber = Math.floor(Math.random() * 99999);
        
        vulnerabilities.push({
          cveId: `CVE-${cveYear}-${cveNumber}`,
          description: `這是 ${packageName} 套件中的一個 ${severity.toLowerCase()} 等級安全漏洞。此漏洞可能會影響應用程式的安全性，建議盡快更新到安全版本。`,
          severity,
          cvssScore: this.getCvssScoreForSeverity(severity),
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
          publishedDate: `${cveYear}-${String(Math.floor(Math.random() * 12) + 1).padStart(2, '0')}-${String(Math.floor(Math.random() * 28) + 1).padStart(2, '0')}T12:00:00.000`,
          lastModifiedDate: `${cveYear + 1}-${String(Math.floor(Math.random() * 12) + 1).padStart(2, '0')}-${String(Math.floor(Math.random() * 28) + 1).padStart(2, '0')}T12:00:00.000`,
          references: [
            `https://github.com/${packageName.split('-')[0]}/security/advisories/GHSA-${this.generateRandomHash()}`,
            `https://nvd.nist.gov/vuln/detail/CVE-${cveYear}-${cveNumber}`
          ],
          affectedVersions: [`< ${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 10)}.0`],
          fixedVersion: `${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 10)}.0`
        });
      }
      
      results.push({
        packageName,
        vulnerabilities
      });
    }
    
    return results;
  }
  
  /**
   * 根據嚴重程度獲取適當的 CVSS 分數
   */
  private static getCvssScoreForSeverity(severity: string): number {
    switch (severity) {
      case 'CRITICAL':
        return 9.0 + Math.random() * 1.0; // 9.0 - 10.0
      case 'HIGH':
        return 7.0 + Math.random() * 2.0; // 7.0 - 9.0
      case 'MEDIUM':
        return 4.0 + Math.random() * 3.0; // 4.0 - 7.0
      case 'LOW':
        return 0.1 + Math.random() * 3.9; // 0.1 - 4.0
      default:
        return 5.0;
    }
  }
  
  /**
   * 生成隨機雜湊值用於 GitHub Advisory ID
   */
  private static generateRandomHash(): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 12; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }
  
  /**
   * 測量渲染時間
   * @param label 測量標籤
   * @param callback 要測量的函數
   */
  static measurePerformance<T>(label: string, callback: () => T): T {
    const start = performance.now();
    const result = callback();
    const end = performance.now();
    console.log(`🚀 [${label}] 執行時間: ${(end - start).toFixed(2)}ms`);
    return result;
  }
  
  /**
   * 記憶體使用情況監控
   */
  static logMemoryUsage(label: string): void {
    if ('memory' in performance) {
      const memory = (performance as any).memory;
      console.log(`💾 [${label}] 記憶體使用:`, {
        used: `${(memory.usedJSHeapSize / 1024 / 1024).toFixed(2)} MB`,
        total: `${(memory.totalJSHeapSize / 1024 / 1024).toFixed(2)} MB`,
        limit: `${(memory.jsHeapSizeLimit / 1024 / 1024).toFixed(2)} MB`
      });
    }
  }
  
  /**
   * 比較虛擬滾動前後的效能差異
   * @param dataSize 資料大小
   */
  static logVirtualScrollBenefits(dataSize: number): void {
    console.log(`🔥 虛擬滾動效能優勢 (資料大小: ${dataSize} 項目):`);
    console.log('📊 傳統渲染: 一次性渲染所有 DOM 元素，可能造成：');
    console.log('   - 初始載入時間較長');
    console.log('   - 大量 DOM 元素影響渲染效能');
    console.log('   - 記憶體使用量較高');
    console.log('   - 滾動時可能出現卡頓');
    console.log('');
    console.log('⚡ 虛擬滾動: 只渲染可視區域的元素，提供：');
    console.log('   - 快速的初始載入時間');
    console.log('   - 穩定的記憶體使用');
    console.log('   - 流暢的滾動體驗');
    console.log('   - 支援大量資料而不影響效能');
    console.log('');
    console.log(`✅ 預估效能提升: ${dataSize > 50 ? '顯著' : '中等'}`);
  }
}