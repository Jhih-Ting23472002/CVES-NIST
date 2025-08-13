import { Injectable } from '@angular/core';
import { Observable, BehaviorSubject } from 'rxjs';
import {
  CveRecord,
  CpeRecord,
  BatchProcessProgress,
  VersionRange
} from '../interfaces/nvd-database.interface';

@Injectable({
  providedIn: 'root'
})
export class NvdParserService {
  private readonly parseProgress$ = new BehaviorSubject<BatchProcessProgress | null>(null);
  private readonly BATCH_SIZE = 100; // 每批處理的記錄數
  private readonly PARSE_DELAY = 10; // 批次間延遲（ms）

  constructor() {}

  /**
   * 取得解析進度
   */
  getParseProgress(): Observable<BatchProcessProgress | null> {
    return this.parseProgress$.asObservable();
  }

  /**
   * 串流解析 NVD JSON 資料
   */
  parseNvdData(jsonData: any, dataVersion?: string): Observable<{
    type: 'cve' | 'cpe' | 'progress' | 'complete';
    data?: CveRecord[] | CpeRecord[];
    progress?: BatchProcessProgress;
  }> {
    return new Observable(observer => {
      const startTime = new Date();
      
      // 解析 CVE 資料 (NVD 2.0 格式)
      if (jsonData.vulnerabilities) {
        this.parseCveData(jsonData, startTime, observer, dataVersion);
      }
      // 解析 CPE 資料 (NVD 2.0 格式)
      else if (jsonData.products) {
        this.parseCpeData(jsonData, startTime, observer, dataVersion);
      }
      else {
        observer.error(new Error('無法識別的 NVD 2.0 資料格式'));
      }
    });
  }

  /**
   * 解析 CVE 資料（支援串流處理）
   */
  private parseCveData(
    jsonData: any,
    startTime: Date,
    observer: any,
    dataVersion?: string
  ): void {
    // NVD 2.0 格式
    const vulnerabilities = jsonData.vulnerabilities || [];
    const total = vulnerabilities.length;
    let processed = 0;
    let batchIndex = 0;

    const processBatch = () => {
      if (processed >= total) {
        observer.next({
          type: 'complete',
          progress: {
            type: 'parse',
            processed: total,
            total: total,
            percentage: 100,
            message: `CVE 解析完成 (${total} 筆記錄)`,
            startTime: startTime
          }
        });
        observer.complete();
        return;
      }

      const start = batchIndex * this.BATCH_SIZE;
      const end = Math.min(start + this.BATCH_SIZE, total);
      const batch = vulnerabilities.slice(start, end);
      
      const parsedRecords: CveRecord[] = [];

      for (const item of batch) {
        try {
          const cveRecord = this.transformCveItem(item, dataVersion);
          if (cveRecord) {
            parsedRecords.push(cveRecord);
          }
          processed++;
        } catch (error) {
          console.warn('解析 CVE 記錄時發生錯誤:', error);
          processed++;
        }
      }

      // 發送這批解析的資料
      observer.next({
        type: 'cve',
        data: parsedRecords
      });

      // 發送進度更新
      const progress: BatchProcessProgress = {
        type: 'parse',
        processed: processed,
        total: total,
        percentage: (processed / total) * 100,
        message: `正在解析 CVE 資料... (${processed}/${total})`,
        startTime: startTime,
        estimatedRemaining: this.calculateEstimatedTime(startTime, processed, total)
      };

      this.parseProgress$.next(progress);
      observer.next({
        type: 'progress',
        progress: progress
      });

      batchIndex++;
      
      // 延遲處理下一批以避免阻塞 UI
      setTimeout(processBatch, this.PARSE_DELAY);
    };

    processBatch();
  }

  /**
   * 解析 CPE 資料
   */
  private parseCpeData(
    jsonData: any,
    startTime: Date,
    observer: any,
    dataVersion?: string
  ): void {
    const products = jsonData.products || [];
    const total = products.length;
    let processed = 0;
    let batchIndex = 0;

    const processBatch = () => {
      if (processed >= total) {
        observer.next({
          type: 'complete',
          progress: {
            type: 'parse',
            processed: total,
            total: total,
            percentage: 100,
            message: `CPE 解析完成 (${total} 筆記錄)`,
            startTime: startTime
          }
        });
        observer.complete();
        return;
      }

      const start = batchIndex * this.BATCH_SIZE;
      const end = Math.min(start + this.BATCH_SIZE, total);
      const batch = products.slice(start, end);
      
      const parsedRecords: CpeRecord[] = [];

      for (const item of batch) {
        try {
          const cpeRecord = this.transformCpeItem(item, dataVersion);
          if (cpeRecord) {
            parsedRecords.push(cpeRecord);
          }
          processed++;
        } catch (error) {
          console.warn('解析 CPE 記錄時發生錯誤:', error);
          processed++;
        }
      }

      observer.next({
        type: 'cpe',
        data: parsedRecords
      });

      const progress: BatchProcessProgress = {
        type: 'parse',
        processed: processed,
        total: total,
        percentage: (processed / total) * 100,
        message: `正在解析 CPE 資料... (${processed}/${total})`,
        startTime: startTime,
        estimatedRemaining: this.calculateEstimatedTime(startTime, processed, total)
      };

      this.parseProgress$.next(progress);
      observer.next({
        type: 'progress',
        progress: progress
      });

      batchIndex++;
      setTimeout(processBatch, this.PARSE_DELAY);
    };

    processBatch();
  }

  /**
   * 轉換 CVE 項目為內部格式
   */
  private transformCveItem(item: any, dataVersion?: string): CveRecord | null {
    try {
      // NVD 2.0 格式：item.cve 包含所有 CVE 資料
      const cve = item.cve;
      
      if (!cve) {
        console.warn('CVE 項目缺少 cve 屬性:', item);
        return null;
      }
      
      // 檢查必要欄位 (NVD 2.0 格式)
      const cveId = cve.id;
      if (!cveId) {
        console.warn('CVE 項目缺少 ID 欄位:', cve);
        return null;
      }

      console.log(`處理 CVE: ${cveId}`);
      
      // 安全地提取各個欄位
      let descriptions: any[] = [];
      let metrics: any = undefined;
      let configurations: any[] = [];
      let versionRanges: any[] = [];
      let references: any[] = [];
      
      try {
        descriptions = this.extractDescriptions(cve);
      } catch (error) {
        console.warn(`提取描述失敗 for ${cveId}:`, error);
      }
      
      try {
        metrics = this.extractMetrics(cve);
      } catch (error) {
        console.warn(`提取指標失敗 for ${cveId}:`, error);
      }
      
      try {
        const configResult = this.extractConfigurations(cve);
        configurations = configResult.configurations;
        versionRanges = configResult.versionRanges;
      } catch (error) {
        console.warn(`提取設定失敗 for ${cveId}:`, error);
      }
      
      try {
        references = this.extractReferences(cve);
      } catch (error) {
        console.warn(`提取參考連結失敗 for ${cveId}:`, error);
      }
      
      // 計算嚴重程度和分數
      const { severity, cvssScore } = this.calculateSeverityAndScore(metrics);
      
      // 建構搜尋文本
      const keywordSearchText = this.buildKeywordSearchText(cveId, descriptions, versionRanges);
      
      // 提取受影響產品和優化欄位
      const affectedProducts = this.extractAffectedProducts(versionRanges);
      const vendorProducts = this.extractVendorProducts(versionRanges);
      const ecosystems = this.extractEcosystems(versionRanges);

      // 提取 NVD 2.0 特有欄位
      const sourceIdentifier = cve.sourceIdentifier;
      const vulnStatus = cve.vulnStatus;
      const weaknesses = this.extractWeaknesses(cve);
      const cveTags = Array.isArray(cve.cveTags) ? cve.cveTags : [];

      // 效能優化欄位
      const primaryCvssVector = this.extractPrimaryCvssVector(metrics);
      const cpeMatchCount = this.calculateCpeMatchCount(configurations);
      const referenceCount = references.length;

      // 取得發布日期（NVD 2.0 格式）
      let publishedDate = cve.published;
      if (!publishedDate) {
        console.warn(`CVE ${cveId} 缺少發布日期，使用當前日期`);
        publishedDate = new Date().toISOString();
      }

      return {
        id: cveId,
        published: publishedDate,
        lastModified: cve.lastModified || new Date().toISOString(),
        descriptions: descriptions,
        metrics: metrics,
        configurations: configurations,
        references: references,
        keywordSearchText: keywordSearchText,
        affectedProducts: affectedProducts,
        severity: severity,
        cvssScore: cvssScore,
        versionRanges: versionRanges,
        
        // NVD 2.0 特有欄位
        sourceIdentifier: sourceIdentifier,
        vulnStatus: vulnStatus,
        weaknesses: weaknesses,
        cveTags: cveTags,
        
        // 效能優化欄位
        primaryCvssVector: primaryCvssVector,
        cpeMatchCount: cpeMatchCount,
        referenceCount: referenceCount,
        vendorProducts: vendorProducts,
        ecosystems: ecosystems,
        
        // 版本管理欄位
        dataVersion: dataVersion || new Date().toISOString().split('T')[0],
        publishedYear: new Date(publishedDate).getFullYear(),
        syncTimestamp: Date.now()
      };
    } catch (error) {
      console.error('轉換 CVE 項目時發生錯誤:', error);
      console.error('問題項目:', JSON.stringify(item, null, 2));
      return null;
    }
  }

  /**
   * 轉換 CPE 項目為內部格式
   */
  private transformCpeItem(item: any, dataVersion?: string): CpeRecord | null {
    try {
      const cpe = item.cpe || item;
      
      if (!cpe.cpeName && !cpe.cpe23Uri) {
        return null;
      }

      const cpeName = cpe.cpeName || cpe.cpe23Uri;
      const cpeObj = this.parseCpeName(cpeName);
      
      // 映射套件名稱
      const mappedPackageNames = this.mapCpeToPackageNames(cpeObj);

      return {
        cpeName: cpeName,
        title: cpe.title?.title || cpe.title || '',
        deprecated: cpe.deprecated || false,
        lastModified: cpe.lastModified || new Date().toISOString(),
        vendor: cpeObj.vendor || '',
        product: cpeObj.product || '',
        version: cpeObj.version,
        update: cpeObj.update,
        edition: cpeObj.edition,
        language: cpeObj.language,
        mappedPackageNames: mappedPackageNames,
        // 版本管理欄位
        dataVersion: dataVersion || new Date().toISOString().split('T')[0],
        syncTimestamp: Date.now()
      };
    } catch (error) {
      console.error('轉換 CPE 項目時發生錯誤:', error);
      return null;
    }
  }

  /**
   * 提取描述 (NVD 2.0 格式)
   */
  private extractDescriptions(cve: any): any[] {
    const descriptions: any[] = [];
    
    // NVD 2.0 格式
    if (Array.isArray(cve.descriptions)) {
      descriptions.push(...cve.descriptions);
    }
    // 備用格式
    else if (cve.description && typeof cve.description === 'string') {
      descriptions.push({ lang: 'en', value: cve.description });
    }
    
    return descriptions;
  }

  /**
   * 提取指標 (NVD 2.0 格式)
   */
  private extractMetrics(cve: any): any {
    // NVD 2.0 格式
    if (cve.metrics) {
      return cve.metrics;
    }
    
    return undefined;
  }

  /**
   * 提取設定和版本範圍 (NVD 2.0 格式)
   */
  private extractConfigurations(cve: any): { configurations: any[], versionRanges: VersionRange[] } {
    const configurations: any[] = [];
    const versionRanges: VersionRange[] = [];
    
    // NVD 2.0 格式 - 直接在 cve.configurations 底下
    if (Array.isArray(cve.configurations)) {
      configurations.push(...cve.configurations);
    }

    // 提取版本範圍
    for (const config of configurations) {
      // NVD 2.0 格式：config 直接包含 nodes
      let nodes = config.nodes || [];
      
      // 如果 config 本身就是一個 node（2.0 格式的扁平結構）
      if (!nodes.length && config.cpeMatch) {
        nodes = [config];
      }
      
      for (const node of nodes) {
        // 處理 NVD 2.0 的 cpeMatch 結構
        const matches = node.cpeMatch || [];
        for (const match of matches) {
          // 僅保留 vulnerable = true 的 CPE 記錄
          if (match.vulnerable === true) {
            const cpeObj = this.parseCpeName(match.criteria || match.cpe23Uri);
            versionRanges.push({
              cpeName: match.criteria || match.cpe23Uri,
              vulnerable: true,
              vendor: cpeObj.vendor || '',
              product: cpeObj.product || '',
              ecosystem: this.detectEcosystem(cpeObj),
              versionStartIncluding: match.versionStartIncluding,
              versionStartExcluding: match.versionStartExcluding,
              versionEndIncluding: match.versionEndIncluding,
              versionEndExcluding: match.versionEndExcluding
            });
          }
        }
      }
    }
    
    return { configurations, versionRanges };
  }

  /**
   * 提取參考連結 (NVD 2.0 格式)
   */
  private extractReferences(cve: any): any[] {
    const references: any[] = [];
    
    // NVD 2.0 格式
    if (Array.isArray(cve.references)) {
      references.push(...cve.references);
    }
    
    return references;
  }

  /**
   * 計算嚴重程度和分數
   */
  private calculateSeverityAndScore(metrics: any): {
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
    cvssScore: number;
  } {
    let cvssScore = 0;
    let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' = 'NONE';

    if (metrics?.cvssMetricV31?.[0]) {
      const cvss = metrics.cvssMetricV31[0];
      cvssScore = cvss.cvssData.baseScore;
      severity = this.mapCvssSeverity(cvss.cvssData.baseSeverity);
    } else if (metrics?.cvssMetricV30?.[0]) {
      const cvss = metrics.cvssMetricV30[0];
      cvssScore = cvss.cvssData.baseScore;
      severity = this.mapCvssSeverity(cvss.cvssData.baseSeverity);
    } else if (metrics?.cvssMetricV2?.[0]) {
      const cvss = metrics.cvssMetricV2[0];
      cvssScore = cvss.cvssData.baseScore;
      severity = this.mapCvssV2Severity(cvssScore);
    }

    return { severity, cvssScore };
  }

  /**
   * 對應 CVSS v3 嚴重程度
   */
  private mapCvssSeverity(severity: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'CRITICAL';
      case 'HIGH': return 'HIGH';
      case 'MEDIUM': return 'MEDIUM';
      case 'LOW': return 'LOW';
      default: return 'NONE';
    }
  }

  /**
   * 對應 CVSS v2 分數到嚴重程度
   */
  private mapCvssV2Severity(score: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0) return 'LOW';
    return 'NONE';
  }

  /**
   * 建構關鍵字搜尋文本
   */
  private buildKeywordSearchText(
    cveId: string,
    descriptions: any[],
    versionRanges: VersionRange[]
  ): string {
    const parts: string[] = [cveId];
    
    // 加入描述文本
    for (const desc of descriptions) {
      if (desc.value) {
        parts.push(desc.value.toLowerCase());
      }
    }
    
    // 加入產品名稱
    for (const range of versionRanges) {
      if (range.cpeName) {
        const cpeObj = this.parseCpeName(range.cpeName);
        if (cpeObj.vendor) parts.push(cpeObj.vendor);
        if (cpeObj.product) parts.push(cpeObj.product);
      }
    }
    
    return parts.join(' ');
  }

  /**
   * 提取受影響產品
   */
  private extractAffectedProducts(versionRanges: VersionRange[]): string[] {
    const products = new Set<string>();
    
    for (const range of versionRanges) {
      if (range.cpeName) {
        const cpeObj = this.parseCpeName(range.cpeName);
        if (cpeObj.product) {
          products.add(cpeObj.product);
        }
        
        // 嘗試映射到常見套件名稱
        const mappedNames = this.mapCpeToPackageNames(cpeObj);
        mappedNames.forEach(name => products.add(name));
      }
    }
    
    return Array.from(products);
  }

  /**
   * 解析 CPE 名稱
   */
  private parseCpeName(cpeName: string): any {
    if (!cpeName) return {};
    
    // 支援 CPE 2.3 格式: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    const parts = cpeName.split(':');
    
    if (parts.length >= 5) {
      return {
        vendor: parts[3] === '*' ? undefined : parts[3],
        product: parts[4] === '*' ? undefined : parts[4],
        version: parts[5] === '*' ? undefined : parts[5],
        update: parts[6] === '*' ? undefined : parts[6],
        edition: parts[7] === '*' ? undefined : parts[7],
        language: parts[8] === '*' ? undefined : parts[8]
      };
    }
    
    return {};
  }

  /**
   * 檢測套件生態系統
   */
  private detectEcosystem(cpeObj: any): string {
    if (!cpeObj.vendor || !cpeObj.product) return 'unknown';
    
    const vendor = cpeObj.vendor.toLowerCase();
    const product = cpeObj.product.toLowerCase();
    
    // Node.js / npm 生態系統
    if (vendor === 'nodejs' || product.includes('node') || 
        product.endsWith('_project') || product.endsWith('-js')) {
      return 'npm';
    }
    
    // 其他已知生態系統
    if (vendor === 'python' || product.endsWith('-python')) return 'pypi';
    if (vendor === 'ruby' || product.endsWith('-ruby')) return 'rubygems';
    if (vendor === 'oracle' && product === 'mysql') return 'mysql';
    if (vendor === 'postgresql') return 'postgresql';
    
    return 'unknown';
  }

  /**
   * 映射 CPE 到套件名稱
   */
  private mapCpeToPackageNames(cpeObj: any): string[] {
    const names: string[] = [];
    
    if (cpeObj.product) {
      // 直接使用產品名稱
      names.push(cpeObj.product);
      
      // 處理常見的命名模式
      const product = cpeObj.product.toLowerCase();
      
      // 移除常見後綴
      const cleanProduct = product
        .replace(/_project$/, '')
        .replace(/[-_]js$/, '')
        .replace(/[-_]node$/, '')
        .replace(/[-_]npm$/, '');
      
      if (cleanProduct !== product) {
        names.push(cleanProduct);
      }
      
      // 處理常見變換
      if (product.includes('-')) {
        names.push(product.replace(/-/g, '_'));
        names.push(product.replace(/-/g, ''));
      }
      
      if (product.includes('_')) {
        names.push(product.replace(/_/g, '-'));
        names.push(product.replace(/_/g, ''));
      }
    }
    
    return [...new Set(names)]; // 去重
  }

  /**
   * 計算預估剩餘時間
   */
  private calculateEstimatedTime(startTime: Date, processed: number, total: number): number {
    if (processed === 0) return 0;
    
    const elapsed = Date.now() - startTime.getTime();
    const rate = processed / elapsed; // 每毫秒處理的記錄數
    const remaining = total - processed;
    
    return remaining / rate;
  }

  /**
   * 提取弱點分類（NVD 2.0）
   */
  private extractWeaknesses(cve: any): any[] {
    if (Array.isArray(cve.weaknesses)) {
      return cve.weaknesses;
    }
    return [];
  }

  /**
   * 提取廠商-產品組合
   */
  private extractVendorProducts(versionRanges: VersionRange[]): string[] {
    const vendorProducts = new Set<string>();
    
    for (const range of versionRanges) {
      if (range.vendor && range.product) {
        vendorProducts.add(`${range.vendor}:${range.product}`);
      }
    }
    
    return Array.from(vendorProducts);
  }

  /**
   * 提取生態系統列表
   */
  private extractEcosystems(versionRanges: VersionRange[]): string[] {
    const ecosystems = new Set<string>();
    
    for (const range of versionRanges) {
      if (range.ecosystem && range.ecosystem !== 'unknown') {
        ecosystems.add(range.ecosystem);
      }
    }
    
    return Array.from(ecosystems);
  }

  /**
   * 提取主要 CVSS 向量
   */
  private extractPrimaryCvssVector(metrics: any): string | undefined {
    // 優先順序：v3.1 > v3.0 > v2.0
    if (metrics?.cvssMetricV31?.[0]) {
      return metrics.cvssMetricV31[0].cvssData?.vectorString;
    }
    if (metrics?.cvssMetricV30?.[0]) {
      return metrics.cvssMetricV30[0].cvssData?.vectorString;
    }
    if (metrics?.cvssMetricV2?.[0]) {
      return metrics.cvssMetricV2[0].cvssData?.vectorString;
    }
    return undefined;
  }

  /**
   * 計算 CPE 匹配總數
   */
  private calculateCpeMatchCount(configurations: any[]): number {
    let totalCount = 0;
    
    for (const config of configurations) {
      const nodes = config.nodes || [];
      for (const node of nodes) {
        const matches = node.cpeMatch || [];
        totalCount += matches.length;
      }
    }
    
    return totalCount;
  }

  /**
   * 清除解析進度
   */
  clearProgress(): void {
    this.parseProgress$.next(null);
  }
}