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
      
      // 解析 CVE 資料
      if (jsonData.CVE_Items || jsonData.vulnerabilities) {
        this.parseCveData(jsonData, startTime, observer, dataVersion);
      }
      // 解析 CPE 資料  
      else if (jsonData.CPE_Items || jsonData.products) {
        this.parseCpeData(jsonData, startTime, observer, dataVersion);
      }
      else {
        observer.error(new Error('無法識別的 NVD 資料格式'));
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
    // 支援新舊兩種 API 格式
    const vulnerabilities = jsonData.vulnerabilities || jsonData.CVE_Items || [];
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
    const products = jsonData.products || jsonData.CPE_Items || [];
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
      // NVD 1.1 JSON Feed 格式：item 有 cve 屬性
      // NVD API 2.0 格式：item 直接是 cve 物件
      const cve = item.cve || item;
      
      // 檢查必要欄位
      let cveId: string;
      if (cve.id) {
        // API 2.0 格式
        cveId = cve.id;
      } else if (cve.CVE_data_meta?.ID) {
        // 1.1 Feed 格式
        cveId = cve.CVE_data_meta.ID;
      } else {
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
      
      // 提取受影響產品
      const affectedProducts = this.extractAffectedProducts(versionRanges);

      // 取得發布日期（支援不同格式）
      let publishedDate = cve.published || cve.publishedDate;
      if (!publishedDate) {
        console.warn(`CVE ${cveId} 缺少發布日期，使用當前日期`);
        publishedDate = new Date().toISOString();
      }

      return {
        id: cveId,
        published: publishedDate,
        lastModified: cve.lastModified || cve.lastModifiedDate || new Date().toISOString(),
        descriptions: descriptions,
        metrics: metrics,
        configurations: configurations,
        references: references,
        keywordSearchText: keywordSearchText,
        affectedProducts: affectedProducts,
        severity: severity,
        cvssScore: cvssScore,
        versionRanges: versionRanges,
        // 版本管理欄位
        dataVersion: dataVersion || new Date().toISOString().split('T')[0], // 預設使用當前日期
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
   * 提取描述
   */
  private extractDescriptions(cve: any): any[] {
    const descriptions: any[] = [];
    
    // API 2.0 格式
    if (Array.isArray(cve.descriptions)) {
      descriptions.push(...cve.descriptions);
    }
    // 1.1 Feed 格式
    else if (cve.description?.description_data && Array.isArray(cve.description.description_data)) {
      descriptions.push(...cve.description.description_data);
    }
    // 備用格式
    else if (cve.description && typeof cve.description === 'string') {
      descriptions.push({ lang: 'en', value: cve.description });
    }
    
    return descriptions;
  }

  /**
   * 提取指標
   */
  private extractMetrics(cve: any): any {
    // API 2.0 格式
    if (cve.metrics) {
      return cve.metrics;
    }
    // 1.1 Feed 格式
    else if (cve.impact) {
      const metrics: any = {};
      
      // CVSS v3.1
      if (cve.impact.baseMetricV3?.cvssV3) {
        metrics.cvssMetricV31 = [{ 
          cvssData: cve.impact.baseMetricV3.cvssV3,
          exploitabilityScore: cve.impact.baseMetricV3.exploitabilityScore,
          impactScore: cve.impact.baseMetricV3.impactScore
        }];
      }
      
      // CVSS v3.0
      if (cve.impact.baseMetricV30?.cvssV30) {
        metrics.cvssMetricV30 = [{ 
          cvssData: cve.impact.baseMetricV30.cvssV30,
          exploitabilityScore: cve.impact.baseMetricV30.exploitabilityScore,
          impactScore: cve.impact.baseMetricV30.impactScore
        }];
      }
      
      // CVSS v2
      if (cve.impact.baseMetricV2?.cvssV2) {
        metrics.cvssMetricV2 = [{ 
          cvssData: cve.impact.baseMetricV2.cvssV2,
          exploitabilityScore: cve.impact.baseMetricV2.exploitabilityScore,
          impactScore: cve.impact.baseMetricV2.impactScore
        }];
      }
      
      return Object.keys(metrics).length > 0 ? metrics : undefined;
    }
    
    return undefined;
  }

  /**
   * 提取設定和版本範圍
   */
  private extractConfigurations(cve: any): { configurations: any[], versionRanges: VersionRange[] } {
    const configurations: any[] = [];
    const versionRanges: VersionRange[] = [];
    
    // API 2.0 格式
    if (Array.isArray(cve.configurations)) {
      configurations.push(...cve.configurations);
    }
    // 1.1 Feed 格式 - problemtype 和 affects
    else if (cve.affects?.vendor?.vendor_data) {
      // 處理 1.1 格式的 affects 資料
      const nodes: any[] = [];
      
      for (const vendor of cve.affects.vendor.vendor_data) {
        for (const product of vendor.product.product_data || []) {
          for (const version of product.version.version_data || []) {
            // 轉換為類似 2.0 格式的結構
            const cpeMatch = {
              vulnerable: true,
              criteria: `cpe:2.3:a:${vendor.vendor_name}:${product.product_name}:${version.version_value}:*:*:*:*:*:*:*`,
              versionStartIncluding: version.version_affected === '>=' ? version.version_value : undefined,
              versionEndIncluding: version.version_affected === '<=' ? version.version_value : undefined
            };
            
            if (!nodes.length) {
              nodes.push({
                operator: 'OR',
                negate: false,
                cpeMatch: []
              });
            }
            
            nodes[0].cpeMatch.push(cpeMatch);
          }
        }
      }
      
      if (nodes.length > 0) {
        configurations.push({ nodes });
      }
    }

    // 提取版本範圍
    for (const config of configurations) {
      const nodes = config.nodes || [];
      for (const node of nodes) {
        const matches = node.cpeMatch || [];
        for (const match of matches) {
          if (match.vulnerable !== false) {
            versionRanges.push({
              cpeName: match.criteria || match.cpe23Uri,
              vulnerable: match.vulnerable !== false,
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
   * 提取參考連結
   */
  private extractReferences(cve: any): any[] {
    const references: any[] = [];
    
    // API 2.0 格式
    if (Array.isArray(cve.references)) {
      references.push(...cve.references);
    }
    // 1.1 Feed 格式
    else if (cve.references?.reference_data && Array.isArray(cve.references.reference_data)) {
      references.push(...cve.references.reference_data.map((ref: any) => ({
        url: ref.url,
        source: ref.source || ref.refsource,
        tags: Array.isArray(ref.tags) ? ref.tags : []
      })));
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
   * 清除解析進度
   */
  clearProgress(): void {
    this.parseProgress$.next(null);
  }
}