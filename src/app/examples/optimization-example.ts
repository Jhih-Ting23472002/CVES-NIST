/**
 * CVE 優化功能使用範例
 * 展示如何使用新的優化儲存格式功能
 */

import { CveRecord } from '../core/interfaces/nvd-database.interface';
import { OptimizedCveRecord } from '../core/interfaces/optimized-storage.interface';
import { CveOptimizationService } from '../core/services/cve-optimization.service';
import { DatabaseWorkerService } from '../core/services/database-worker.service';

/**
 * 範例 1: 基本的 CVE 記錄優化
 */
export function basicOptimizationExample(optimizationService: CveOptimizationService) {
  // 模擬一個包含結構化資料的 CVE 記錄
  const cveWithStructuredData: CveRecord = {
    id: 'CVE-2023-12345',
    published: '2023-01-01T00:00:00.000Z',
    lastModified: '2023-01-01T00:00:00.000Z',
    descriptions: [
      {
        lang: 'en',
        value: 'A security vulnerability exists in the form-data package that allows attackers to perform HTTP Parameter Pollution.'
      }
    ],
    configurations: [
      {
        nodes: [
          {
            operator: 'OR',
            negate: false,
            cpeMatch: [
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:form-data:form-data:*:*:*:*:*:node.js:*:*',
                matchCriteriaId: 'ABC123-DEF456',
                versionEndExcluding: '2.5.4'
              },
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:form-data:form-data:*:*:*:*:*:node.js:*:*',
                matchCriteriaId: 'GHI789-JKL012',
                versionStartIncluding: '3.0.0',
                versionEndIncluding: '3.0.3'
              }
            ]
          }
        ]
      }
    ],
    references: [
      {
        url: 'https://github.com/form-data/form-data/security/advisories/GHSA-test',
        source: 'github.com',
        tags: ['Vendor Advisory']
      }
    ],
    keywordSearchText: '',
    affectedProducts: [],
    severity: 'MEDIUM',
    cvssScore: 5.3,
    versionRanges: [],
    sourceIdentifier: 'security@example.com',
    vulnStatus: 'Analyzed',
    weaknesses: [
      {
        source: 'nvd@nist.gov',
        type: 'Primary',
        description: [
          {
            lang: 'en',
            value: 'CWE-444 Inconsistent Interpretation of HTTP Requests (\'HTTP Request Smuggling\')'
          }
        ]
      }
    ],
    cveTags: [],
    primaryCvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
    cpeMatchCount: 2,
    referenceCount: 1,
    vendorProducts: [],
    ecosystems: [],
    dataVersion: '2023-01-01',
    publishedYear: 2023,
    syncTimestamp: Date.now()
  };

  // 優化 CVE 記錄
  const optimized = optimizationService.optimizeCveRecord(cveWithStructuredData);
  
  console.log('優化結果:', {
    cveId: optimized.id,
    productCount: optimized.optimizedProductInfo.length,
    extractionMethods: optimized.dataExtractionMethods.map(m => m.method),
    products: optimized.optimizedProductInfo.map(p => ({
      name: p.productName,
      ecosystem: p.ecosystem,
      versionRanges: p.versionRanges.length,
      confidence: p.confidenceScore,
      source: p.cpeInfo ? 'CPE' : p.descriptionInfo ? 'Description' : 'Unknown'
    }))
  });

  return optimized;
}

/**
 * 範例 2: 描述解析回退機制
 */
export function descriptionFallbackExample(optimizationService: CveOptimizationService) {
  // 模擬一個 vulnStatus 為 "Awaiting Analysis" 的 CVE 記錄
  const cveWithDescriptionOnly: CveRecord = {
    id: 'CVE-2023-67890',
    published: '2023-02-15T00:00:00.000Z',
    lastModified: '2023-02-15T00:00:00.000Z',
    descriptions: [
      {
        lang: 'en',
        value: 'This issue affects form-data: < 2.5.4, 3.0.0 - 3.0.3, 4.0.0 - 4.0.3. Attackers can exploit this vulnerability to perform HTTP Parameter Pollution attacks.'
      }
    ],
    configurations: [], // 空的 configurations 觸發描述解析
    references: [],
    keywordSearchText: '',
    affectedProducts: [],
    severity: 'HIGH',
    cvssScore: 7.5,
    versionRanges: [],
    sourceIdentifier: 'security@example.com',
    vulnStatus: 'Awaiting Analysis', // 觸發描述回退機制
    weaknesses: [],
    cveTags: [],
    primaryCvssVector: undefined,
    cpeMatchCount: 0,
    referenceCount: 0,
    vendorProducts: [],
    ecosystems: [],
    dataVersion: '2023-02-15',
    publishedYear: 2023,
    syncTimestamp: Date.now()
  };

  // 優化 CVE 記錄（會使用描述解析）
  const optimized = optimizationService.optimizeCveRecord(cveWithDescriptionOnly);
  
  console.log('描述解析結果:', {
    cveId: optimized.id,
    extractionMethods: optimized.dataExtractionMethods,
    products: optimized.optimizedProductInfo.map(p => ({
      name: p.productName,
      ecosystem: p.ecosystem,
      versionRanges: p.versionRanges.length,
      confidence: p.confidenceScore,
      descriptionInfo: p.descriptionInfo ? {
        extractedProductName: p.descriptionInfo.extractedProductName,
        extractedVersionText: p.descriptionInfo.extractedVersionText,
        regexPattern: p.descriptionInfo.regexPattern
      } : null
    }))
  });

  return optimized;
}

/**
 * 範例 3: 批次優化處理
 */
export async function batchOptimizationExample(
  workerService: DatabaseWorkerService,
  cveRecords: CveRecord[]
) {
  console.log(`開始批次優化 ${cveRecords.length} 筆 CVE 記錄...`);

  // 監聽進度更新
  const progressSubscription = workerService.getProgress().subscribe(progress => {
    if (progress) {
      console.log(`優化進度: ${progress.phase} - ${progress.processed}/${progress.total} (${progress.percentage?.toFixed(1)}%)`);
    }
  });

  try {
    // 執行批次優化
    const result = await workerService.optimizeRecords({
      cveRecords,
      batchSize: 100
    }).toPromise();

    if (!result) {
      throw new Error('優化結果為空');
    }

    console.log('批次優化完成:', {
      totalOriginal: result.totalOriginal,
      totalOptimized: result.totalOptimized,
      optimizationRate: ((result.totalOptimized / result.totalOriginal) * 100).toFixed(1) + '%'
    });

    // 分析優化結果
    const productStats = analyzeOptimizedResults(result.optimizedRecords);
    console.log('產品統計:', productStats);

    return result;

  } finally {
    progressSubscription.unsubscribe();
  }
}

/**
 * 範例 4: 智慧優化和資料庫更新
 */
export async function smartOptimizationAndUpdateExample(
  workerService: DatabaseWorkerService,
  cveRecords: CveRecord[],
  currentVersion: string,
  newVersion: string
) {
  console.log(`開始智慧優化和更新: ${currentVersion} -> ${newVersion}`);

  const updateSubscription = workerService.smartOptimizeAndUpdate({
    cveRecords,
    currentVersion,
    newVersion,
    optimizationBatchSize: 100,
    storageBatchSize: 1000
  }).subscribe({
    next: (status) => {
      console.log(`${status.phase}: ${status.message}`);
      if (status.processed && status.total) {
        const percentage = ((status.processed / status.total) * 100).toFixed(1);
        console.log(`進度: ${status.processed}/${status.total} (${percentage}%)`);
      }
    },
    complete: () => {
      console.log('智慧優化和更新完成！');
    },
    error: (error) => {
      console.error('智慧優化和更新失敗:', error);
    }
  });

  return updateSubscription;
}

/**
 * 分析優化結果的統計資訊
 */
function analyzeOptimizedResults(optimizedRecords: OptimizedCveRecord[]) {
  const stats = {
    totalRecords: optimizedRecords.length,
    recordsWithProducts: 0,
    productsByEcosystem: {} as { [key: string]: number },
    averageConfidenceScore: 0,
    extractionMethodStats: {} as { [key: string]: number },
    versionRangeStats: {
      withVersionRanges: 0,
      withoutVersionRanges: 0,
      averageRangesPerProduct: 0
    }
  };

  let totalConfidence = 0;
  let totalProductCount = 0;
  let totalVersionRangeCount = 0;

  for (const record of optimizedRecords) {
    if (record.optimizedProductInfo.length > 0) {
      stats.recordsWithProducts++;
    }

    // 統計提取方法
    for (const method of record.dataExtractionMethods) {
      stats.extractionMethodStats[method.method] = (stats.extractionMethodStats[method.method] || 0) + 1;
    }

    // 統計產品和生態系統
    for (const product of record.optimizedProductInfo) {
      totalProductCount++;
      totalConfidence += product.confidenceScore;
      
      stats.productsByEcosystem[product.ecosystem] = (stats.productsByEcosystem[product.ecosystem] || 0) + 1;
      
      if (product.versionRanges.length > 0) {
        stats.versionRangeStats.withVersionRanges++;
        totalVersionRangeCount += product.versionRanges.length;
      } else {
        stats.versionRangeStats.withoutVersionRanges++;
      }
    }
  }

  stats.averageConfidenceScore = totalProductCount > 0 ? totalConfidence / totalProductCount : 0;
  stats.versionRangeStats.averageRangesPerProduct = totalProductCount > 0 ? totalVersionRangeCount / totalProductCount : 0;

  return stats;
}

/**
 * 範例 5: 信心分數分析
 */
export function confidenceScoreAnalysisExample(optimizedRecords: OptimizedCveRecord[]) {
  const confidenceDistribution = {
    high: 0,     // >= 0.8
    medium: 0,   // 0.5 - 0.8
    low: 0       // < 0.5
  };

  const methodConfidence = {
    structured_cpe: [],
    description_regex: [],
    fallback_analysis: []
  } as { [key: string]: number[] };

  for (const record of optimizedRecords) {
    for (const product of record.optimizedProductInfo) {
      // 分布統計
      if (product.confidenceScore >= 0.8) {
        confidenceDistribution.high++;
      } else if (product.confidenceScore >= 0.5) {
        confidenceDistribution.medium++;
      } else {
        confidenceDistribution.low++;
      }

      // 按提取方法分組
      const sourceMethod = product.cpeInfo ? 'structured_cpe' : 
                         product.descriptionInfo ? 'description_regex' : 
                         'fallback_analysis';
      
      if (methodConfidence[sourceMethod]) {
        methodConfidence[sourceMethod].push(product.confidenceScore);
      }
    }
  }

  // 計算平均信心分數
  const averageByMethod = {} as { [key: string]: number };
  for (const [method, scores] of Object.entries(methodConfidence)) {
    if (scores.length > 0) {
      averageByMethod[method] = scores.reduce((sum, score) => sum + score, 0) / scores.length;
    }
  }

  console.log('信心分數分析:', {
    distribution: confidenceDistribution,
    averageByMethod
  });

  return { confidenceDistribution, averageByMethod };
}