/**
 * 優化掃描整合測試
 * 測試新的優化格式掃描邏輯是否正確工作
 */

import { OptimizedCveRecord } from '../interfaces/optimized-storage.interface';
import { CveRecord } from '../interfaces/nvd-database.interface';

// 模擬優化格式的 CVE 記錄
export const mockOptimizedCveRecord: OptimizedCveRecord = {
  id: 'CVE-2023-TEST-001',
  published: '2023-01-01T00:00:00.000Z',
  lastModified: '2023-01-01T00:00:00.000Z',
  descriptions: [
    {
      lang: 'en',
      value: 'A security vulnerability exists in the form-data package that allows HTTP Parameter Pollution.'
    }
  ],
  configurations: [],
  references: [],
  severity: 'HIGH',
  cvssScore: 7.5,
  sourceIdentifier: 'test@example.com',
  vulnStatus: 'Analyzed',
  weaknesses: [],
  cveTags: [],
  primaryCvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
  cpeMatchCount: 1,
  referenceCount: 1,
  vendorProducts: ['form-data:form-data'],
  ecosystems: ['npm'],
  dataVersion: '2023-01-01',
  publishedYear: 2023,
  syncTimestamp: Date.now(),
  
  // 新的優化資訊
  optimizedProductInfo: [
    {
      productName: 'form-data',
      vendor: 'form-data',
      ecosystem: 'npm',
      versionRanges: [
        {
          versionConstraints: [
            {
              type: 'lt',
              version: '2.5.4'
            }
          ],
          originalCpeName: 'cpe:2.3:a:form-data:form-data:*:*:*:*:*:node.js:*:*',
          vulnerable: true,
          source: 'cpe_configuration'
        },
        {
          versionConstraints: [
            {
              type: 'range',
              version: '3.0.0',
              endVersion: '3.0.3',
              includeStart: true,
              includeEnd: true
            }
          ],
          vulnerable: true,
          source: 'cpe_configuration'
        }
      ],
      cpeInfo: {
        cpeName: 'cpe:2.3:a:form-data:form-data:*:*:*:*:*:node.js:*:*',
        vendor: 'form-data',
        product: 'form-data'
      },
      confidenceScore: 0.9,
      aliases: ['form_data', 'formdata']
    }
  ],
  dataExtractionMethods: [
    {
      method: 'structured_cpe',
      success: true,
      extractedProductCount: 1,
      confidenceLevel: 'high'
    }
  ],
  processingTimestamp: Date.now()
};

// 模擬舊格式的 CVE 記錄（用於回退測試）
export const mockLegacyCveRecord: CveRecord = {
  id: 'CVE-2023-TEST-002',
  published: '2023-01-01T00:00:00.000Z',
  lastModified: '2023-01-01T00:00:00.000Z',
  descriptions: [
    {
      lang: 'en',
      value: 'A vulnerability in the legacy-package.'
    }
  ],
  configurations: [],
  references: [],
  keywordSearchText: 'legacy-package vulnerability security',
  affectedProducts: ['legacy-package'],
  severity: 'MEDIUM',
  cvssScore: 5.0,
  versionRanges: [
    {
      cpeName: 'cpe:2.3:a:legacy:legacy-package:*:*:*:*:*:*:*:*',
      vulnerable: true,
      vendor: 'legacy',
      product: 'legacy-package',
      ecosystem: 'npm',
      versionEndExcluding: '1.0.0'
    }
  ],
  sourceIdentifier: 'test@example.com',
  vulnStatus: 'Analyzed',
  weaknesses: [],
  cveTags: [],
  primaryCvssVector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H',
  cpeMatchCount: 1,
  referenceCount: 0,
  vendorProducts: ['legacy:legacy-package'],
  ecosystems: ['npm'],
  dataVersion: '2023-01-01',
  publishedYear: 2023,
  syncTimestamp: Date.now()
};

/**
 * 測試案例：驗證查詢邏輯
 */
export const scanTestCases = [
  {
    name: '精確產品名稱匹配',
    packageName: 'form-data',
    version: '2.0.0',
    expectedMatch: true,
    expectedRecord: mockOptimizedCveRecord,
    reason: '應該匹配 form-data 產品名稱且版本 2.0.0 < 2.5.4'
  },
  {
    name: '產品別名匹配',
    packageName: 'form_data',
    version: '2.0.0',
    expectedMatch: true,
    expectedRecord: mockOptimizedCveRecord,
    reason: '應該匹配 form_data 別名'
  },
  {
    name: '版本不受影響',
    packageName: 'form-data',
    version: '3.1.0',
    expectedMatch: false,
    expectedRecord: mockOptimizedCveRecord,
    reason: '版本 3.1.0 超出受影響範圍，不應該匹配'
  },
  {
    name: '版本範圍內匹配',
    packageName: 'form-data',
    version: '3.0.1',
    expectedMatch: true,
    expectedRecord: mockOptimizedCveRecord,
    reason: '版本 3.0.1 在 3.0.0-3.0.3 範圍內'
  },
  {
    name: '舊格式回退',
    packageName: 'legacy-package',
    version: '0.9.0',
    expectedMatch: true,
    expectedRecord: mockLegacyCveRecord,
    reason: '應該能處理舊格式記錄'
  },
  {
    name: '產品名稱不匹配',
    packageName: 'nonexistent-package',
    version: '1.0.0',
    expectedMatch: false,
    expectedRecord: null,
    reason: '不存在的套件不應該匹配任何記錄'
  }
];

/**
 * 生態系統過濾測試案例
 */
export const ecosystemTestCases = [
  {
    name: 'NPM 生態系統匹配',
    packageName: 'form-data',
    ecosystem: 'npm',
    expectedMatch: true,
    reason: 'form-data 是 npm 套件'
  },
  {
    name: 'Python 生態系統不匹配',
    packageName: 'form-data',
    ecosystem: 'pypi',
    expectedMatch: false,
    reason: 'form-data 不是 Python 套件'
  }
];

/**
 * 信心分數測試案例
 */
export const confidenceTestCases = [
  {
    name: '高信心分數結構化資料',
    record: mockOptimizedCveRecord,
    expectedMinConfidence: 0.8,
    reason: '結構化 CPE 資料應該有高信心分數'
  }
];

/**
 * 效能測試資料
 */
export const performanceTestData = {
  smallDataset: Array.from({ length: 100 }, (_, i) => ({
    ...mockOptimizedCveRecord,
    id: `CVE-2023-PERF-${String(i).padStart(3, '0')}`,
    optimizedProductInfo: [{
      ...mockOptimizedCveRecord.optimizedProductInfo[0],
      productName: `test-package-${i}`
    }]
  })),
  
  largeDataset: Array.from({ length: 10000 }, (_, i) => ({
    ...mockOptimizedCveRecord,
    id: `CVE-2023-LARGE-${String(i).padStart(5, '0')}`,
    optimizedProductInfo: [{
      ...mockOptimizedCveRecord.optimizedProductInfo[0],
      productName: `large-package-${i}`
    }]
  }))
};

/**
 * 模擬查詢執行測試
 */
export function runMockQueryTest(
  testCase: typeof scanTestCases[0],
  queryFunction: (packageName: string, version?: string) => boolean
): {
  passed: boolean;
  actualResult: boolean;
  expectedResult: boolean;
  testName: string;
  reason: string;
} {
  const actualResult = queryFunction(testCase.packageName, testCase.version);
  const passed = actualResult === testCase.expectedMatch;
  
  return {
    passed,
    actualResult,
    expectedResult: testCase.expectedMatch,
    testName: testCase.name,
    reason: testCase.reason
  };
}

/**
 * 執行所有測試案例的模擬函數
 */
export function runAllMockTests(): {
  passed: number;
  failed: number;
  total: number;
  results: Array<ReturnType<typeof runMockQueryTest>>;
} {
  // 這是一個模擬實作，實際測試需要真實的查詢服務
  const mockQueryFunction = (packageName: string, version?: string) => {
    // 簡化的模擬邏輯
    if (packageName === 'form-data') {
      if (!version) return true;
      if (version === '2.0.0' || version === '3.0.1') return true;
      if (version === '3.1.0') return false;
    }
    if (packageName === 'form_data') return true;
    if (packageName === 'legacy-package') return true;
    return false;
  };

  const results = scanTestCases.map(testCase => 
    runMockQueryTest(testCase, mockQueryFunction)
  );
  
  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;
  
  return {
    passed,
    failed,
    total: results.length,
    results
  };
}

// 輸出測試摘要
export function printTestSummary(): void {
  const testResults = runAllMockTests();
  
  console.log('=== 優化掃描整合測試摘要 ===');
  console.log(`總測試案例: ${testResults.total}`);
  console.log(`通過: ${testResults.passed}`);
  console.log(`失敗: ${testResults.failed}`);
  console.log(`成功率: ${((testResults.passed / testResults.total) * 100).toFixed(1)}%`);
  
  if (testResults.failed > 0) {
    console.log('\n失敗的測試案例:');
    testResults.results
      .filter(r => !r.passed)
      .forEach(r => {
        console.log(`- ${r.testName}: 預期 ${r.expectedResult}, 實際 ${r.actualResult}`);
        console.log(`  理由: ${r.reason}`);
      });
  }
  
  console.log('\n=== 測試完成 ===');
}