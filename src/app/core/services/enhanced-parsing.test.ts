/**
 * 增強描述解析測試
 * 測試新的正則表達式模式是否能正確提取套件名稱和版本資訊
 */

import { CveOptimizationService } from './cve-optimization.service';
import { DESCRIPTION_PARSING_PATTERNS } from '../config/optimization.config';

describe('Enhanced Description Parsing Tests', () => {
  let service: CveOptimizationService;

  beforeEach(() => {
    service = new CveOptimizationService();
  });

  describe('測試實際 CVE 描述解析', () => {
    
    it('應該正確解析 brace-expansion CVE-2025-5889', () => {
      const description = "A vulnerability was found in juliangruber brace-expansion up to 1.1.11/2.0.1/3.0.0/4.0.0. It has been rated as problematic. Affected by this issue is the function expand of the file index.js. The manipulation leads to inefficient regular expression complexity. The attack may be launched remotely. The complexity of an attack is rather high. The exploitation is known to be difficult. The exploit has been disclosed to the public and may be used. Upgrading to version 1.1.12, 2.0.2, 3.0.1 and 4.0.1 is able to address this issue. The name of the patch is a5b98a4f30d7813266b221435e1eaaf25a1b0ac5. It is recommended to upgrade the affected component.";
      
      console.log('=== 測試 brace-expansion CVE-2025-5889 ===');
      
      // 測試各種模式
      let foundPackages: string[] = [];
      let foundVersions: string[] = [];
      let foundFixVersions: string[] = [];
      
      for (const pattern of DESCRIPTION_PARSING_PATTERNS.vulnerabilityPatterns) {
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(description)) !== null) {
          console.log(`模式匹配: ${pattern.source}`);
          console.log(`匹配結果:`, match);
          
          if (match[1]) {
            const packageName = match[1].trim();
            if (packageName.includes('brace-expansion')) {
              foundPackages.push(packageName);
            }
          }
          
          if (match[2]) {
            const versionInfo = match[2].trim();
            foundVersions.push(versionInfo);
            console.log(`版本資訊: ${versionInfo}`);
          }
        }
      }
      
      // 測試修復版本模式
      for (const pattern of DESCRIPTION_PARSING_PATTERNS.fixVersionPatterns) {
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(description)) !== null) {
          console.log(`修復版本模式匹配: ${pattern.source}`);
          console.log(`修復版本結果:`, match);
          
          if (match[1]) {
            foundFixVersions.push(match[1]);
          }
        }
      }
      
      console.log('找到的套件:', foundPackages);
      console.log('找到的版本:', foundVersions);
      console.log('找到的修復版本:', foundFixVersions);
      
      // 驗證結果
      expect(foundPackages.some(pkg => pkg.includes('brace-expansion'))).toBe(true);
      expect(foundVersions.length).toBeGreaterThan(0);
      expect(foundFixVersions.length).toBeGreaterThan(0);
      
      // 應該找到修復版本 1.1.12, 2.0.2, 3.0.1 and 4.0.1
      const fixVersionText = foundFixVersions[0];
      expect(fixVersionText).toContain('1.1.12');
      expect(fixVersionText).toContain('2.0.2');
      expect(fixVersionText).toContain('3.0.1');
      expect(fixVersionText).toContain('4.0.1');
    });

    it('應該正確解析 http-proxy-middleware CVE-2025-32997', () => {
      const description = "In http-proxy-middleware before 2.0.9 and 3.x before 3.0.5, fixRequestBody proceeds even if bodyParser has failed.";
      
      console.log('=== 測試 http-proxy-middleware CVE-2025-32997 ===');
      
      let foundPackages: string[] = [];
      let foundVersions: string[] = [];
      
      for (const pattern of DESCRIPTION_PARSING_PATTERNS.vulnerabilityPatterns) {
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(description)) !== null) {
          console.log(`模式匹配: ${pattern.source}`);
          console.log(`匹配結果:`, match);
          
          if (match[1]) {
            const packageName = match[1].trim();
            if (packageName.includes('http-proxy-middleware')) {
              foundPackages.push(packageName);
            }
          }
          
          if (match[2]) {
            const versionInfo = match[2].trim();
            foundVersions.push(versionInfo);
            console.log(`版本資訊: ${versionInfo}`);
          }
        }
      }
      
      console.log('找到的套件:', foundPackages);
      console.log('找到的版本:', foundVersions);
      
      // 驗證結果
      expect(foundPackages.some(pkg => pkg.includes('http-proxy-middleware'))).toBe(true);
      expect(foundVersions.length).toBeGreaterThan(0);
      
      // 應該找到版本約束資訊
      const versionText = foundVersions[0];
      expect(versionText).toBeTruthy();
      expect(versionText.length).toBeGreaterThan(0);
    });

    it('應該正確解析複雜版本格式', () => {
      console.log('=== 測試複雜版本格式解析 ===');
      
      const testCases = [
        {
          text: "up to 1.1.11/2.0.1/3.0.0/4.0.0",
          expected: ['1.1.11', '2.0.1', '3.0.0', '4.0.0']
        },
        {
          text: "before 2.0.9 and 3.x before 3.0.5",
          expected: ['2.0.9', '3.0.5']
        },
        {
          text: "version 1.1.12, 2.0.2, 3.0.1 and 4.0.1",
          expected: ['1.1.12', '2.0.2', '3.0.1', '4.0.1']
        }
      ];
      
      for (const testCase of testCases) {
        console.log(`測試文字: ${testCase.text}`);
        
        for (const pattern of DESCRIPTION_PARSING_PATTERNS.versionConstraintPatterns) {
          pattern.lastIndex = 0;
          let match;
          while ((match = pattern.exec(testCase.text)) !== null) {
            console.log(`版本約束匹配: ${pattern.source}`);
            console.log(`匹配結果:`, match);
          }
        }
      }
    });
    
  });

  describe('測試版本範圍解析功能', () => {
    
    it('應該正確解析斜線分隔的版本', () => {
      // 使用反射來測試私有方法
      const parseVersionRangeFromText = (service as any).parseVersionRangeFromText.bind(service);
      
      const versionText = "1.1.11/2.0.1/3.0.0/4.0.0";
      const ranges = parseVersionRangeFromText(versionText);
      
      console.log('斜線版本解析結果:', ranges);
      
      expect(ranges.length).toBe(4);
      expect(ranges[0].versionConstraints[0].version).toBe('1.1.11');
      expect(ranges[1].versionConstraints[0].version).toBe('2.0.1');
      expect(ranges[2].versionConstraints[0].version).toBe('3.0.0');
      expect(ranges[3].versionConstraints[0].version).toBe('4.0.0');
    });

    it('應該正確解析修復版本資訊', () => {
      const parseVersionRangeFromText = (service as any).parseVersionRangeFromText.bind(service);
      
      const versionText = "up to 1.1.11, fixed: 1.1.12, 2.0.2, 3.0.1 and 4.0.1";
      const ranges = parseVersionRangeFromText(versionText);
      
      console.log('修復版本解析結果:', ranges);
      
      expect(ranges.length).toBeGreaterThan(1);
      
      // 應該有易受攻擊的版本和修復版本
      const vulnerableRanges = ranges.filter((r: any) => r.vulnerable === true);
      const fixedRanges = ranges.filter((r: any) => r.vulnerable === false);
      
      expect(vulnerableRanges.length).toBeGreaterThan(0);
      expect(fixedRanges.length).toBeGreaterThan(0);
    });

    it('應該正確解析 "before" 格式', () => {
      const parseVersionRangeFromText = (service as any).parseVersionRangeFromText.bind(service);
      
      const versionText = "2.0.9 and 3.x before 3.0.5";
      const ranges = parseVersionRangeFromText(versionText);
      
      console.log('Before 格式解析結果:', ranges);
      
      expect(ranges.length).toBeGreaterThan(0);
      expect(ranges[0].versionConstraints[0].type).toBe('lt');
      expect(ranges[0].versionConstraints[0].version).toBe('3.0.5');
    });

  });

  describe('測試套件名稱驗證', () => {
    
    it('應該正確識別有效的套件名稱', () => {
      const isValidPackageName = (service as any).isValidPackageName.bind(service);
      
      const validNames = [
        'brace-expansion',
        'http-proxy-middleware',
        '@angular/core',
        'lodash.merge',
        'form-data'
      ];
      
      const invalidNames = [
        'this',
        'that',
        'vulnerability',
        'allows',
        'version'
      ];
      
      for (const name of validNames) {
        expect(isValidPackageName(name)).toBe(true);
        console.log(`✅ ${name} - 有效`);
      }
      
      for (const name of invalidNames) {
        expect(isValidPackageName(name)).toBe(false);
        console.log(`❌ ${name} - 無效`);
      }
    });
    
  });

});

// 實用工具函數：用於測試和調試新的正則表達式
export function testDescriptionParsing(description: string, cveId: string = 'TEST') {
  console.log(`=== 測試 CVE ${cveId} 描述解析 ===`);
  console.log(`描述: ${description}`);
  console.log('');
  
  // 測試所有漏洞模式
  console.log('📋 測試漏洞模式:');
  for (let i = 0; i < DESCRIPTION_PARSING_PATTERNS.vulnerabilityPatterns.length; i++) {
    const pattern = DESCRIPTION_PARSING_PATTERNS.vulnerabilityPatterns[i];
    pattern.lastIndex = 0;
    
    let match;
    while ((match = pattern.exec(description)) !== null) {
      console.log(`  模式 ${i + 1}: ${pattern.source}`);
      console.log(`  匹配: ${match[0]}`);
      if (match[1]) console.log(`  套件: ${match[1]}`);
      if (match[2]) console.log(`  版本: ${match[2]}`);
      console.log('');
    }
  }
  
  // 測試版本約束模式
  console.log('📋 測試版本約束模式:');
  for (let i = 0; i < DESCRIPTION_PARSING_PATTERNS.versionConstraintPatterns.length; i++) {
    const pattern = DESCRIPTION_PARSING_PATTERNS.versionConstraintPatterns[i];
    pattern.lastIndex = 0;
    
    let match;
    while ((match = pattern.exec(description)) !== null) {
      console.log(`  版本約束 ${i + 1}: ${pattern.source}`);
      console.log(`  匹配: ${match[0]}`);
      console.log('');
    }
  }
  
  // 測試修復版本模式
  console.log('📋 測試修復版本模式:');
  for (let i = 0; i < DESCRIPTION_PARSING_PATTERNS.fixVersionPatterns.length; i++) {
    const pattern = DESCRIPTION_PARSING_PATTERNS.fixVersionPatterns[i];
    pattern.lastIndex = 0;
    
    let match;
    while ((match = pattern.exec(description)) !== null) {
      console.log(`  修復版本 ${i + 1}: ${pattern.source}`);
      console.log(`  匹配: ${match[0]}`);
      if (match[1]) console.log(`  版本: ${match[1]}`);
      console.log('');
    }
  }
}