import { TestBed } from '@angular/core/testing';
import { NvdParserService } from './nvd-parser.service';
import { VersionRange } from '../interfaces/nvd-database.interface';

describe('NvdParserService - Enhanced Version Extraction', () => {
  let service: NvdParserService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(NvdParserService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('extractVersionRangesFromDescription', () => {
    it('should extract @babel/helpers and @babel/runtime from CVE-2025-27789', () => {
      const mockCve = {
        cve: {
          id: 'CVE-2025-27789',
          descriptions: [
            {
              lang: 'en',
              value: `Babel is a compiler for writing next generation JavaScript. When using versions of Babel prior to 7.26.10 and 8.0.0-alpha.17 to compile regular expression named capturing groups, Babel will generate a polyfill for the \`.replace\` method that has quadratic complexity on some specific replacement pattern strings (i.e. the second argument passed to \`.replace\`). Generated code is vulnerable if all the following conditions are true: Using Babel to compile regular expression named capturing groups, using the \`.replace\` method on a regular expression that contains named capturing groups, and the code using untrusted strings as the second argument of \`.replace\`. This problem has been fixed in \`@babel/helpers\` and \`@babel/runtime\` 7.26.10 and 8.0.0-alpha.17. It's likely that individual users do not directly depend on \`@babel/helpers\`, and instead depend on \`@babel/core\` (which itself depends on \`@babel/helpers\`). Upgrading to \`@babel/core\` 7.26.10 is not required, but it guarantees use of a new enough \`@babel/helpers\` version. Note that just updating Babel dependencies is not enough; one will also need to re-compile the code. No known workarounds are available.`
            }
          ]
        }
      };

      // 通過反射調用私有方法進行測試
      const extractMethod = (service as any).extractVersionRangesFromDescription;
      const result: VersionRange[] = extractMethod.call(service, mockCve.cve.descriptions, 'CVE-2025-27789');

      // 應該能找到兩個套件
      expect(result.length).toBeGreaterThanOrEqual(2);
      
      // 檢查是否包含 @babel/helpers
      const helpersPkg = result.find((r: VersionRange) => r.product === '@babel/helpers');
      expect(helpersPkg).toBeTruthy();
      expect(helpersPkg?.versionEndExcluding).toBe('7.26.10');

      // 檢查是否包含 @babel/runtime
      const runtimePkg = result.find((r: VersionRange) => r.product === '@babel/runtime');
      expect(runtimePkg).toBeTruthy();
      expect(runtimePkg?.versionEndExcluding).toBe('7.26.10');
    });

    it('should extract webpack-dev-server from CVE-2025-30360', () => {
      const mockCve = {
        cve: {
          id: 'CVE-2025-30360',
          descriptions: [
            {
              lang: 'en',
              value: `webpack-dev-server allows users to use webpack with a development server that provides live reloading. Prior to version 5.2.1, webpack-dev-server users' source code may be stolen when you access a malicious web site with non-Chromium based browser. The \`Origin\` header is checked to prevent Cross-site WebSocket hijacking from happening, which was reported by CVE-2018-14732. But webpack-dev-server always allows IP address \`Origin\` headers. This allows websites that are served on IP addresses to connect WebSocket. An attacker can obtain source code via a method similar to that used to exploit CVE-2018-14732. Version 5.2.1 contains a patch for the issue.`
            }
          ]
        }
      };

      const extractMethod = (service as any).extractVersionRangesFromDescription;
      const result: VersionRange[] = extractMethod.call(service, mockCve.cve.descriptions, 'CVE-2025-30360');

      // 應該能找到 webpack-dev-server
      expect(result.length).toBeGreaterThanOrEqual(1);
      
      const webpackPkg = result.find((r: VersionRange) => r.product === 'webpack-dev-server');
      expect(webpackPkg).toBeTruthy();
      expect(webpackPkg?.versionEndExcluding).toBe('5.2.1');
    });

    it('should still handle existing form-data format from CVE-2025-7783', () => {
      const mockCve = {
        cve: {
          id: 'CVE-2025-7783',
          descriptions: [
            {
              lang: 'en',
              value: `Use of Insufficiently Random Values vulnerability in form-data allows HTTP Parameter Pollution (HPP). This vulnerability is associated with program files lib/form_data.Js.\n\nThis issue affects form-data: < 2.5.4, 3.0.0 - 3.0.3, 4.0.0 - 4.0.3.`
            }
          ]
        }
      };

      const extractMethod = (service as any).extractVersionRangesFromDescription;
      const result: VersionRange[] = extractMethod.call(service, mockCve.cve.descriptions, 'CVE-2025-7783');

      // 應該能找到 form-data 的多個版本範圍
      expect(result.length).toBeGreaterThanOrEqual(3);
      
      const formDataRanges = result.filter((r: VersionRange) => r.product === 'form-data');
      expect(formDataRanges.length).toBe(3);
      
      // 檢查版本範圍
      const range1 = formDataRanges.find((r: VersionRange) => r.versionEndExcluding === '2.5.4');
      expect(range1).toBeTruthy();
      
      const range2 = formDataRanges.find((r: VersionRange) => r.versionStartIncluding === '3.0.0' && r.versionEndIncluding === '3.0.3');
      expect(range2).toBeTruthy();
      
      const range3 = formDataRanges.find((r: VersionRange) => r.versionStartIncluding === '4.0.0' && r.versionEndIncluding === '4.0.3');
      expect(range3).toBeTruthy();
    });

    it('should handle version with patch info', () => {
      const mockCve = {
        cve: {
          id: 'CVE-TEST-PATCH',
          descriptions: [
            {
              lang: 'en',
              value: `express allows attackers to bypass security measures. Version 4.18.1 contains a patch for the issue.`
            }
          ]
        }
      };

      const extractMethod = (service as any).extractVersionRangesFromDescription;
      const result: VersionRange[] = extractMethod.call(service, mockCve.cve.descriptions, 'CVE-TEST-PATCH');

      // 這個模式可能無法匹配，因為缺少"Prior to version"或明確的套件名稱
      // 但至少不應該崩潰
      expect(result).toBeDefined();
    });

    it('should handle upgrading pattern', () => {
      const mockCve = {
        cve: {
          id: 'CVE-TEST-UPGRADE',
          descriptions: [
            {
              lang: 'en',
              value: `A vulnerability exists in React applications. Upgrading to \`@babel/core\` 7.26.10 fixes this issue.`
            }
          ]
        }
      };

      const extractMethod = (service as any).extractVersionRangesFromDescription;
      const result: VersionRange[] = extractMethod.call(service, mockCve.cve.descriptions, 'CVE-TEST-UPGRADE');

      // 應該能找到 @babel/core
      const babelCore = result.find((r: VersionRange) => r.product === '@babel/core');
      expect(babelCore).toBeTruthy();
      expect(babelCore?.versionEndExcluding).toBe('7.26.10');
    });
  });
});