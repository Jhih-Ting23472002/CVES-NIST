import { Injectable } from '@angular/core';
import * as CDX from '@cyclonedx/cyclonedx-library';
import { PackageInfo, Vulnerability } from '../models/vulnerability.model';
import { buildNpmPurl, base64ToHex } from '../../shared/utils/sbom-utils';

export interface SpdxOptions {
  scanTimestamp?: Date;
  includeVulnerabilities?: boolean;
}

/**
 * 產生 SPDX 2.3 SBOM（JSON 格式），欄位嚴格對齊官方 schema
 * （src/app/core/schemas/spdx-2.3-schema.json，additionalProperties: false）。
 *
 * SPDX 沒有官方的瀏覽器端產生函式庫，故手刻結構、以官方 schema 測試把關：
 * - 漏洞資訊以 SECURITY externalRef 附在受影響套件（SPDX 2.3 無 vulnerabilities 欄位）
 * - 授權必須是合法 SPDX 表達式，否則填 NOASSERTION（不推測、不捏造）
 * - VEX 狀態無法在 SPDX 2.3 表達，如需 VEX 請用 CycloneDX 匯出
 */
@Injectable({
  providedIn: 'root'
})
export class SpdxSbomService {

  generateSbomJson(
    packages: PackageInfo[],
    scanResults: { packageName: string, vulnerabilities: Vulnerability[] }[],
    options: SpdxOptions = {}
  ): string {
    const created = this.formatSpdxDate(options.scanTimestamp ?? new Date());
    const cvesByPackage = options.includeVulnerabilities
      ? this.groupCvesByPackage(packages, scanResults)
      : new Map<string, string[]>();

    const spdxPackages = packages.map((pkg, index) =>
      this.buildPackage(pkg, `SPDXRef-Package-${index + 1}`, cvesByPackage.get(this.packageKey(pkg)) ?? [])
    );

    const sbom = {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'cves-nist-scan-report',
      documentNamespace: `https://cve-scanner.local/spdx/${crypto.randomUUID()}`,
      creationInfo: {
        created,
        creators: ['Tool: cves-nist-1.0.0'],
        licenseListVersion: '3.21'
      },
      packages: [
        {
          SPDXID: 'SPDXRef-Package-root',
          name: 'scanned-project',
          downloadLocation: 'NOASSERTION',
          filesAnalyzed: false,
          copyrightText: 'NOASSERTION',
          licenseConcluded: 'NOASSERTION',
          licenseDeclared: 'NOASSERTION'
        },
        ...spdxPackages
      ],
      relationships: [
        {
          spdxElementId: 'SPDXRef-DOCUMENT',
          relatedSpdxElement: 'SPDXRef-Package-root',
          relationshipType: 'DESCRIBES'
        },
        ...packages.map((pkg, index) => pkg.type === 'devDependency'
          ? {
              spdxElementId: `SPDXRef-Package-${index + 1}`,
              relatedSpdxElement: 'SPDXRef-Package-root',
              relationshipType: 'DEV_DEPENDENCY_OF'
            }
          : {
              spdxElementId: 'SPDXRef-Package-root',
              relatedSpdxElement: `SPDXRef-Package-${index + 1}`,
              relationshipType: 'DEPENDS_ON'
            })
      ]
    };

    return JSON.stringify(sbom, null, 2);
  }

  private buildPackage(pkg: PackageInfo, spdxId: string, cveIds: string[]): any {
    const spdxPackage: any = {
      SPDXID: spdxId,
      name: pkg.name,
      versionInfo: pkg.version,
      downloadLocation: pkg.resolved || 'NOASSERTION',
      filesAnalyzed: false,
      copyrightText: 'NOASSERTION',
      supplier: 'NOASSERTION',
      homepage: `https://www.npmjs.com/package/${pkg.name}`,
      licenseConcluded: this.toSpdxLicense(pkg.licenseConcluded),
      licenseDeclared: this.toSpdxLicense(pkg.licenseDeclared || pkg.license),
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: buildNpmPurl(pkg.name, pkg.version).toString()
        },
        ...cveIds.map(cveId => ({
          referenceCategory: 'SECURITY',
          referenceType: 'advisory',
          referenceLocator: `https://nvd.nist.gov/vuln/detail/${cveId}`
        }))
      ]
    };

    if (pkg.description) {
      spdxPackage.description = pkg.description;
    }
    if (pkg.licenseSource) {
      spdxPackage.licenseComments = `License source: ${pkg.licenseSource}`;
    }
    if (pkg.integrity?.startsWith('sha512-')) {
      const hex = base64ToHex(pkg.integrity.slice('sha512-'.length));
      if (hex) {
        spdxPackage.checksums = [{ algorithm: 'SHA512', checksumValue: hex }];
      }
    }

    return spdxPackage;
  }

  /**
   * 授權必須是合法 SPDX ID 或表達式，否則 NOASSERTION（不捏造）
   */
  private toSpdxLicense(licenseStr?: string): string {
    if (!licenseStr) {
      return 'NOASSERTION';
    }
    const spdxId = CDX.SPDX.fixupSpdxId(licenseStr);
    if (spdxId) {
      return spdxId;
    }
    return this.isValidSpdxExpression(licenseStr) ? licenseStr : 'NOASSERTION';
  }

  // ponytail: 輕量表達式驗證（token 逐一比對 + 括號平衡），不驗完整文法；
  // 若需嚴格文法驗證，改用 spdx-expression-parse（需自訂 webpack 才能進瀏覽器）
  private isValidSpdxExpression(expr: string): boolean {
    let depth = 0;
    for (const ch of expr) {
      if (ch === '(') depth++;
      if (ch === ')' && --depth < 0) return false;
    }
    if (depth !== 0) return false;

    const tokens = expr.replace(/[()]/g, ' ').split(/\s+/).filter(Boolean);
    if (tokens.length === 0) return false;
    return tokens.every((token, i) => {
      if (token === 'AND' || token === 'OR' || token === 'WITH') {
        return i > 0 && i < tokens.length - 1; // 運算子不可在頭尾
      }
      return token.startsWith('LicenseRef-') ||
        CDX.SPDX.isSupportedSpdxId(this.stripPlus(token)) ||
        // WITH 後面的 exception id 無法用 license 清單驗證，放行由 token 格式把關
        (i > 0 && tokens[i - 1] === 'WITH' && /^[A-Za-z0-9.-]+$/.test(token));
    });
  }

  private stripPlus(token: string): string {
    return token.endsWith('+') ? token.slice(0, -1) : token;
  }

  private groupCvesByPackage(
    packages: PackageInfo[],
    scanResults: { packageName: string, vulnerabilities: Vulnerability[] }[]
  ): Map<string, string[]> {
    const map = new Map<string, string[]>();
    for (const result of scanResults) {
      const pkg = packages.find(p => p.name === result.packageName ||
        p.packageKey === result.packageName ||
        `${p.name}@${p.version}` === result.packageName);
      if (!pkg || result.vulnerabilities.length === 0) {
        continue;
      }
      const key = this.packageKey(pkg);
      const cves = map.get(key) ?? [];
      for (const vuln of result.vulnerabilities) {
        if (!cves.includes(vuln.cveId)) {
          cves.push(vuln.cveId);
        }
      }
      map.set(key, cves);
    }
    return map;
  }

  private packageKey(pkg: PackageInfo): string {
    return `${pkg.name}@${pkg.version}`;
  }

  /**
   * SPDX 時間格式為 YYYY-MM-DDThh:mm:ssZ（不含毫秒）
   */
  private formatSpdxDate(date: Date): string {
    return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
  }
}
