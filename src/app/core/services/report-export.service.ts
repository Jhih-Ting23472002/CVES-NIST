import { Injectable } from '@angular/core';
import { saveAs } from 'file-saver';
import { PackageInfo, Vulnerability } from '../models/vulnerability.model';
import {
  getUniqueTotalVulnerabilities,
  getUniqueSeverityBreakdown,
  getTotalAffectedCombinations
} from '../../shared/utils/vulnerability-count-utils';
import { VexAnalysisService } from './vex-analysis.service';
import { LicenseAnalysisService } from './license-analysis.service';
import { SbomValidatorService, ValidationResult } from './sbom-validator.service';

@Injectable({
  providedIn: 'root'
})
export class ReportExportService {

  constructor(
    private vexAnalysisService: VexAnalysisService,
    private licenseAnalysisService: LicenseAnalysisService,
    private sbomValidatorService: SbomValidatorService
  ) { }

  /**
   * 匯出 JSON 格式報告
   */
  exportAsJson(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date
  ): void {
    const report = {
      metadata: {
        scanDate: scanTimestamp ? scanTimestamp.toISOString() : new Date().toISOString(),
        exportDate: new Date().toISOString(),
        totalPackages: packages.length,
        totalVulnerabilities: this.getTotalVulnerabilities(scanResults),
        scanSummary: this.generateScanSummary(scanResults)
      },
      packages: packages,
      vulnerabilities: scanResults,
      summary: {
        severityBreakdown: this.getSeverityBreakdown(scanResults),
        riskAnalysis: this.generateRiskAnalysis(scanResults),
        recommendations: this.generateRecommendations(scanResults)
      }
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: 'application/json;charset=utf-8'
    });

    const fileName = `security-scan-report-${this.formatDate(new Date())}.json`;
    saveAs(blob, fileName);
  }

  /**
   * 匯出 CSV 格式報告
   */
  exportAsCsv(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date
  ): void {
    const csvData: string[] = [];

    // 添加掃描資訊標題
    if (scanTimestamp) {
      csvData.push(`掃描報告`);
      csvData.push(`掃描時間,${scanTimestamp.toLocaleString('zh-TW')}`);
      csvData.push(`匯出時間,${new Date().toLocaleString('zh-TW')}`);
      csvData.push(`總套件數,${packages.length}`);
      csvData.push(`總漏洞數,${this.getTotalVulnerabilities(scanResults)}`);
      csvData.push(''); // 空行分隔
    }

    // CSV 標題列
    csvData.push([
      '套件名稱',
      '套件版本',
      '套件類型',
      'CVE 編號',
      '嚴重程度',
      'CVSS 分數',
      '漏洞描述',
      '發布日期',
      '最後修改',
      '修復版本',
      '參考資料'
    ].join(','));

    // 資料列
    scanResults.forEach(result => {
      const packageInfo = packages.find(p => p.name === result.packageName);

      if (result.vulnerabilities.length === 0) {
        // 安全套件
        csvData.push([
          this.escapeCsvField(result.packageName),
          this.escapeCsvField(packageInfo?.version || ''),
          this.escapeCsvField(packageInfo?.type || ''),
          '',
          '安全',
          '0',
          '未發現已知漏洞',
          '',
          '',
          '',
          ''
        ].join(','));
      } else {
        // 有漏洞的套件
        result.vulnerabilities.forEach(vuln => {
          csvData.push([
            this.escapeCsvField(result.packageName),
            this.escapeCsvField(packageInfo?.version || ''),
            this.escapeCsvField(packageInfo?.type || ''),
            this.escapeCsvField(vuln.cveId),
            this.escapeCsvField(vuln.severity),
            vuln.cvssScore.toString(),
            this.escapeCsvField(vuln.description),
            this.escapeCsvField(vuln.publishedDate),
            this.escapeCsvField(vuln.lastModifiedDate),
            this.escapeCsvField(vuln.fixedVersion || ''),
            this.escapeCsvField(vuln.references.join('; '))
          ].join(','));
        });
      }
    });

    // 添加 UTF-8 BOM 以確保正確的編碼顯示
    const BOM = '\uFEFF';
    const csvContent = BOM + csvData.join('\n');
    
    const blob = new Blob([csvContent], {
      type: 'text/csv;charset=utf-8'
    });

    const fileName = `security-scan-report-${this.formatDate(new Date())}.csv`;
    saveAs(blob, fileName);
  }

  /**
   * 匯出 HTML 格式報告
   */
  exportAsHtml(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date
  ): void {
    const html = this.generateHtmlReport(packages, scanResults, scanTimestamp);

    const blob = new Blob([html], {
      type: 'text/html;charset=utf-8'
    });

    const fileName = `security-scan-report-${this.formatDate(new Date())}.html`;
    saveAs(blob, fileName);
  }

  /**
   * 匯出 CycloneDX SBOM 格式
   */
  exportAsCycloneDX(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = false
  ): void {
    const sbom = this.generateCycloneDXSbom(packages, scanResults, scanTimestamp, includeVulnerabilities);

    const blob = new Blob([JSON.stringify(sbom, null, 2)], {
      type: 'application/json;charset=utf-8'
    });

    const fileName = `sbom-cyclonedx-${this.formatDate(new Date())}.json`;
    saveAs(blob, fileName);
  }

  /**
   * 匯出 SPDX SBOM 格式
   */
  exportAsSpdx(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = false
  ): void {
    const sbom = this.generateSpdxSbom(packages, scanResults, scanTimestamp, includeVulnerabilities);

    const blob = new Blob([JSON.stringify(sbom, null, 2)], {
      type: 'application/json;charset=utf-8'
    });

    const fileName = `sbom-spdx-${this.formatDate(new Date())}.json`;
    saveAs(blob, fileName);
  }

  /**
   * 匯出 SBOM HTML 格式 (Trivy 風格)
   */
  exportAsSbomHtml(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = true
  ): void {
    const html = this.generateSbomHtmlReport(packages, scanResults, scanTimestamp, includeVulnerabilities);

    const blob = new Blob([html], {
      type: 'text/html;charset=utf-8'
    });

    const fileName = `sbom-report-${this.formatDate(new Date())}.html`;
    saveAs(blob, fileName);
  }

  /**
   * 產生 HTML 報告
   */
  private generateHtmlReport(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date
  ): string {
    const severityBreakdown = this.getSeverityBreakdown(scanResults);
    const totalVulns = this.getTotalVulnerabilities(scanResults);

    return `
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全掃描報告</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .critical { color: #d32f2f; }
        .high { color: #f57c00; }
        .medium { color: #e65100; }
        .low { color: #388e3c; }
        .safe { color: #1976d2; }

        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .section h2 {
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        .vulnerability {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            background: #fafafa;
        }
        .vulnerability h3 {
            margin-top: 0;
            color: #333;
        }
        .severity-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.8rem;
        }
        .severity-critical { background-color: #d32f2f; }
        .severity-high { background-color: #f57c00; }
        .severity-medium { background-color: #e65100; }
        .severity-low { background-color: #388e3c; }
        .package-safe {
            background: #e8f5e8;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        
        /* Trivy 風格表格 */
        .vulnerability-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            background: white;
            border: 2px solid #333;
        }
        
        .vulnerability-table th {
            background-color: #f8f9fa;
            border: 1px solid #333;
            padding: 10px 8px;
            text-align: center;
            font-weight: bold;
            font-size: 13px;
        }
        
        .vulnerability-table td {
            border: 1px solid #333;
            padding: 8px;
            vertical-align: top;
            font-size: 12px;
        }
        
        .vulnerability-table .library-cell {
            font-weight: bold;
            max-width: 150px;
            word-wrap: break-word;
        }
        
        .vulnerability-table .vulnerability-cell {
            max-width: 120px;
            word-wrap: break-word;
        }
        
        .vulnerability-table .severity-cell {
            text-align: center;
            font-weight: bold;
            width: 80px;
        }
        
        .vulnerability-table .version-cell {
            max-width: 100px;
            word-wrap: break-word;
            text-align: center;
        }
        
        .vulnerability-table .title-cell {
            max-width: 300px;
            word-wrap: break-word;
        }
        
        .vulnerability-table .title-cell a {
            color: #0066cc;
            text-decoration: none;
        }
        
        .vulnerability-table .title-cell a:hover {
            text-decoration: underline;
        }
        
        .trivy-summary {
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 15px;
            border-left: 4px solid #007acc;
            margin: 20px 0;
            font-size: 14px;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #666;
            border-top: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>安全掃描報告</h1>
        ${scanTimestamp ? `<p>掃描時間: ${scanTimestamp.toLocaleString('zh-TW')}</p>` : ''}
        <p>匯出時間: ${new Date().toLocaleString('zh-TW')}</p>
        <p>掃描了 ${packages.length} 個套件，發現 ${totalVulns} 個漏洞</p>
    </div>

    <div class="summary">
        ${severityBreakdown.critical > 0 ? `
        <div class="stat-card">
            <div class="stat-number critical">${severityBreakdown.critical}</div>
            <div>嚴重漏洞</div>
        </div>` : ''}
        ${severityBreakdown.high > 0 ? `
        <div class="stat-card">
            <div class="stat-number high">${severityBreakdown.high}</div>
            <div>高風險漏洞</div>
        </div>` : ''}
        ${severityBreakdown.medium > 0 ? `
        <div class="stat-card">
            <div class="stat-number medium">${severityBreakdown.medium}</div>
            <div>中風險漏洞</div>
        </div>` : ''}
        ${severityBreakdown.low > 0 ? `
        <div class="stat-card">
            <div class="stat-number low">${severityBreakdown.low}</div>
            <div>低風險漏洞</div>
        </div>` : ''}
        <div class="stat-card">
            <div class="stat-number safe">${severityBreakdown.safe}</div>
            <div>安全套件</div>
        </div>
    </div>

    <div class="section">
        <h2>套件掃描結果</h2>
        ${scanResults.map(result => {
          const packageInfo = packages.find(p => p.name === result.packageName);

          if (result.vulnerabilities.length === 0) {
            return `
            <div class="package-safe">
                <strong>${result.packageName}</strong> (${packageInfo?.version || 'unknown'})
                - <span style="color: #4caf50;">✓ 安全</span>
            </div>`;
          } else {
            return `
            <div class="vulnerability">
                <h3>${result.packageName} (${packageInfo?.version || 'unknown'})</h3>
                ${result.vulnerabilities.map(vuln => `
                <div style="margin-bottom: 15px;">
                    <h4>${vuln.cveId}
                        <span class="severity-badge severity-${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                        <span style="margin-left: 10px;">CVSS: ${vuln.cvssScore.toFixed(1)}</span>
                    </h4>
                    <p>${vuln.description}</p>
                    <p><strong>發佈日期:</strong> ${new Date(vuln.publishedDate).toLocaleDateString('zh-TW')}</p>
                    ${vuln.fixedVersion ? `<p><strong>修復版本:</strong> ${vuln.fixedVersion}</p>` : ''}
                </div>
                `).join('')}
            </div>`;
          }
        }).join('')}
    </div>

    <div class="section">
        <h2>安全建議</h2>
        ${this.generateRecommendations(scanResults).map(rec => `<p>• ${rec}</p>`).join('')}
    </div>

    <div class="footer">
        <p>本報告由 CVE 安全掃描工具產生</p>
        <p>基於 NIST 國家漏洞資料庫 (NVD) 資料</p>
    </div>
</body>
</html>`;
  }

  private getTotalVulnerabilities(scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]): number {
    return getUniqueTotalVulnerabilities(scanResults);
  }

  private getSeverityBreakdown(scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]): {
    critical: number;
    high: number;
    medium: number;
    low: number;
    safe: number;
  } {
    const uniqueBreakdown = getUniqueSeverityBreakdown(scanResults);
    const safeCount = scanResults.filter(r => r.vulnerabilities.length === 0).length;

    return {
      ...uniqueBreakdown,
      safe: safeCount
    };
  }

  private generateScanSummary(scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]): string {
    const totalPackages = scanResults.length;
    const vulnerablePackages = scanResults.filter(r => r.vulnerabilities.length > 0).length;
    const safePackages = totalPackages - vulnerablePackages;
    const uniqueCount = getUniqueTotalVulnerabilities(scanResults);
    const combinationCount = getTotalAffectedCombinations(scanResults);

    let summary = `掃描了 ${totalPackages} 個套件，其中 ${vulnerablePackages} 個套件存在漏洞，${safePackages} 個套件安全。`;
    if (combinationCount > uniqueCount) {
      summary += `共發現 ${uniqueCount} 個唯一漏洞，影響 ${combinationCount} 個套件-漏洞組合。`;
    }
    return summary;
  }

  private generateRiskAnalysis(scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]): string[] {
    const breakdown = this.getSeverityBreakdown(scanResults);
    const analysis: string[] = [];

    if (breakdown.critical > 0) {
      analysis.push(`發現 ${breakdown.critical} 個嚴重等級漏洞，需要立即處理`);
    }
    if (breakdown.high > 0) {
      analysis.push(`發現 ${breakdown.high} 個高風險漏洞，建議優先修復`);
    }
    if (breakdown.medium > 0 || breakdown.low > 0) {
      analysis.push(`發現 ${breakdown.medium + breakdown.low} 個中低風險漏洞，建議納入維護計畫`);
    }
    if (breakdown.safe > 0) {
      analysis.push(`${breakdown.safe} 個套件目前安全，請持續關注更新`);
    }

    return analysis;
  }

  private generateRecommendations(scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]): string[] {
    const breakdown = this.getSeverityBreakdown(scanResults);
    const recommendations: string[] = [];

    // NIST 框架建議
    recommendations.push('🏛️ NIST 網路安全框架建議:');
    recommendations.push('  • 識別(Identify): 建立完整的資產清單和風險評估');
    recommendations.push('  • 保護(Protect): 實施存取控制和安全配置管理');
    recommendations.push('  • 偵測(Detect): 部署持續監控和異常偵測');
    recommendations.push('  • 回應(Respond): 建立事件回應和溝通計畫');
    recommendations.push('  • 復原(Recover): 制定業務持續性和復原策略');

    if (breakdown.critical > 0) {
      recommendations.push('');
      recommendations.push('🚨 嚴重漏洞處理 (NIST SP 800-40 指引):');
      recommendations.push('  • 72小時內完成修復 (依據 CISA BOD 指令)');
      recommendations.push('  • 啟動 NIST SP 800-61 資安事件處理程序');
      recommendations.push('  • 實施 NIST RMF 風險管理框架評估');
      recommendations.push('  • 考慮暫時隔離受影響系統');
    }

    if (breakdown.high > 0) {
      recommendations.push('');
      recommendations.push('⚠️ 高風險漏洞管理:');
      recommendations.push('  • 15天內完成修復 (CISA 建議時程)');
      recommendations.push('  • 使用 CVSS 和 EPSS 評估修復優先順序');
      recommendations.push('  • 實施網路分段和存取控制作為暫時緩解');
    }
    return recommendations;
  }

  private escapeCsvField(field: string): string {
    if (!field) return '';
    
    // 檢查是否需要引號包裹
    if (field.includes(',') || field.includes('"') || field.includes('\n') || field.includes('\r')) {
      // 將引號轉義為雙引號，並用引號包裹整個欄位
      return `"${field.replace(/"/g, '""')}"`;
    }
    return field;
  }

  private formatDate(date: Date): string {
    return date.toISOString().split('T')[0];
  }

  /**
   * 產生 CycloneDX SBOM
   */
  private generateCycloneDXSbom(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = false
  ): any {
    const timestamp = scanTimestamp || new Date();
    
    const sbom: any = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      serialNumber: `urn:uuid:${this.generateUUID()}`,
      version: 1,
      metadata: {
        timestamp: timestamp.toISOString(),
        tools: [
          {
            vendor: 'CVE Scanner',
            name: 'cves-nist',
            version: '1.0.0'
          }
        ],
        component: {
          type: 'application',
          name: 'scanned-project',
          version: '1.0.0'
        }
      },
      components: packages.map(pkg => {
        const component: any = {
          type: 'library',
          'bom-ref': this.generatePackageRef(pkg),
          name: pkg.name,
          version: pkg.version,
          purl: `pkg:npm/${pkg.name}@${pkg.version}`,
          scope: this.mapPackageTypeToCycloneDXScope(pkg.type),
          supplier: {
            name: 'npm registry',
            url: ['https://www.npmjs.com']
          },
          externalReferences: [
            {
              type: 'website',
              url: `https://www.npmjs.com/package/${pkg.name}`
            },
            {
              type: 'distribution',
              url: pkg.resolved || `https://registry.npmjs.org/${pkg.name}/-/${pkg.name}-${pkg.version}.tgz`
            }
          ]
        };

        if (pkg.description) {
          component.description = pkg.description;
        }

        // 改善 license 處理
        if (pkg.license) {
          component.licenses = [
            {
              license: {
                id: pkg.license,
                name: pkg.license
              }
            }
          ];
        } else {
          // 常見套件的預設 license 推測
          const commonLicenses: Record<string, string> = {
            'lodash': 'MIT',
            'express': 'MIT',
            'axios': 'MIT',
            'react': 'MIT',
            'vue': 'MIT',
            'angular': 'MIT',
            'typescript': 'Apache-2.0',
            'jest': 'MIT',
            'crypto-js': 'MIT'
          };
          const inferredLicense = commonLicenses[pkg.name];
          if (inferredLicense) {
            component.licenses = [
              {
                license: {
                  id: inferredLicense,
                  name: `${inferredLicense} (inferred)`
                }
              }
            ];
          }
        }

        return component;
      })
    };

    if (includeVulnerabilities) {
      sbom.vulnerabilities = this.generateCycloneDXVulnerabilities(packages, scanResults);
    }

    return sbom;
  }

  /**
   * 產生 SPDX SBOM
   */
  private generateSpdxSbom(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = false
  ): any {
    const timestamp = scanTimestamp || new Date();
    const documentNamespace = `https://cve-scanner.local/spdx/${this.generateUUID()}`;
    
    const sbom: any = {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'CVE Scanner Report',
      documentNamespace: documentNamespace,
      creationInfo: {
        created: timestamp.toISOString(),
        creators: ['Tool: CVE Scanner'],
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
        ...packages.map((pkg, index) => {
          const packageSpdxId = `SPDXRef-Package-${index + 1}`;
          const npmUrl = `https://www.npmjs.com/package/${pkg.name}`;
          const repositoryUrl = pkg.resolved || `https://registry.npmjs.org/${pkg.name}/-/${pkg.name}-${pkg.version}.tgz`;
          
          const spdxPackage: any = {
            SPDXID: packageSpdxId,
            name: pkg.name,
            version: pkg.version,
            downloadLocation: repositoryUrl,
            filesAnalyzed: false,
            copyrightText: pkg.license ? `Copyright contributors to ${pkg.name}` : 'NOASSERTION',
            supplier: `Organization: npm registry (https://www.npmjs.com)`,
            originator: `Organization: ${pkg.name} contributors`,
            homepage: npmUrl,
            sourceInfo: `Downloaded from npm registry`,
            externalRefs: [
              {
                referenceCategory: 'PACKAGE_MANAGER',
                referenceType: 'purl',
                referenceLocator: `pkg:npm/${pkg.name}@${pkg.version}`
              },
              {
                referenceCategory: 'OTHER',
                referenceType: 'website',
                referenceLocator: npmUrl
              }
            ]
          };

          // 改善 license 處理
          if (pkg.license) {
            spdxPackage.licenseConcluded = pkg.license;
            spdxPackage.licenseDeclared = pkg.license;
          } else {
            // 常見套件的預設 license 假設
            const commonLicenses: Record<string, string> = {
              'lodash': 'MIT',
              'express': 'MIT',
              'axios': 'MIT',
              'react': 'MIT',
              'vue': 'MIT',
              'angular': 'MIT',
              'typescript': 'Apache-2.0',
              'jest': 'MIT'
            };
            const inferredLicense = commonLicenses[pkg.name] || 'NOASSERTION';
            spdxPackage.licenseConcluded = inferredLicense;
            spdxPackage.licenseDeclared = 'NOASSERTION';
            if (inferredLicense !== 'NOASSERTION') {
              spdxPackage.licenseComments = `License "${inferredLicense}" was inferred from known package metadata`;
            }
          }

          return spdxPackage;
        })
      ],
      relationships: [
        {
          spdxElementId: 'SPDXRef-DOCUMENT',
          relatedSpdxElement: 'SPDXRef-Package-root',
          relationshipType: 'DESCRIBES'
        },
        ...packages.map((_, index) => ({
          spdxElementId: 'SPDXRef-Package-root',
          relatedSpdxElement: `SPDXRef-Package-${index + 1}`,
          relationshipType: 'DEPENDS_ON'
        }))
      ]
    };

    if (includeVulnerabilities) {
      sbom.vulnerabilities = this.generateSpdxVulnerabilities(packages, scanResults);
    }

    return sbom;
  }

  /**
   * 產生 CycloneDX 漏洞資訊
   */
  private generateCycloneDXVulnerabilities(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]
  ): any[] {
    // 依 CVE ID 合併，避免重複條目
    const vulnMap = new Map<string, any>();

    scanResults.forEach(result => {
      const pkg = packages.find(p => p.name === result.packageName ||
        p.packageKey === result.packageName ||
        `${p.name}@${p.version}` === result.packageName);

      if (!pkg) return;

      result.vulnerabilities.forEach(vuln => {
        const existing = vulnMap.get(vuln.cveId);
        const affectEntry = {
          ref: this.generatePackageRef(pkg),
          versions: [
            {
              version: pkg.version,
              status: 'affected'
            }
          ]
        };

        if (existing) {
          // 同一 CVE 影響多個套件時，合併 affects 陣列
          const alreadyAffected = existing.affects.some(
            (a: any) => a.ref === affectEntry.ref
          );
          if (!alreadyAffected) {
            existing.affects.push(affectEntry);
          }
        } else {
          vulnMap.set(vuln.cveId, {
            id: vuln.cveId,
            source: {
              name: 'NVD',
              url: `https://nvd.nist.gov/vuln/detail/${vuln.cveId}`
            },
            description: vuln.description,
            published: vuln.publishedDate,
            updated: vuln.lastModifiedDate,
            ratings: [
              {
                source: {
                  name: 'CVSS',
                  url: 'https://www.first.org/cvss/'
                },
                score: vuln.cvssScore,
                severity: vuln.severity.toLowerCase(),
                method: 'CVSSv3',
                vector: vuln.cvssVector || ''
              }
            ],
            affects: [affectEntry],
            references: vuln.references.map(ref => ({
              id: ref,
              source: {
                url: ref
              }
            }))
          });
        }
      });
    });

    return Array.from(vulnMap.values());
  }

  /**
   * 產生 SPDX 漏洞資訊
   */
  private generateSpdxVulnerabilities(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]
  ): any[] {
    // 依 CVE ID 合併，避免重複條目
    const vulnMap = new Map<string, any>();

    scanResults.forEach(result => {
      const pkg = packages.find(p => p.name === result.packageName ||
        p.packageKey === result.packageName ||
        `${p.name}@${p.version}` === result.packageName);

      if (!pkg) return;

      result.vulnerabilities.forEach(vuln => {
        const existing = vulnMap.get(vuln.cveId);
        const affectEntry = {
          spdxElementId: this.findPackageSpdxId(packages, pkg),
          versionInfo: pkg.version
        };

        if (existing) {
          // 同一 CVE 影響多個套件時，合併 affects 陣列
          const alreadyAffected = existing.affects.some(
            (a: any) => a.spdxElementId === affectEntry.spdxElementId
          );
          if (!alreadyAffected) {
            existing.affects.push(affectEntry);
          }
        } else {
          vulnMap.set(vuln.cveId, {
            id: vuln.cveId,
            description: vuln.description,
            published: vuln.publishedDate,
            modified: vuln.lastModifiedDate,
            affects: [affectEntry],
            properties: [
              {
                name: 'cvss:3.0:score',
                value: vuln.cvssScore.toString()
              },
              {
                name: 'cvss:3.0:severity',
                value: vuln.severity
              }
            ],
            externalReferences: [
              {
                type: 'advisory',
                locator: `https://nvd.nist.gov/vuln/detail/${vuln.cveId}`
              },
              ...vuln.references.map(ref => ({
                type: 'other',
                locator: ref
              }))
            ]
          });
        }
      });
    });

    return Array.from(vulnMap.values());
  }

  /**
   * 產生套件參考識別符
   */
  private generatePackageRef(pkg: PackageInfo): string {
    return `pkg:npm/${pkg.name}@${pkg.version}`;
  }

  /**
   * 找到套件的 SPDX ID
   */
  private findPackageSpdxId(packages: PackageInfo[], targetPkg: PackageInfo): string {
    const index = packages.findIndex(p => p.name === targetPkg.name && p.version === targetPkg.version);
    return `SPDXRef-Package-${index + 1}`;
  }

  /**
   * 對應套件類型到 CycloneDX scope
   */
  private mapPackageTypeToCycloneDXScope(type: 'dependency' | 'devDependency' | 'transitive'): string {
    switch (type) {
      case 'dependency': return 'required';
      case 'devDependency': return 'optional';
      case 'transitive': return 'required';
      default: return 'required';
    }
  }

  /**
   * 產生 UUID
   */
  private generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c == 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  /**
   * 產生 SBOM HTML 報告 (Trivy 風格)
   */
  private generateSbomHtmlReport(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = true
  ): string {
    const totalVulns = this.getTotalVulnerabilities(scanResults);
    const severityBreakdown = this.getSeverityBreakdown(scanResults);
    
    // 生成 Trivy 風格的總覽
    const trivySummary = this.generateTrivySummary(severityBreakdown, totalVulns);
    
    // 生成漏洞表格
    const vulnerabilityTable = includeVulnerabilities ? 
      this.generateVulnerabilityTable(packages, scanResults) : '';

    return `
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SBOM 安全報告</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
        }
        
        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        /* Trivy 風格總覽 */
        .trivy-summary {
            font-family: 'Courier New', monospace;
            background: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            font-size: 16px;
            font-weight: bold;
            white-space: pre;
        }
        
        /* 漏洞表格 */
        .vulnerability-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            background: white;
            border: 2px solid #2c3e50;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .vulnerability-table th {
            background: linear-gradient(135deg, #34495e 0%, #2c3e50 100%);
            color: white;
            border: 1px solid #2c3e50;
            padding: 12px 8px;
            text-align: center;
            font-weight: bold;
            font-size: 14px;
        }
        
        .vulnerability-table td {
            border: 1px solid #bdc3c7;
            padding: 10px 8px;
            vertical-align: top;
            font-size: 12px;
        }
        
        .vulnerability-table tbody tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        
        .vulnerability-table tbody tr:hover {
            background-color: #e8f4fd;
        }
        
        .library-cell {
            font-weight: bold;
            max-width: 150px;
            word-wrap: break-word;
            color: #2c3e50;
        }
        
        .vulnerability-cell {
            max-width: 120px;
            word-wrap: break-word;
            font-weight: bold;
        }
        
        .severity-cell {
            text-align: center;
            font-weight: bold;
            width: 80px;
        }
        
        .severity-critical {
            background-color: #e74c3c;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .severity-high {
            background-color: #f39c12;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .severity-medium {
            background-color: #f1c40f;
            color: #2c3e50;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .severity-low {
            background-color: #27ae60;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .version-cell {
            max-width: 100px;
            word-wrap: break-word;
            text-align: center;
            font-family: 'Courier New', monospace;
        }
        
        .title-cell {
            max-width: 350px;
            word-wrap: break-word;
            line-height: 1.4;
        }
        
        .title-cell a {
            color: #3498db;
            text-decoration: none;
        }
        
        .title-cell a:hover {
            text-decoration: underline;
        }
        
        .description {
            margin-bottom: 8px;
            line-height: 1.3;
        }
        
        .cve-link {
            font-size: 11px;
            color: #7f8c8d;
        }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .section h2 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-top: 0;
        }
        
        .footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #7f8c8d;
            border-top: 1px solid #bdc3c7;
        }
        
        .no-vulnerabilities {
            text-align: center;
            padding: 40px;
            background: #d5f4e6;
            border-radius: 8px;
            color: #27ae60;
            font-size: 18px;
            font-weight: bold;
        }
        
        /* 套件清單表格樣式 */
        .package-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            border: 1px solid #bdc3c7;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .package-table th {
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
            font-size: 14px;
            border-bottom: 2px solid #2980b9;
        }
        
        .package-table td {
            padding: 10px 12px;
            border-bottom: 1px solid #ecf0f1;
            vertical-align: middle;
        }
        
        .package-table tbody tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        
        .package-table tbody tr:hover {
            background-color: #e3f2fd;
        }
        
        .package-name {
            font-weight: bold;
            color: #2c3e50;
            font-family: 'Courier New', monospace;
        }
        
        .package-version {
            font-family: 'Courier New', monospace;
            color: #7f8c8d;
            font-size: 13px;
        }
        
        .package-type-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .type-dependency {
            background-color: #3498db;
            color: white;
        }
        
        .type-devdependency {
            background-color: #f39c12;
            color: white;
        }
        
        .type-transitive {
            background-color: #95a5a6;
            color: white;
        }
        
        .vulnerability-status {
            text-align: center;
        }
        
        .status-safe {
            color: #27ae60;
            font-weight: bold;
        }
        
        .status-vulnerable {
            color: #e74c3c;
            font-weight: bold;
        }
        
        .vulnerability-count {
            background-color: #e74c3c;
            color: white;
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 11px;
            margin-left: 5px;
        }
        
        .package-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        
        .stat-item {
            text-align: center;
        }
        
        .stat-number {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .stat-label {
            font-size: 12px;
            color: #7f8c8d;
            margin-top: 4px;
        }
        
        .package-search {
            margin: 15px 0;
            padding: 15px;
            background: #ecf0f1;
            border-radius: 8px;
        }
        
        .search-input {
            width: 100%;
            padding: 10px;
            border: 1px solid #bdc3c7;
            border-radius: 4px;
            font-size: 14px;
            margin-bottom: 10px;
        }
        
        .filter-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 6px 12px;
            border: 1px solid #3498db;
            background: white;
            color: #3498db;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.3s ease;
        }
        
        .filter-btn.active,
        .filter-btn:hover {
            background: #3498db;
            color: white;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SBOM 安全掃描報告</h1>
        <div class="subtitle">軟體物料清單與漏洞分析</div>
        ${scanTimestamp ? `<p>掃描時間: ${scanTimestamp.toLocaleString('zh-TW')}</p>` : ''}
        <p>匯出時間: ${new Date().toLocaleString('zh-TW')}</p>
        <p>掃描了 ${packages.length} 個套件</p>
    </div>

    ${trivySummary}

    ${totalVulns > 0 ? `
    <div class="section">
        <h2>🔍 漏洞詳細清單</h2>
        ${vulnerabilityTable}
    </div>
    ` : `
    <div class="no-vulnerabilities">
        ✅ 恭喜！未發現任何已知安全漏洞
    </div>
    `}

    <div class="section">
        <h2>📦 套件清單</h2>
        <p>此報告包含以下 ${packages.length} 個套件的安全分析結果：</p>
        ${this.generatePackageTable(packages, scanResults)}
    </div>

    <div class="footer">
        <p>本報告由 CVE 安全掃描工具產生</p>
        <p>基於 NIST 國家漏洞資料庫 (NVD) 資料</p>
        <p>遵循 SBOM (Software Bill of Materials) 標準</p>
    </div>
</body>
</html>`;
  }

  /**
   * 產生 Trivy 風格的總覽
   */
  private generateTrivySummary(severityBreakdown: any, totalVulns: number): string {
    if (totalVulns === 0) {
      return `<div class="trivy-summary">Total: 0 (安全無漏洞)</div>`;
    }

    const parts = [];
    if (severityBreakdown.critical > 0) parts.push(`CRITICAL: ${severityBreakdown.critical}`);
    if (severityBreakdown.high > 0) parts.push(`HIGH: ${severityBreakdown.high}`);
    if (severityBreakdown.medium > 0) parts.push(`MEDIUM: ${severityBreakdown.medium}`);
    if (severityBreakdown.low > 0) parts.push(`LOW: ${severityBreakdown.low}`);

    return `<div class="trivy-summary">Total: ${totalVulns} (${parts.join(', ')})</div>`;
  }

  /**
   * 產生漏洞表格
   */
  private generateVulnerabilityTable(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]
  ): string {
    // 合併同一套件的結果，並對 CVE 去重
    const mergedResultsMap = new Map<string, {packageName: string, vulnerabilities: Vulnerability[]}>();
    for (const result of scanResults) {
      const existing = mergedResultsMap.get(result.packageName);
      if (existing) {
        existing.vulnerabilities.push(...result.vulnerabilities);
      } else {
        mergedResultsMap.set(result.packageName, {
          packageName: result.packageName,
          vulnerabilities: [...result.vulnerabilities]
        });
      }
    }

    const vulnerableResults = Array.from(mergedResultsMap.values())
      .map(result => ({
        ...result,
        // 依 cveId 去重，保留第一次出現的漏洞物件
        vulnerabilities: result.vulnerabilities.filter(
          (vuln, idx, arr) => arr.findIndex(v => v.cveId === vuln.cveId) === idx
        )
      }))
      .filter(result => result.vulnerabilities.length > 0);

    if (vulnerableResults.length === 0) {
      return '';
    }

    const tableRows = vulnerableResults.map(result => {
      const packageInfo = packages.find(p => p.name === result.packageName ||
        p.packageKey === result.packageName ||
        `${p.name}@${p.version}` === result.packageName);
      const rowSpan = result.vulnerabilities.length;

      return result.vulnerabilities.map((vuln, index) => {
        const isFirstRow = index === 0;

        return `
          <tr>
            ${isFirstRow ? `
              <td class="library-cell" rowspan="${rowSpan}">${result.packageName}</td>
            ` : ''}
            <td class="vulnerability-cell">${vuln.cveId}</td>
            <td class="severity-cell">
              <span class="severity-${vuln.severity.toLowerCase()}">${vuln.severity}</span>
            </td>
            ${isFirstRow ? `
              <td class="version-cell" rowspan="${rowSpan}">${packageInfo?.version || 'unknown'}</td>
            ` : ''}
            <td class="version-cell">${vuln.fixedVersion || '尚無修復版本'}</td>
            <td class="title-cell">
              <div class="description">${vuln.description.substring(0, 100)}${vuln.description.length > 100 ? '...' : ''}</div>
              <div class="cve-link">
                <a href="https://nvd.nist.gov/vuln/detail/${vuln.cveId}" target="_blank">
                  https://nvd.nist.gov/vuln/detail/${vuln.cveId}
                </a>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }).join('');

    return `
      <table class="vulnerability-table">
        <thead>
          <tr>
            <th>套件名稱<br>(Library)</th>
            <th>漏洞編號<br>(Vulnerability)</th>
            <th>嚴重程度<br>(Severity)</th>
            <th>已安裝版本<br>(Installed Version)</th>
            <th>修復版本<br>(Fixed Version)</th>
            <th>漏洞描述<br>(Title)</th>
          </tr>
        </thead>
        <tbody>
          ${tableRows}
        </tbody>
      </table>
    `;
  }

  /**
   * 取得套件類型標籤
   */
  private getPackageTypeLabel(type: 'dependency' | 'devDependency' | 'transitive'): string {
    switch (type) {
      case 'dependency': return '正式相依';
      case 'devDependency': return '開發相依';
      case 'transitive': return '間接相依';
      default: return '未知';
    }
  }

  /**
   * 產生套件表格
   */
  private generatePackageTable(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]
  ): string {
    // 計算統計資料
    const stats = this.calculatePackageStats(packages, scanResults);
    
    // 產生統計資訊區塊
    const statsBlock = this.generatePackageStats(stats);
    
    // 產生搜尋和篩選區塊
    const searchBlock = this.generatePackageSearchBlock();
    
    // 產生表格
    const tableContent = this.generatePackageTableContent(packages, scanResults);
    
    return `
      ${statsBlock}
      ${searchBlock}
      ${tableContent}
      ${this.generatePackageTableScript()}
    `;
  }

  /**
   * 計算套件統計資料
   */
  private calculatePackageStats(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]
  ): any {
    const dependencyCount = packages.filter(p => p.type === 'dependency').length;
    const devDependencyCount = packages.filter(p => p.type === 'devDependency').length;
    const transitiveCount = packages.filter(p => p.type === 'transitive').length;
    
    const vulnerablePackages = scanResults.filter(r => r.vulnerabilities.length > 0);
    const safePackages = packages.length - vulnerablePackages.length;
    
    return {
      total: packages.length,
      dependency: dependencyCount,
      devDependency: devDependencyCount,
      transitive: transitiveCount,
      vulnerable: vulnerablePackages.length,
      safe: safePackages
    };
  }

  /**
   * 產生套件統計資訊區塊
   */
  private generatePackageStats(stats: any): string {
    return `
      <div class="package-stats">
        <div class="stat-item">
          <div class="stat-number">${stats.total}</div>
          <div class="stat-label">總套件數</div>
        </div>
        <div class="stat-item">
          <div class="stat-number">${stats.dependency}</div>
          <div class="stat-label">正式相依</div>
        </div>
        <div class="stat-item">
          <div class="stat-number">${stats.devDependency}</div>
          <div class="stat-label">開發相依</div>
        </div>
        <div class="stat-item">
          <div class="stat-number">${stats.transitive}</div>
          <div class="stat-label">間接相依</div>
        </div>
        <div class="stat-item">
          <div class="stat-number" style="color: #e74c3c;">${stats.vulnerable}</div>
          <div class="stat-label">有漏洞</div>
        </div>
        <div class="stat-item">
          <div class="stat-number" style="color: #27ae60;">${stats.safe}</div>
          <div class="stat-label">安全</div>
        </div>
      </div>
    `;
  }

  /**
   * 產生搜尋和篩選區塊
   */
  private generatePackageSearchBlock(): string {
    return `
      <div class="package-search">
        <input type="text" class="search-input" id="packageSearch" placeholder="🔍 搜尋套件名稱...">
        <div class="filter-buttons">
          <button class="filter-btn active" onclick="filterPackages('all')">全部</button>
          <button class="filter-btn" onclick="filterPackages('dependency')">正式相依</button>
          <button class="filter-btn" onclick="filterPackages('devDependency')">開發相依</button>
          <button class="filter-btn" onclick="filterPackages('transitive')">間接相依</button>
          <button class="filter-btn" onclick="filterPackages('vulnerable')">有漏洞</button>
          <button class="filter-btn" onclick="filterPackages('safe')">安全</button>
        </div>
      </div>
    `;
  }

  /**
   * 產生套件表格內容
   */
  private generatePackageTableContent(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]
  ): string {
    const tableRows = packages.map((pkg, index) => {
      const scanResult = scanResults.find(r => 
        r.packageName === pkg.name || 
        r.packageName === pkg.packageKey || 
        r.packageName === `${pkg.name}@${pkg.version}`
      );
      
      const vulnerabilityCount = scanResult ? scanResult.vulnerabilities.length : 0;
      const isVulnerable = vulnerabilityCount > 0;
      
      return `
        <tr class="package-row" data-type="${pkg.type}" data-vulnerable="${isVulnerable}" data-name="${pkg.name.toLowerCase()}">
          <td class="package-name">${pkg.name}</td>
          <td class="package-version">${pkg.version}</td>
          <td>
            <span class="package-type-badge type-${pkg.type}">${this.getPackageTypeLabel(pkg.type)}</span>
          </td>
          <td class="vulnerability-status">
            ${isVulnerable ? 
              `<span class="status-vulnerable">有漏洞<span class="vulnerability-count">${vulnerabilityCount}</span></span>` :
              `<span class="status-safe">✓ 安全</span>`
            }
          </td>
          <td style="font-size: 12px; color: #7f8c8d;">
            ${pkg.description ? pkg.description.substring(0, 80) + (pkg.description.length > 80 ? '...' : '') : '無描述'}
          </td>
        </tr>
      `;
    }).join('');

    return `
      <table class="package-table" id="packageTable">
        <thead>
          <tr>
            <th style="width: 25%;">套件名稱</th>
            <th style="width: 10%;">版本</th>
            <th style="width: 12%;">類型</th>
            <th style="width: 13%;">安全狀態</th>
            <th style="width: 40%;">描述</th>
          </tr>
        </thead>
        <tbody>
          ${tableRows}
        </tbody>
      </table>
      <div id="packageCount" style="margin-top: 10px; color: #7f8c8d; font-size: 14px;"></div>
    `;
  }

  /**
   * 產生套件表格的 JavaScript 功能
   */
  private generatePackageTableScript(): string {
    return `
      <script>
        let currentFilter = 'all';
        let currentSearch = '';

        // 初始化
        document.addEventListener('DOMContentLoaded', function() {
          updatePackageCount();
          
          // 搜尋功能
          const searchInput = document.getElementById('packageSearch');
          if (searchInput) {
            searchInput.addEventListener('input', function(e) {
              currentSearch = e.target.value.toLowerCase();
              applyFilters();
            });
          }
        });

        // 篩選功能
        function filterPackages(type) {
          currentFilter = type;
          
          // 更新按鈕狀態
          document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.classList.remove('active');
          });
          event.target.classList.add('active');
          
          applyFilters();
        }

        // 應用篩選條件
        function applyFilters() {
          const rows = document.querySelectorAll('.package-row');
          let visibleCount = 0;
          
          rows.forEach(row => {
            let shouldShow = true;
            
            // 類型篩選
            if (currentFilter !== 'all') {
              if (currentFilter === 'vulnerable' && row.dataset.vulnerable !== 'true') {
                shouldShow = false;
              } else if (currentFilter === 'safe' && row.dataset.vulnerable === 'true') {
                shouldShow = false;
              } else if (currentFilter !== 'vulnerable' && currentFilter !== 'safe' && row.dataset.type !== currentFilter) {
                shouldShow = false;
              }
            }
            
            // 搜尋篩選
            if (currentSearch && !row.dataset.name.includes(currentSearch)) {
              shouldShow = false;
            }
            
            row.style.display = shouldShow ? '' : 'none';
            if (shouldShow) visibleCount++;
          });
          
          updatePackageCount(visibleCount);
        }

        // 更新套件計數
        function updatePackageCount(visible) {
          const countElement = document.getElementById('packageCount');
          if (countElement) {
            const total = document.querySelectorAll('.package-row').length;
            if (visible !== undefined) {
              countElement.textContent = \`顯示 \${visible} / \${total} 個套件\`;
            } else {
              countElement.textContent = \`共 \${total} 個套件\`;
            }
          }
        }
      </script>
    `;
  }

  /**
   * 匯出增強版 CycloneDX SBOM（包含 VEX 和改進的授權資訊）
   */
  exportEnhancedCycloneDX(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = true
  ): void {
    // 增強套件的授權資訊
    const enhancedPackages = this.licenseAnalysisService.enhancePackagesWithLicenseInfo(packages, 'package-lock');
    
    // 分析 VEX 狀態
    const analyzedResults = includeVulnerabilities ? 
      this.vexAnalysisService.analyzeVulnerabilities(scanResults, enhancedPackages) : 
      scanResults;

    // 產生 SBOM
    const sbom = this.generateEnhancedCycloneDXSbom(enhancedPackages, analyzedResults, scanTimestamp, includeVulnerabilities);
    
    // 驗證格式
    const validationResult = this.sbomValidatorService.validateCycloneDX(sbom);
    
    // 添加驗證資訊到 metadata
    sbom.metadata.validation = {
      isValid: validationResult.isValid,
      score: validationResult.score,
      summary: this.sbomValidatorService.getValidationSummary(validationResult),
      timestamp: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(sbom, null, 2)], {
      type: 'application/json;charset=utf-8'
    });

    const fileName = `enhanced-cyclonedx-${this.formatDate(new Date())}.json`;
    saveAs(blob, fileName);
  }

  /**
   * 匯出增強版 SPDX SBOM（包含改進的授權資訊）
   */
  exportEnhancedSpdx(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = true
  ): void {
    // 增強套件的授權資訊
    const enhancedPackages = this.licenseAnalysisService.enhancePackagesWithLicenseInfo(packages, 'package-lock');
    
    // 分析 VEX 狀態
    const analyzedResults = includeVulnerabilities ? 
      this.vexAnalysisService.analyzeVulnerabilities(scanResults, enhancedPackages) : 
      scanResults;

    // 產生 SBOM
    const sbom = this.generateEnhancedSpdxSbom(enhancedPackages, analyzedResults, scanTimestamp, includeVulnerabilities);
    
    // 驗證格式
    const validationResult = this.sbomValidatorService.validateSPDX(sbom);
    
    // 添加驗證資訊作為註解
    sbom.annotations = sbom.annotations || [];
    sbom.annotations.push({
      annotationType: 'REVIEW',
      annotator: 'Tool: SBOM Validator',
      annotationDate: new Date().toISOString(),
      annotationComment: `Validation: ${this.sbomValidatorService.getValidationSummary(validationResult)} (Score: ${validationResult.score}/100)`
    });

    const blob = new Blob([JSON.stringify(sbom, null, 2)], {
      type: 'application/json;charset=utf-8'
    });

    const fileName = `enhanced-spdx-${this.formatDate(new Date())}.json`;
    saveAs(blob, fileName);
  }

  /**
   * 產生增強版 CycloneDX SBOM
   */
  private generateEnhancedCycloneDXSbom(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = false
  ): any {
    const timestamp = scanTimestamp || new Date();
    
    const sbom: any = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      serialNumber: `urn:uuid:${this.generateUUID()}`,
      version: 1,
      metadata: {
        timestamp: timestamp.toISOString(),
        tools: [
          {
            vendor: 'CVE Scanner Enhanced',
            name: 'cves-nist',
            version: '1.1.0',
            capabilities: ['VEX Analysis', 'Enhanced License Detection', 'Format Validation']
          }
        ],
        component: {
          type: 'application',
          name: 'scanned-project',
          version: '1.0.0'
        },
        licenses: this.generateLicenseSummary(packages)
      },
      components: packages.map(pkg => {
        const component: any = {
          type: 'library',
          'bom-ref': this.generatePackageRef(pkg),
          name: pkg.name,
          version: pkg.version,
          purl: `pkg:npm/${pkg.name}@${pkg.version}`,
          scope: this.mapPackageTypeToCycloneDXScope(pkg.type),
          supplier: {
            name: 'npm registry',
            url: ['https://www.npmjs.com']
          },
          externalReferences: [
            {
              type: 'website',
              url: `https://www.npmjs.com/package/${pkg.name}`
            },
            {
              type: 'distribution',
              url: pkg.resolved || `https://registry.npmjs.org/${pkg.name}/-/${pkg.name}-${pkg.version}.tgz`
            }
          ]
        };

        if (pkg.description) {
          component.description = pkg.description;
        }

        // 增強的授權處理
        this.addEnhancedLicenseInfo(component, pkg);

        // 添加完整性資訊
        if (pkg.integrity) {
          component.hashes = [
            {
              alg: 'SHA-512',
              content: pkg.integrity.replace('sha512-', '')
            }
          ];
        }

        return component;
      })
    };

    if (includeVulnerabilities) {
      sbom.vulnerabilities = this.generateEnhancedCycloneDXVulnerabilities(packages, scanResults);
    }

    return sbom;
  }

  /**
   * 產生增強版 SPDX SBOM
   */
  private generateEnhancedSpdxSbom(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = false
  ): any {
    const timestamp = scanTimestamp || new Date();
    const documentNamespace = `https://cve-scanner.local/spdx/${this.generateUUID()}`;
    
    const sbom: any = {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'Enhanced CVE Scanner Report',
      documentNamespace: documentNamespace,
      creationInfo: {
        created: timestamp.toISOString(),
        creators: ['Tool: CVE Scanner Enhanced-1.1.0'],
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
        ...packages.map((pkg, index) => {
          const packageSpdxId = `SPDXRef-Package-${index + 1}`;
          const npmUrl = `https://www.npmjs.com/package/${pkg.name}`;
          const repositoryUrl = pkg.resolved || `https://registry.npmjs.org/${pkg.name}/-/${pkg.name}-${pkg.version}.tgz`;
          
          const spdxPackage: any = {
            SPDXID: packageSpdxId,
            name: pkg.name,
            version: pkg.version,
            downloadLocation: repositoryUrl,
            filesAnalyzed: false,
            copyrightText: pkg.licenseDeclared ? `Copyright contributors to ${pkg.name}` : 'NOASSERTION',
            supplier: `Organization: npm registry (https://www.npmjs.com)`,
            originator: `Organization: ${pkg.name} contributors`,
            homepage: npmUrl,
            sourceInfo: `Downloaded from npm registry`,
            externalRefs: [
              {
                referenceCategory: 'PACKAGE_MANAGER',
                referenceType: 'purl',
                referenceLocator: `pkg:npm/${pkg.name}@${pkg.version}`
              },
              {
                referenceCategory: 'OTHER',
                referenceType: 'website',
                referenceLocator: npmUrl
              }
            ]
          };

          // 增強的授權處理
          spdxPackage.licenseConcluded = pkg.licenseConcluded || 'NOASSERTION';
          spdxPackage.licenseDeclared = pkg.licenseDeclared || 'NOASSERTION';
          
          // 添加授權來源資訊
          if (pkg.licenseSource) {
            spdxPackage.licenseComments = `License source: ${pkg.licenseSource}`;
          }

          // 添加完整性檢查
          if (pkg.integrity) {
            spdxPackage.checksums = [
              {
                algorithm: 'SHA512',
                value: pkg.integrity.replace('sha512-', '')
              }
            ];
          }

          return spdxPackage;
        })
      ],
      relationships: [
        {
          spdxElementId: 'SPDXRef-DOCUMENT',
          relatedSpdxElement: 'SPDXRef-Package-root',
          relationshipType: 'DESCRIBES'
        },
        ...packages.map((_, index) => ({
          spdxElementId: 'SPDXRef-Package-root',
          relatedSpdxElement: `SPDXRef-Package-${index + 1}`,
          relationshipType: 'DEPENDS_ON'
        }))
      ]
    };

    if (includeVulnerabilities) {
      sbom.vulnerabilities = this.generateEnhancedSpdxVulnerabilities(packages, scanResults);
    }

    return sbom;
  }

  /**
   * 添加增強的授權資訊到 CycloneDX 元件
   */
  private addEnhancedLicenseInfo(component: any, pkg: PackageInfo): void {
    const licenses = [];

    if (pkg.licenseDeclared) {
      licenses.push({
        license: {
          id: pkg.licenseDeclared,
          name: pkg.licenseDeclared
        },
        expression: pkg.licenseDeclared
      });
    }

    if (pkg.licenseConcluded && pkg.licenseConcluded !== pkg.licenseDeclared) {
      licenses.push({
        license: {
          id: pkg.licenseConcluded,
          name: `${pkg.licenseConcluded} (concluded)`
        },
        expression: pkg.licenseConcluded
      });
    }

    // 如果沒有授權資訊，使用原有邏輯
    if (licenses.length === 0 && pkg.license) {
      licenses.push({
        license: {
          id: pkg.license,
          name: pkg.license
        },
        expression: pkg.license
      });
    }

    if (licenses.length > 0) {
      component.licenses = licenses;
    }

    // 添加授權來源資訊
    if (pkg.licenseSource) {
      component.properties = component.properties || [];
      component.properties.push({
        name: 'license:source',
        value: pkg.licenseSource
      });
    }
  }

  /**
   * 產生授權摘要
   */
  private generateLicenseSummary(packages: PackageInfo[]): any[] {
    const licenseStats = this.licenseAnalysisService.getLicenseStatistics(packages);
    const summary: any[] = [];

    Object.entries(licenseStats.licenseBreakdown).forEach(([license, count]) => {
      if (license !== 'Unknown' && count > 0) {
        summary.push({
          license: {
            id: license,
            name: license
          },
          usage: `${count} packages`
        });
      }
    });

    return summary;
  }

  /**
   * 產生增強版 CycloneDX 漏洞資訊（包含 VEX 狀態）
   */
  private generateEnhancedCycloneDXVulnerabilities(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]
  ): any[] {
    // 依 CVE ID 合併，避免重複條目
    const vulnMap = new Map<string, any>();

    scanResults.forEach(result => {
      const pkg = packages.find(p => p.name === result.packageName ||
        p.packageKey === result.packageName ||
        `${p.name}@${p.version}` === result.packageName);

      if (!pkg) return;

      result.vulnerabilities.forEach(vuln => {
        const existing = vulnMap.get(vuln.cveId);
        const affectEntry: any = {
          ref: this.generatePackageRef(pkg),
          versions: [
            {
              version: pkg.version,
              status: 'affected'
            }
          ]
        };

        // 將 VEX 分析放入 affectEntry，保留每個套件各自的狀態
        if (vuln.vexStatus) {
          affectEntry.analysis = {
            state: vuln.vexStatus,
            justification: vuln.vexJustification || undefined,
            response: vuln.vexStatus === 'fixed' ? ['will_not_fix'] : undefined,
            detail: vuln.vexJustification
          };
        }

        if (existing) {
          const alreadyAffected = existing.affects.some(
            (a: any) => a.ref === affectEntry.ref
          );
          if (!alreadyAffected) {
            existing.affects.push(affectEntry);
          }
        } else {
          const vulnerability: any = {
            id: vuln.cveId,
            source: {
              name: 'NVD',
              url: `https://nvd.nist.gov/vuln/detail/${vuln.cveId}`
            },
            description: vuln.description,
            published: vuln.publishedDate,
            updated: vuln.lastModifiedDate,
            ratings: [
              {
                source: {
                  name: 'CVSS',
                  url: 'https://www.first.org/cvss/'
                },
                score: vuln.cvssScore,
                severity: vuln.severity.toLowerCase(),
                method: 'CVSSv3',
                vector: vuln.cvssVector || ''
              }
            ],
            affects: [affectEntry],
            references: vuln.references.map(ref => ({
              id: ref,
              source: {
                url: ref
              }
            }))
          };

          vulnMap.set(vuln.cveId, vulnerability);
        }
      });
    });

    return Array.from(vulnMap.values());
  }

  /**
   * 產生增強版 SPDX 漏洞資訊（包含 VEX 狀態）
   */
  private generateEnhancedSpdxVulnerabilities(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]
  ): any[] {
    // 依 CVE ID 合併，避免重複條目
    const vulnMap = new Map<string, any>();

    scanResults.forEach(result => {
      const pkg = packages.find(p => p.name === result.packageName ||
        p.packageKey === result.packageName ||
        `${p.name}@${p.version}` === result.packageName);

      if (!pkg) return;

      result.vulnerabilities.forEach(vuln => {
        const existing = vulnMap.get(vuln.cveId);
        const spdxId = this.findPackageSpdxId(packages, pkg);
        const affectEntry = {
          spdxElementId: spdxId,
          versionInfo: pkg.version
        };

        if (existing) {
          const alreadyAffected = existing.affects.some(
            (a: any) => a.spdxElementId === affectEntry.spdxElementId
          );
          if (!alreadyAffected) {
            existing.affects.push(affectEntry);
            // 補上此套件的 per-package VEX 屬性
            if (vuln.vexStatus) {
              existing.properties.push({ name: `vex:status:${spdxId}`, value: vuln.vexStatus });
              if (vuln.vexJustification) {
                existing.properties.push({ name: `vex:justification:${spdxId}`, value: vuln.vexJustification });
              }
            }
          }
        } else {
          const vulnerability: any = {
            id: vuln.cveId,
            description: vuln.description,
            published: vuln.publishedDate,
            modified: vuln.lastModifiedDate,
            affects: [affectEntry],
            properties: [
              {
                name: 'cvss:3.0:score',
                value: vuln.cvssScore.toString()
              },
              {
                name: 'cvss:3.0:severity',
                value: vuln.severity
              }
            ],
            externalReferences: [
              {
                type: 'advisory',
                locator: `https://nvd.nist.gov/vuln/detail/${vuln.cveId}`
              },
              ...vuln.references.map(ref => ({
                type: 'other',
                locator: ref
              }))
            ]
          };

          // 添加 per-package VEX 屬性，以 spdxId 區分不同套件的狀態
          if (vuln.vexStatus) {
            vulnerability.properties.push({ name: `vex:status:${spdxId}`, value: vuln.vexStatus });
            if (vuln.vexJustification) {
              vulnerability.properties.push({ name: `vex:justification:${spdxId}`, value: vuln.vexJustification });
            }
          }

          vulnMap.set(vuln.cveId, vulnerability);
        }
      });
    });

    return Array.from(vulnMap.values());
  }

  /**
   * 匯出授權相容性報告
   */
  exportLicenseCompatibilityReport(packages: PackageInfo[]): void {
    const enhancedPackages = this.licenseAnalysisService.enhancePackagesWithLicenseInfo(packages);
    const stats = this.licenseAnalysisService.getLicenseStatistics(enhancedPackages);
    const compatibility = this.licenseAnalysisService.checkLicenseCompatibility(enhancedPackages);

    const report = {
      metadata: {
        reportType: 'License Compatibility Analysis',
        generatedAt: new Date().toISOString(),
        toolName: 'CVE Scanner Enhanced',
        version: '1.1.0'
      },
      summary: stats,
      compatibility: compatibility,
      packages: enhancedPackages.map(pkg => ({
        name: pkg.name,
        version: pkg.version,
        license: pkg.license,
        licenseDeclared: pkg.licenseDeclared,
        licenseConcluded: pkg.licenseConcluded,
        licenseSource: pkg.licenseSource
      }))
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: 'application/json;charset=utf-8'
    });

    const fileName = `license-compatibility-${this.formatDate(new Date())}.json`;
    saveAs(blob, fileName);
  }
}
