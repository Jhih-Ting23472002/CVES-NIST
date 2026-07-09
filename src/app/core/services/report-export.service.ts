import { Injectable } from '@angular/core';
import { saveAs } from 'file-saver';
import { PackageInfo, Vulnerability } from '../models/vulnerability.model';
import {
  getUniqueTotalVulnerabilities,
  getUniqueSeverityBreakdown,
  getTotalAffectedCombinations,
  detectDataSources
} from '../../shared/utils/vulnerability-count-utils';
import { CycloneDxSbomService } from './cyclonedx-sbom.service';
import { SpdxSbomService } from './spdx-sbom.service';
import { getAdvisoryUrl, buildNpmPurl } from '../../shared/utils/sbom-utils';

@Injectable({
  providedIn: 'root'
})
export class ReportExportService {

  constructor(
    private cycloneDxSbomService: CycloneDxSbomService,
    private spdxSbomService: SpdxSbomService
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
   * 匯出 CycloneDX SBOM 格式
   */
  exportAsCycloneDX(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = false
  ): void {
    const json = this.cycloneDxSbomService.generateBomJson(packages, scanResults, {
      scanTimestamp,
      includeVulnerabilities
    });

    const blob = new Blob([json], {
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
    const json = this.spdxSbomService.generateSbomJson(packages, scanResults, {
      scanTimestamp,
      includeVulnerabilities
    });

    const blob = new Blob([json], {
      type: 'application/json;charset=utf-8'
    });

    const fileName = `sbom-spdx-${this.formatDate(new Date())}.json`;
    saveAs(blob, fileName);
  }

  /**
   * 匯出掃描結果報告 HTML 格式 (Trivy 風格，供人類閱讀)
   */
  exportAsScanReportHtml(
    packages: PackageInfo[],
    scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[],
    scanTimestamp?: Date,
    includeVulnerabilities: boolean = true
  ): void {
    const html = this.generateScanReportHtml(packages, scanResults, scanTimestamp, includeVulnerabilities);

    const blob = new Blob([html], {
      type: 'text/html;charset=utf-8'
    });

    const fileName = `scan-report-${this.formatDate(new Date())}.html`;
    saveAs(blob, fileName);
  }

  /**
   * 匯出 SBOM HTML 格式 (人類可讀，呈現套件的 License 與 PURL)
   */
  exportSbomAsHtml(
    packages: PackageInfo[],
    generatedAt: Date = new Date()
  ): void {
    const html = this.generateSbomHtml(packages, generatedAt);

    const blob = new Blob([html], {
      type: 'text/html;charset=utf-8'
    });

    const fileName = `sbom-${this.formatDate(new Date())}.html`;
    saveAs(blob, fileName);
  }

  /**
   * 產生人類可讀的 SBOM HTML (CycloneDX 1.6 內容：套件 / 版本 / License / PURL)
   */
  private generateSbomHtml(packages: PackageInfo[], generatedAt: Date): string {
    const direct = packages.filter(p => p.type !== 'transitive');
    const transitive = packages.filter(p => p.type === 'transitive');

    const section = (title: string, list: PackageInfo[]): string => {
      if (list.length === 0) {
        return '';
      }
      const rows = list.map(pkg => {
        const license = pkg.licenseConcluded || pkg.licenseDeclared || pkg.license || '—';
        const purl = buildNpmPurl(pkg.name, pkg.version).toString();
        return `
      <tr>
        <td>${this.escapeHtml(pkg.name)}</td>
        <td><code>${this.escapeHtml(pkg.version)}</code></td>
        <td>${this.escapeHtml(license)}</td>
        <td class="purl"><code>${this.escapeHtml(purl)}</code></td>
      </tr>`;
      }).join('');
      return `
  <h2>${title}<span class="count">${list.length}</span></h2>
  <table>
    <thead>
      <tr><th>套件</th><th>版本</th><th>License</th><th>PURL</th></tr>
    </thead>
    <tbody>${rows}
    </tbody>
  </table>`;
    };

    return `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8" />
<title>SBOM 報表</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "PingFang TC", "Microsoft JhengHei", sans-serif;
    margin: 0; padding: 40px; background: #f5f7fa; color: #2c3e50; line-height: 1.6;
  }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 24px; border-bottom: 3px solid #3498db; padding-bottom: 12px; }
  h2 { font-size: 18px; margin-top: 40px; }
  h2 .count {
    display: inline-block; margin-left: 10px; padding: 2px 10px;
    background: #3498db; color: white; border-radius: 12px; font-size: 13px; font-weight: normal;
  }
  .meta {
    background: white; padding: 20px 24px; border-radius: 8px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin: 20px 0;
  }
  .meta-row { display: flex; padding: 6px 0; border-bottom: 1px solid #ecf0f1; }
  .meta-row:last-child { border-bottom: none; }
  .meta-label { width: 180px; color: #7f8c8d; font-weight: 600; }
  .meta-value { flex: 1; word-break: break-all; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 20px 0; }
  .stat-card {
    background: white; padding: 20px; border-radius: 8px; text-align: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
  }
  .stat-number { font-size: 36px; font-weight: 700; color: #3498db; }
  .stat-label { color: #7f8c8d; font-size: 13px; margin-top: 4px; }
  table {
    width: 100%; border-collapse: collapse; background: white; border-radius: 8px;
    overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05); font-size: 13px;
  }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #ecf0f1; }
  th { background: #34495e; color: white; font-weight: 600; }
  tr:last-child td { border-bottom: none; }
  tr:hover { background: #f8f9fa; }
  code {
    background: #ecf0f1; padding: 2px 6px; border-radius: 3px;
    font-family: "SF Mono", Consolas, monospace; font-size: 12px;
  }
  .purl { max-width: 400px; word-break: break-all; }
  @media print {
    body { background: white; padding: 20px; }
    .stat-card, .meta, table { box-shadow: none; border: 1px solid #ddd; }
  }
</style>
</head>
<body>
<div class="container">
  <h1>SBOM 報表</h1>

  <div class="meta">
    <div class="meta-row"><div class="meta-label">SBOM 格式</div><div class="meta-value">CycloneDX 1.6</div></div>
    <div class="meta-row"><div class="meta-label">產生時間</div><div class="meta-value">${generatedAt.toLocaleString('zh-TW')}</div></div>
    <div class="meta-row"><div class="meta-label">產生工具</div><div class="meta-value">CVE 安全掃描工具</div></div>
  </div>

  <div class="stats">
    <div class="stat-card"><div class="stat-number">${packages.length}</div><div class="stat-label">元件總數</div></div>
    <div class="stat-card"><div class="stat-number">${direct.length}</div><div class="stat-label">直接依賴</div></div>
    <div class="stat-card"><div class="stat-number">${transitive.length}</div><div class="stat-label">間接依賴</div></div>
  </div>
${section('直接依賴', direct)}
${section('間接依賴', transitive)}
</div>
</body>
</html>`;
  }

  private escapeHtml(value: string): string {
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  private getTotalVulnerabilities(scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]): number {
    return getUniqueTotalVulnerabilities(scanResults);
  }

  private getSeverityBreakdown(scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]): {
    critical: number;
    high: number;
    medium: number;
    low: number;
    none: number;
    safe: number;
  } {
    const uniqueBreakdown = getUniqueSeverityBreakdown(scanResults);
    const safeCount = scanResults.filter(r => r.vulnerabilities.length === 0).length;

    return {
      ...uniqueBreakdown,
      safe: safeCount
    };
  }

  /**
   * 依掃描結果的實際資料來源產生頁尾說明
   */
  private getDataSourceLine(scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]): string {
    const { hasOsv, hasNist } = detectDataSources(scanResults);
    if (hasOsv && !hasNist) return '資料來源：OSV.dev';
    if (hasNist && !hasOsv) return '資料來源：NIST 國家漏洞資料庫 (NVD)';
    // 兩者皆有，或零漏洞無從判斷時列出雙來源
    return '資料來源：OSV.dev 與 NIST 國家漏洞資料庫 (NVD)';
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
      recommendations.push('⚠️ 高風險漏洞 management:');
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
   * 產生漏洞掃描結果報告 HTML (Trivy 風格)
   */
  private generateScanReportHtml(
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
    <title>漏洞掃描結果報告</title>
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

        .severity-none {
            background-color: #95a5a6;
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
        <h1>🛡️ 漏洞掃描結果報告</h1>
        <div class="subtitle">套件安全漏洞分析</div>
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
        <p>${this.getDataSourceLine(scanResults)}</p>
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
    if (severityBreakdown.none > 0) parts.push(`NONE: ${severityBreakdown.none}`);

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
                <a href="${getAdvisoryUrl(vuln.cveId)}" target="_blank">
                  ${getAdvisoryUrl(vuln.cveId)}
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
}
