import { Injectable } from '@angular/core';
import { saveAs } from 'file-saver';
import { PackageInfo, Vulnerability } from '../models/vulnerability.model';

@Injectable({
  providedIn: 'root'
})
export class ReportExportService {

  constructor() { }

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
    return scanResults.reduce((total, result) => total + result.vulnerabilities.length, 0);
  }

  private getSeverityBreakdown(scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]): {
    critical: number;
    high: number;
    medium: number;
    low: number;
    safe: number;
  } {
    const breakdown = { critical: 0, high: 0, medium: 0, low: 0, safe: 0 };

    scanResults.forEach(result => {
      if (result.vulnerabilities.length === 0) {
        breakdown.safe += 1;
      } else {
        result.vulnerabilities.forEach(vuln => {
          switch (vuln.severity) {
            case 'CRITICAL': breakdown.critical += 1; break;
            case 'HIGH': breakdown.high += 1; break;
            case 'MEDIUM': breakdown.medium += 1; break;
            case 'LOW': breakdown.low += 1; break;
          }
        });
      }
    });

    return breakdown;
  }

  private generateScanSummary(scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[]): string {
    const totalPackages = scanResults.length;
    const vulnerablePackages = scanResults.filter(r => r.vulnerabilities.length > 0).length;
    const safePackages = totalPackages - vulnerablePackages;

    return `掃描了 ${totalPackages} 個套件，其中 ${vulnerablePackages} 個套件存在漏洞，${safePackages} 個套件安全。`;
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
}
