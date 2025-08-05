import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBarModule, MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { Subscription } from 'rxjs';

import { NistApiService } from '../../core/services/nist-api.service';
import { PackageInfo, Vulnerability, ScanProgress } from '../../core/models/vulnerability.model';

@Component({
  selector: 'app-scan',
  standalone: true,
  imports: [
    CommonModule,
    MatCardModule,
    MatButtonModule,
    MatProgressBarModule,
    MatIconModule,
    MatSnackBarModule,
    MatTableModule
  ],
  templateUrl: './scan.component.html',
  styleUrls: ['./scan.component.scss']
})
export class ScanComponent implements OnInit, OnDestroy {
  packages: PackageInfo[] = [];
  isScanning = false;
  scanCompleted = false;
  scanResults: {packageName: string, vulnerabilities: Vulnerability[]}[] = [];
  scanTimestamp: Date = new Date();
  scanProgress: ScanProgress = {
    current: 0,
    total: 0,
    percentage: 0,
    currentPackage: ''
  };
  
  displayedColumns = ['package', 'vulnerabilities', 'highestSeverity'];
  private scanSubscription?: Subscription;
  
  constructor(
    private router: Router,
    private nistApiService: NistApiService,
    private snackBar: MatSnackBar
  ) {
    // 從路由狀態取得套件清單
    const navigation = this.router.getCurrentNavigation();
    if (navigation?.extras?.state?.['packages']) {
      this.packages = navigation.extras.state['packages'];
    }
  }
  
  ngOnInit(): void {
    if (this.packages.length === 0) {
      this.snackBar.open('沒有套件資料，請先上傳 package.json 檔案', '確定', {
        duration: 5000
      });
      this.goBack();
    } else {
      // 自動開始掃描
      this.startScan();
    }
  }
  
  ngOnDestroy(): void {
    if (this.scanSubscription) {
      this.scanSubscription.unsubscribe();
    }
  }
  
  getScanTitle(): string {
    if (this.isScanning) return '掃描進度';
    if (this.scanCompleted) return '掃描完成';
    return '準備掃描';
  }
  
  getScanSubtitle(): string {
    if (this.isScanning) return '正在檢查套件漏洞...';
    if (this.scanCompleted) return `掃描了 ${this.packages.length} 個套件`;
    return `準備掃描 ${this.packages.length} 個套件`;
  }
  
  startScan(): void {
    if (this.packages.length === 0) return;
    
    this.isScanning = true;
    this.scanCompleted = false;
    this.scanResults = [];
    this.scanTimestamp = new Date(); // 記錄掃描開始時間
    this.scanProgress = {
      current: 0,
      total: this.packages.length,
      percentage: 0,
      currentPackage: '準備開始掃描...'
    };
    
    this.scanSubscription = this.nistApiService.searchMultiplePackagesWithProgress(this.packages).subscribe({
      next: (response) => {
        if (response.type === 'progress' && response.progress) {
          // 更新進度
          this.scanProgress = {
            current: response.progress.current + 1, // +1 因為 index 從 0 開始
            total: response.progress.total,
            percentage: ((response.progress.current + 1) / response.progress.total) * 100,
            currentPackage: response.progress.currentPackage.includes('等待') 
              ? response.progress.currentPackage 
              : `正在掃描: ${response.progress.currentPackage}`
          };
        } else if (response.type === 'result' && response.results) {
          // 掃描完成
          this.scanResults = response.results;
          this.isScanning = false;
          this.scanCompleted = true;
          
          const vulnerableCount = response.results.filter(r => r.vulnerabilities.length > 0).length;
          const totalVulnerabilities = response.results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
          const failedCount = response.results.filter(r => r.vulnerabilities.length === 0).length;
          
          let message = '';
          if (totalVulnerabilities > 0) {
            message = `掃描完成！在 ${vulnerableCount} 個套件中發現 ${totalVulnerabilities} 個漏洞`;
            if (failedCount > 0) {
              message += `，${failedCount} 個套件掃描失敗或無資料`;
            }
            this.snackBar.open(message, '確定', {
              duration: 8000,
              panelClass: ['warning-snackbar']
            });
          } else {
            message = '掃描完成！沒有發現任何已知漏洞';
            if (failedCount > 0) {
              message += `（${failedCount} 個套件掃描失敗或無資料）`;
            }
            this.snackBar.open(message, '確定', {
              duration: 5000,
              panelClass: ['success-snackbar']
            });
          }
        } else if (response.type === 'error' && response.error) {
          // 處理錯誤但不停止掃描
          console.warn('掃描過程中發生錯誤:', response.error);
        }
      },
      error: (error) => {
        this.isScanning = false;
        this.snackBar.open(`掃描失敗: ${error.message}`, '確定', {
          duration: 8000,
          panelClass: ['error-snackbar']
        });
      }
    });
  }
  
  getSeverityCount(severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'): number {
    return this.scanResults.reduce((count, result) => {
      return count + result.vulnerabilities.filter(v => v.severity === severity).length;
    }, 0);
  }
  
  getSafePackagesCount(): number {
    return this.scanResults.filter(result => result.vulnerabilities.length === 0).length;
  }
  
  getVulnerablePackages(): {packageName: string, vulnerabilities: Vulnerability[]}[] {
    return this.scanResults.filter(result => result.vulnerabilities.length > 0);
  }
  
  getHighestSeverity(vulnerabilities: Vulnerability[]): string {
    if (vulnerabilities.length === 0) return 'NONE';
    
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];
    
    for (const severity of severityOrder) {
      if (vulnerabilities.some(v => v.severity === severity)) {
        return severity;
      }
    }
    
    return 'NONE';
  }
  
  viewReport(): void {
    this.router.navigate(['/report'], {
      state: { 
        packages: this.packages,
        scanResults: this.scanResults,
        scanTimestamp: this.scanTimestamp
      }
    });
  }
  
  goBack(): void {
    this.router.navigate(['/upload']);
  }
}