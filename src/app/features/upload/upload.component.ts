import { Component, OnInit, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { MatStepperModule } from '@angular/material/stepper';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatChipsModule } from '@angular/material/chips';
import { MatSnackBarModule, MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatRadioModule } from '@angular/material/radio';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatBadgeModule } from '@angular/material/badge';
import { FormsModule } from '@angular/forms';
import { ScrollingModule } from '@angular/cdk/scrolling';

import { FileParserService } from '../../core/services/file-parser.service';
import { BackgroundScanService } from '../../core/services/background-scan.service';
import { PackageInfo, ValidationResult, ScanConfig, DEFAULT_SCAN_CONFIGS } from '../../core/models/vulnerability.model';

@Component({
  selector: 'app-upload',
  standalone: true,
  imports: [
    CommonModule,
    ReactiveFormsModule,
    FormsModule,
    RouterModule,
    MatStepperModule,
    MatButtonModule,
    MatCardModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatChipsModule,
    MatSnackBarModule,
    MatTableModule,
    MatTooltipModule,
    MatRadioModule,
    MatExpansionModule,
    MatBadgeModule,
    ScrollingModule
  ],
  templateUrl: './upload.component.html',
  styleUrls: ['./upload.component.scss']
})
export class UploadComponent implements OnInit {
  @ViewChild('fileInput') fileInput!: ElementRef<HTMLInputElement>;
  @ViewChild('stepper') stepper!: any;

  fileSelectionForm: FormGroup;
  validationForm: FormGroup;
  
  selectedFile: File | null = null;
  isDragOver = false;
  isValidating = false;
  isParsing = false;
  validationResult: ValidationResult | null = null;
  packages: PackageInfo[] = [];
  allPackages: PackageInfo[] = [];
  currentScanConfig: ScanConfig = DEFAULT_SCAN_CONFIGS['balanced'];
  estimatedScanTime: { estimatedMinutes: number; description: string } | null = null;
  
  // UI 狀態控制
  showPackagesList = false; // 預設不展開套件清單
  displayedColumns = ['name', 'version', 'type'];

  // 掃描模式選項
  scanModes = [
    { 
      value: 'fast', 
      label: '快速掃描', 
      description: '僅掃描直接相依性，跳過開發工具',
      icon: 'flash_on',
      config: DEFAULT_SCAN_CONFIGS['fast']
    },
    { 
      value: 'balanced', 
      label: '平衡掃描', 
      description: '掃描直接和開發相依性，限制間接相依深度',
      icon: 'balance',
      config: DEFAULT_SCAN_CONFIGS['balanced']
    },
    { 
      value: 'comprehensive', 
      label: '完整掃描', 
      description: '掃描所有相依性，包含深層間接相依',
      icon: 'search',
      config: DEFAULT_SCAN_CONFIGS['comprehensive']
    }
  ];

  constructor(
    private fb: FormBuilder,
    private router: Router,
    private snackBar: MatSnackBar,
    private fileParserService: FileParserService,
    public backgroundScanService: BackgroundScanService
  ) {
    this.fileSelectionForm = this.fb.group({
      file: ['', Validators.required]
    });
    
    this.validationForm = this.fb.group({
      validation: ['', Validators.required]
    });
  }

  ngOnInit(): void {}

  // 拖拽事件處理
  onDragOver(event: DragEvent): void {
    event.preventDefault();
    this.isDragOver = true;
  }

  onDragLeave(event: DragEvent): void {
    event.preventDefault();
    this.isDragOver = false;
  }

  onDrop(event: DragEvent): void {
    event.preventDefault();
    this.isDragOver = false;
    
    const files = event.dataTransfer?.files;
    if (files && files.length > 0) {
      this.handleFileSelection(files[0]);
    }
  }

  // 檔案選擇處理
  triggerFileInput(): void {
    this.fileInput.nativeElement.click();
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.handleFileSelection(input.files[0]);
    }
  }

  private handleFileSelection(file: File): void {
    // 檔案大小檢查 (10MB)
    const maxSize = 10 * 1024 * 1024;
    if (file.size > maxSize) {
      this.snackBar.open('檔案大小超過 10MB 限制', '確定', {
        duration: 5000,
        panelClass: ['error-snackbar']
      });
      return;
    }

    // 檔案類型檢查
    const isValidFile = file.name === 'package.json' || file.name === 'package-lock.json';
    if (!isValidFile) {
      this.snackBar.open('請選擇 package.json 或 package-lock.json 檔案', '確定', {
        duration: 5000,
        panelClass: ['error-snackbar']
      });
      return;
    }

    this.selectedFile = file;
    this.fileSelectionForm.patchValue({ file: file.name });
    this.validationResult = null;
    this.packages = [];
  }

  removeFile(): void {
    this.selectedFile = null;
    this.fileSelectionForm.reset();
    this.validationResult = null;
    this.packages = [];
    if (this.fileInput) {
      this.fileInput.nativeElement.value = '';
    }
  }


  // 檔案驗證
  validateFile(): void {
    if (!this.selectedFile) return;
    
    this.isValidating = true;
    this.fileParserService.validateFileFormat(this.selectedFile).subscribe({
      next: (result) => {
        this.validationResult = result;
        this.validationForm.patchValue({ 
          validation: result.isValid ? 'valid' : 'invalid' 
        });
        this.isValidating = false;
        
        if (result.isValid) {
          // 自動解析套件並跳到下一步
          this.parsePackages();
          // 跳到第二步驟
          setTimeout(() => {
            if (this.stepper) {
              this.stepper.next();
            }
          }, 500);
        } else {
          this.snackBar.open('檔案驗證失敗，請檢查錯誤訊息', '確定', {
            duration: 5000,
            panelClass: ['error-snackbar']
          });
        }
      },
      error: (error) => {
        this.isValidating = false;
        this.snackBar.open(`驗證失敗: ${error.message}`, '確定', {
          duration: 5000,
          panelClass: ['error-snackbar']
        });
      }
    });
  }

  // 解析套件清單
  private parsePackages(): void {
    if (!this.selectedFile) return;
    
    this.isParsing = true;
    
    // 先取得所有套件以便統計和建議
    this.fileParserService.parsePackageFile(this.selectedFile, DEFAULT_SCAN_CONFIGS['comprehensive']).subscribe({
      next: (allPackages) => {
        this.allPackages = allPackages;
        
        // 根據套件數量建議掃描配置
        const recommendedConfig = this.fileParserService.getScanConfigRecommendation(allPackages.length);
        const recommendedMode = this.scanModes.find(mode => mode.config.mode === recommendedConfig.mode);
        
        // 使用當前選擇的配置過濾套件
        if (this.selectedFile) {
          this.fileParserService.parsePackageFile(this.selectedFile, this.currentScanConfig).subscribe({
            next: (filteredPackages) => {
              this.packages = filteredPackages;
              this.estimatedScanTime = this.fileParserService.estimateScanTime(filteredPackages);
              this.isParsing = false;
              
              const filterInfo = allPackages.length !== filteredPackages.length ? 
                `，已過濾至 ${filteredPackages.length} 個套件` : '';
              
              this.snackBar.open(
                `成功解析 ${filteredPackages.length} 個套件${filterInfo}${recommendedMode ? `，建議使用「${recommendedMode.label}」模式` : ''}`, 
                '確定', 
                {
                  duration: 4000,
                  panelClass: ['success-snackbar']
                }
              );
            },
            error: (error) => {
              this.isParsing = false;
              this.snackBar.open(`解析失敗: ${error.message}`, '確定', {
                duration: 5000,
                panelClass: ['error-snackbar']
              });
            }
          });
        }
      },
      error: (error) => {
        this.isParsing = false;
        this.snackBar.open(`解析失敗: ${error.message}`, '確定', {
          duration: 5000,
          panelClass: ['error-snackbar']
        });
      }
    });
  }

  // 開始掃描
  startScan(): void {
    if (this.packages.length === 0) return;
    
    // 將套件資料傳遞給掃描頁面
    this.router.navigate(['/scan'], { 
      state: { packages: this.packages }
    });
  }

  // 工具方法
  formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  getDependencyCount(type: 'dependency' | 'devDependency' | 'transitive'): number {
    return this.packages.filter(pkg => pkg.type === type).length;
  }

  getDependenciesCount(): number {
    return this.packages.filter(pkg => pkg.type === 'dependency').length;
  }

  getDevDependenciesCount(): number {
    return this.packages.filter(pkg => pkg.type === 'devDependency').length;
  }

  getTransitiveDependenciesCount(): number {
    return this.packages.filter(pkg => pkg.type === 'transitive').length;
  }

  isPackageLockFile(): boolean {
    return this.selectedFile?.name === 'package-lock.json';
  }

  // 切換掃描模式
  onScanModeChange(mode: string): void {
    const selectedMode = this.scanModes.find(m => m.value === mode);
    if (selectedMode && this.selectedFile) {
      this.currentScanConfig = selectedMode.config;
      
      // 重新過濾套件
      this.fileParserService.parsePackageFile(this.selectedFile, this.currentScanConfig).subscribe({
        next: (filteredPackages) => {
          this.packages = filteredPackages;
          this.estimatedScanTime = this.fileParserService.estimateScanTime(filteredPackages);
          
          const originalCount = this.allPackages.length;
          const filteredCount = filteredPackages.length;
          
          if (originalCount !== filteredCount) {
            this.snackBar.open(
              `已切換至${selectedMode.label}，顯示 ${filteredCount}/${originalCount} 個套件`, 
              '確定', 
              { duration: 3000 }
            );
          }
        },
        error: (error) => {
          console.error('重新過濾套件失敗:', error);
        }
      });
    }
  }

  // 取得當前模式描述
  getCurrentModeDescription(): string {
    const currentMode = this.scanModes.find(mode => mode.config.mode === this.currentScanConfig.mode);
    return currentMode?.description || '';
  }

  // 取得掃描統計資訊
  getScanStats(): string {
    if (this.allPackages.length === 0) return '';
    
    const total = this.allPackages.length;
    const current = this.packages.length;
    const filtered = total - current;
    
    if (filtered === 0) {
      return `將掃描全部 ${total} 個套件`;
    } else {
      return `將掃描 ${current} 個套件 (已過濾 ${filtered} 個)`;
    }
  }

  // 虛擬滾動 trackBy 函數，提升性能
  trackByPackageName(_index: number, item: PackageInfo): string {
    return item.name;
  }

}