import { Component, OnInit, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { MatStepperModule } from '@angular/material/stepper';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatChipsModule } from '@angular/material/chips';
import { MatSnackBarModule, MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';

import { FileParserService } from '../../core/services/file-parser.service';
import { PackageInfo, ValidationResult } from '../../core/models/vulnerability.model';

@Component({
  selector: 'app-upload',
  standalone: true,
  imports: [
    CommonModule,
    ReactiveFormsModule,
    MatStepperModule,
    MatButtonModule,
    MatCardModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatChipsModule,
    MatSnackBarModule,
    MatTableModule,
    MatTooltipModule
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
  
  displayedColumns = ['name', 'version', 'type'];

  constructor(
    private fb: FormBuilder,
    private router: Router,
    private snackBar: MatSnackBar,
    private fileParserService: FileParserService
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
    if (!file.name.endsWith('.json')) {
      this.snackBar.open('請選擇 JSON 格式的檔案', '確定', {
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
    this.fileParserService.parsePackageJson(this.selectedFile).subscribe({
      next: (packages) => {
        this.packages = packages;
        this.isParsing = false;
        
        this.snackBar.open(`成功解析 ${packages.length} 個套件`, '確定', {
          duration: 3000,
          panelClass: ['success-snackbar']
        });
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

  getDependencyCount(type: 'dependency' | 'devDependency'): number {
    return this.packages.filter(pkg => pkg.type === type).length;
  }

  getDependenciesCount(): number {
    return this.packages.filter(pkg => pkg.type === 'dependency').length;
  }

  getDevDependenciesCount(): number {
    return this.packages.filter(pkg => pkg.type === 'devDependency').length;
  }
}