import { Injectable } from '@angular/core';
import { Observable, from, throwError } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import { PackageInfo, ValidationResult } from '../models/vulnerability.model';
import { IFileParserService } from '../interfaces/services.interface';

@Injectable({
  providedIn: 'root'
})
export class FileParserService implements IFileParserService {

  parsePackageJson(file: File): Observable<PackageInfo[]> {
    return from(this.readFileContent(file)).pipe(
      map(content => {
        try {
          const packageJson = JSON.parse(content);
          return this.extractDependencies(content);
        } catch (error) {
          throw new Error('無效的 JSON 格式');
        }
      }),
      catchError(error => {
        return throwError(() => new Error(`解析檔案失敗: ${error.message}`));
      })
    );
  }

  validateFileFormat(file: File): Observable<ValidationResult> {
    return new Observable(observer => {
      const result: ValidationResult = {
        isValid: true,
        errors: [],
        warnings: []
      };

      // 檢查檔案名稱
      if (file.name !== 'package.json') {
        result.warnings.push('檔案名稱不是 package.json，請確認這是正確的檔案');
      }

      // 檢查檔案類型
      if (file.type && file.type !== 'application/json') {
        result.warnings.push('檔案類型不是 JSON 格式');
      }

      // 檢查檔案大小 (最大 10MB)
      const maxSize = 10 * 1024 * 1024; // 10MB
      if (file.size > maxSize) {
        result.errors.push('檔案過大，請選擇小於 10MB 的檔案');
        result.isValid = false;
      }

      // 檢查檔案內容
      this.readFileContent(file).then(content => {
        try {
          const packageJson = JSON.parse(content);
          
          // 檢查必要欄位
          if (!packageJson.name) {
            result.warnings.push('package.json 缺少 name 欄位');
          }
          
          if (!packageJson.version) {
            result.warnings.push('package.json 缺少 version 欄位');
          }

          // 檢查相依性
          const hasDependencies = packageJson.dependencies || packageJson.devDependencies;
          if (!hasDependencies) {
            result.errors.push('package.json 中沒有找到 dependencies 或 devDependencies');
            result.isValid = false;
          } else {
            const depCount = Object.keys(packageJson.dependencies || {}).length;
            const devDepCount = Object.keys(packageJson.devDependencies || {}).length;
            
            if (depCount + devDepCount === 0) {
              result.errors.push('沒有找到任何相依套件');
              result.isValid = false;
            } else if (depCount + devDepCount > 1000) {
              result.warnings.push(`發現 ${depCount + devDepCount} 個套件，掃描可能需要較長時間`);
            }
          }

        } catch (parseError) {
          result.errors.push('JSON 格式錯誤，無法解析檔案內容');
          result.isValid = false;
        }

        observer.next(result);
        observer.complete();
      }).catch(error => {
        result.errors.push(`讀取檔案失敗: ${error.message}`);
        result.isValid = false;
        observer.next(result);
        observer.complete();
      });
    });
  }

  extractDependencies(content: string): PackageInfo[] {
    try {
      const packageJson = JSON.parse(content);
      const packages: PackageInfo[] = [];

      // 處理 dependencies
      if (packageJson.dependencies) {
        Object.entries(packageJson.dependencies).forEach(([name, version]) => {
          packages.push({
            name,
            version: this.normalizeVersion(version as string),
            type: 'dependency',
            description: packageJson.description
          });
        });
      }

      // 處理 devDependencies
      if (packageJson.devDependencies) {
        Object.entries(packageJson.devDependencies).forEach(([name, version]) => {
          packages.push({
            name,
            version: this.normalizeVersion(version as string),
            type: 'devDependency',
            description: packageJson.description
          });
        });
      }

      return packages.sort((a, b) => a.name.localeCompare(b.name));
    } catch (error) {
      throw new Error('解析 package.json 內容失敗');
    }
  }

  private async readFileContent(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = (event) => {
        if (event.target?.result) {
          resolve(event.target.result as string);
        } else {
          reject(new Error('讀取檔案內容失敗'));
        }
      };
      
      reader.onerror = () => {
        reject(new Error('讀取檔案時發生錯誤'));
      };
      
      reader.readAsText(file);
    });
  }

  private normalizeVersion(version: string): string {
    // 移除版本前綴符號 (^, ~, >=, 等)
    return version.replace(/^[\^~>=<]+/, '').trim();
  }

  // 輔助方法：檢查版本格式
  private isValidVersion(version: string): boolean {
    // 簡單的語義化版本檢查
    const semverPattern = /^\d+\.\d+\.\d+/;
    return semverPattern.test(this.normalizeVersion(version));
  }

  // 輔助方法：取得相依性統計
  getDependencyStats(packages: PackageInfo[]): {
    total: number;
    dependencies: number;
    devDependencies: number;
  } {
    const dependencies = packages.filter(pkg => pkg.type === 'dependency').length;
    const devDependencies = packages.filter(pkg => pkg.type === 'devDependency').length;
    
    return {
      total: packages.length,
      dependencies,
      devDependencies
    };
  }
}