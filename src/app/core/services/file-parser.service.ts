import { Injectable } from '@angular/core';
import { Observable, from, throwError } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import { PackageInfo, ValidationResult, ScanConfig, DEFAULT_SCAN_CONFIGS } from '../models/vulnerability.model';
import { IFileParserService } from '../interfaces/services.interface';

@Injectable({
  providedIn: 'root'
})
export class FileParserService implements IFileParserService {

  parsePackageFile(file: File, scanConfig?: ScanConfig): Observable<PackageInfo[]> {
    const config = scanConfig || DEFAULT_SCAN_CONFIGS['balanced'];
    const isPackageLock = file.name === 'package-lock.json';

    return from(this.readFileContent(file)).pipe(
      map(content => {
        try {
          const packageData = JSON.parse(content);
          const allPackages = isPackageLock ?
            this.extractDependenciesFromLock(content) :
            this.extractDependencies(content);

          return this.filterPackagesByConfig(allPackages, config);
        } catch (error) {
          throw new Error('無效的 JSON 格式');
        }
      }),
      catchError(error => {
        return throwError(() => new Error(`解析檔案失敗: ${error.message}`));
      })
    );
  }

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

      const isPackageJson = file.name === 'package.json';
      const isPackageLock = file.name === 'package-lock.json';

      // 檢查檔案名稱
      if (!isPackageJson && !isPackageLock) {
        result.warnings.push('檔案名稱不是 package.json 或 package-lock.json，請確認這是正確的檔案');
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
            result.warnings.push(`${isPackageLock ? 'package-lock.json' : 'package.json'} 缺少 name 欄位`);
          }

          if (!packageJson.version) {
            result.warnings.push(`${isPackageLock ? 'package-lock.json' : 'package.json'} 缺少 version 欄位`);
          }

          // 根據檔案類型檢查相依性
          if (isPackageLock) {
            // package-lock.json 檢查
            const lockfileVersion = packageJson.lockfileVersion || 1;
            const hasPackages = !!packageJson.packages;
            const hasDependencies = !!packageJson.dependencies;

            if (lockfileVersion >= 2 && !hasPackages) {
              result.errors.push('package-lock.json (v2+) 中沒有找到 packages 區段');
              result.isValid = false;
            } else if (lockfileVersion === 1 && !hasDependencies) {
              result.errors.push('package-lock.json (v1) 中沒有找到 dependencies 區段');
              result.isValid = false;
            } else if (!hasPackages && !hasDependencies) {
              result.errors.push('package-lock.json 格式不支援：找不到 packages 或 dependencies 區段');
              result.isValid = false;
            } else {
              try {
                // 嘗試解析套件以驗證格式
                const testPackages = this.extractDependenciesFromLock(content);
                if (testPackages.length === 0) {
                  result.warnings.push('沒有找到任何有效的相依套件');
                } else if (testPackages.length > 5000) {
                  result.warnings.push(`發現 ${testPackages.length} 個套件（包含間接相依），掃描可能需要較長時間`);
                }
              } catch (parseError) {
                result.warnings.push('package-lock.json 格式可能有問題，但仍可嘗試解析');
              }
            }
          } else {
            // package.json 檢查
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

  extractDependenciesFromLock(content: string): PackageInfo[] {
    try {
      const packageLock = JSON.parse(content);
      const packages: PackageInfo[] = [];
      const lockfileVersion = packageLock.lockfileVersion || 1;

      // 根據 lockfileVersion 決定解析方式
      if (lockfileVersion >= 2 && packageLock.packages) {
        // 新版格式 (lockfileVersion 2+): 使用 packages
        return this.parsePackagesFormat(packageLock, packages);
      } else if (packageLock.dependencies) {
        // 舊版格式 (lockfileVersion 1): 使用 dependencies
        return this.parseDependenciesFormat(packageLock, packages);
      } else {
        throw new Error('package-lock.json 格式不支援：找不到 packages 或 dependencies 區段');
      }
    } catch (error) {
      console.error('解析 package-lock.json 時發生錯誤:', error);
      throw new Error(`解析 package-lock.json 內容失敗: ${error instanceof Error ? error.message : '未知錯誤'}`);
    }
  }

  // 解析新版格式 (lockfileVersion 2+)
  private parsePackagesFormat(packageLock: any, packages: PackageInfo[]): PackageInfo[] {
    // 取得根套件的 dependencies 和 devDependencies 資訊
    const rootPackage = packageLock.packages[''];
    const rootDeps = rootPackage?.dependencies || {};
    const rootDevDeps = rootPackage?.devDependencies || {};

    // 處理所有套件
    Object.entries(packageLock.packages).forEach(([packagePath, packageInfo]: [string, any]) => {
      // 跳過根套件（空字串）
      if (packagePath === '') return;

      // 取得套件名稱（移除 node_modules/ 前綴和路徑）
      const packageName = this.extractPackageNameFromPath(packagePath);

      // 跳過無效的套件名稱
      if (!packageName || packageName.trim() === '') return;

      // 判斷是直接相依還是間接相依
      const isDirect = rootDeps.hasOwnProperty(packageName) || rootDevDeps.hasOwnProperty(packageName);
      const isDevDep = rootDevDeps.hasOwnProperty(packageName);

      // 安全地處理版本號
      const version = packageInfo.version || '0.0.0';

      // 安全地處理 license 欄位
      let license: string | undefined;
      if (packageInfo.license) {
        if (typeof packageInfo.license === 'string') {
          license = packageInfo.license;
        } else if (typeof packageInfo.license === 'object' && packageInfo.license.type) {
          license = packageInfo.license.type;
        }
      }

      packages.push({
        name: packageName,
        version: version,
        type: isDirect ? (isDevDep ? 'devDependency' : 'dependency') : 'transitive',
        description: packageInfo.description || undefined,
        resolved: packageInfo.resolved,
        integrity: packageInfo.integrity,
        dev: packageInfo.dev || false,
        license: license,
        packageKey: `${packageName}@${version}`,
        isPrimary: isDirect,
        dependencyPath: this.extractDependencyPath(packagePath)
      });
    });

    // 移除重複項目（同一個套件可能有多個版本）
    const uniquePackages = this.removeDuplicatePackages(packages);
    return uniquePackages.sort((a, b) => a.name.localeCompare(b.name));
  }

  // 解析舊版格式 (lockfileVersion 1)
  private parseDependenciesFormat(packageLock: any, packages: PackageInfo[]): PackageInfo[] {
    // 取得根層級的相依性資訊
    const rootDeps = packageLock.dependencies || {};

    // 遞迴處理相依性樹
    this.extractFromDependencyTree(rootDeps, packages, 'dependency');

    // 處理 devDependencies（如果存在）
    if (packageLock.devDependencies) {
      this.extractFromDependencyTree(packageLock.devDependencies, packages, 'devDependency');
    }

    // 移除重複項目
    const uniquePackages = this.removeDuplicatePackages(packages);
    return uniquePackages.sort((a, b) => a.name.localeCompare(b.name));
  }

  // 從相依性樹中提取套件
  private extractFromDependencyTree(deps: any, packages: PackageInfo[], type: 'dependency' | 'devDependency', isTransitive = false): void {
    Object.entries(deps).forEach(([packageName, packageInfo]: [string, any]) => {
      if (!packageName || packageName.trim() === '') return;

      const version = packageInfo.version || '0.0.0';

      // 安全地處理 license 欄位
      let license: string | undefined;
      if (packageInfo.license) {
        if (typeof packageInfo.license === 'string') {
          license = packageInfo.license;
        } else if (typeof packageInfo.license === 'object' && packageInfo.license.type) {
          license = packageInfo.license.type;
        }
      }

      packages.push({
        name: packageName,
        version: version,
        type: isTransitive ? 'transitive' : type,
        description: packageInfo.description || undefined,
        resolved: packageInfo.resolved,
        integrity: packageInfo.integrity,
        dev: type === 'devDependency',
        license: license,
        packageKey: `${packageName}@${version}`,
        isPrimary: !isTransitive,
        dependencyPath: isTransitive ? [packageName] : []
      });

      // 遞迴處理嵌套的相依性（標記為間接相依）
      if (packageInfo.dependencies) {
        this.extractFromDependencyTree(packageInfo.dependencies, packages, type, true);
      }
    });
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


  // 輔助方法：從套件路徑提取套件名稱
  private extractPackageNameFromPath(packagePath: string): string {
    if (!packagePath || packagePath.trim() === '') {
      return '';
    }

    // 移除 node_modules/ 前綴
    let name = packagePath.replace(/^node_modules\//, '');

    // 如果還有嵌套的 node_modules，取最後一個
    const lastNodeModulesIndex = name.lastIndexOf('node_modules/');
    if (lastNodeModulesIndex !== -1) {
      name = name.substring(lastNodeModulesIndex + 'node_modules/'.length);
    }

    // 處理 scoped packages (例如 @angular/core)
    if (name.startsWith('@')) {
      const parts = name.split('/');
      if (parts.length >= 2) {
        return parts.slice(0, 2).join('/');
      }
      return name; // 如果格式異常，返回原名稱
    }

    // 處理一般套件 - 只取第一個路徑段
    const firstPart = name.split('/')[0];
    return firstPart || '';
  }

  // 輔助方法：從套件路徑提取依賴路徑
  private extractDependencyPath(packagePath: string): string[] {
    if (!packagePath || packagePath.trim() === '') {
      return [];
    }

    const pathSegments = packagePath.split('/node_modules/').filter(segment => segment.trim() !== '');
    
    // 移除第一個空的 node_modules 前綴（如果有的話）
    if (pathSegments[0] === '') {
      pathSegments.shift();
    }

    // 清理每個路徑段，確保 scoped packages 正確處理
    const cleanedPath = pathSegments.map(segment => {
      segment = segment.replace(/^node_modules\//, '');
      
      // 對於 scoped packages，確保包含完整名稱
      if (segment.startsWith('@')) {
        const parts = segment.split('/');
        if (parts.length >= 2) {
          return parts.slice(0, 2).join('/');
        }
      }
      
      return segment.split('/')[0];
    });

    return cleanedPath.filter(path => path.trim() !== '');
  }

  // 輔助方法：合併同名套件的不同版本
  private removeDuplicatePackages(packages: PackageInfo[]): PackageInfo[] {
    const packageMap = new Map<string, PackageInfo[]>();
    
    // 按套件名稱分組
    packages.forEach(pkg => {
      const key = pkg.name;
      if (!packageMap.has(key)) {
        packageMap.set(key, []);
      }
      packageMap.get(key)!.push(pkg);
    });
    
    const result: PackageInfo[] = [];
    
    // 處理每個套件群組
    packageMap.forEach((versions) => {
      if (versions.length === 1) {
        // 只有一個版本，直接加入
        result.push(versions[0]);
      } else {
        // 有多個版本，需要決策
        const uniqueVersions = this.deduplicateVersions(versions);
        result.push(...uniqueVersions);
      }
    });
    
    return result;
  }
  
  // 處理同套件的多版本情況
  private deduplicateVersions(packages: PackageInfo[]): PackageInfo[] {
    const versionMap = new Map<string, PackageInfo>();
    
    packages.forEach(pkg => {
      const versionKey = pkg.version;
      
      if (!versionMap.has(versionKey)) {
        versionMap.set(versionKey, pkg);
      } else {
        // 同版本但不同類型，優先保留直接依賴
        const existing = versionMap.get(versionKey)!;
        const newPkg = this.selectBetterPackageInfo(existing, pkg);
        versionMap.set(versionKey, newPkg);
      }
    });
    
    return Array.from(versionMap.values());
  }
  
  // 選擇較佳的套件資訊（優先級：dependency > devDependency > transitive）
  private selectBetterPackageInfo(existing: PackageInfo, candidate: PackageInfo): PackageInfo {
    const typePriority = { 'dependency': 0, 'devDependency': 1, 'transitive': 2 };
    const existingPriority = typePriority[existing.type];
    const candidatePriority = typePriority[candidate.type];
    
    if (candidatePriority < existingPriority) {
      return candidate;
    } else if (candidatePriority === existingPriority) {
      // 相同優先級，合併資訊
      return {
        ...existing,
        // 保留更完整的描述
        description: candidate.description || existing.description,
        // 保留 resolved 和 integrity 資訊
        resolved: candidate.resolved || existing.resolved,
        integrity: candidate.integrity || existing.integrity,
        license: candidate.license || existing.license
      };
    }
    
    return existing;
  }

  // 常見的開發工具和構建工具套件 (通常安全風險較低)
  private readonly COMMON_TOOLS = new Set([
    // 測試框架
    'jest', 'mocha', 'chai', 'jasmine', 'karma', 'protractor', 'cypress', 'playwright',
    'vitest', '@testing-library', 'enzyme', 'sinon', 'nyc', 'c8',

    // 構建工具
    'webpack', 'rollup', 'vite', 'parcel', 'esbuild', 'swc', 'turbo',
    'gulp', 'grunt', 'browserify', 'snowpack',

    // Babel 相關
    '@babel', 'babel-core', 'babel-loader', 'babel-preset', 'babel-plugin',

    // TypeScript 相關
    'typescript', 'ts-node', 'ts-loader', 'tsc-watch', '@types',

    // ESLint/Prettier
    'eslint', 'prettier', 'stylelint', 'jshint', 'jslint',
    '@eslint', 'eslint-config', 'eslint-plugin',

    // 開發伺服器
    'nodemon', 'pm2', 'concurrently', 'cross-env', 'rimraf',

    // Angular CLI 工具
    '@angular-devkit', '@schematics', 'ng-packagr',

    // 其他工具
    'autoprefixer', 'postcss', 'sass', 'less', 'stylus',
    'husky', 'lint-staged', 'commitizen', 'semantic-release',
    'is-number', 'has', 'which', 'string-width', 'ent', 'is-even', 'kind-of', 'is-plain-object'
  ]);

  // 過濾套件根據掃描配置
  private filterPackagesByConfig(packages: PackageInfo[], config: ScanConfig): PackageInfo[] {
    let filteredPackages = [...packages];

    // 根據類型過濾
    if (!config.includeDirectDeps) {
      filteredPackages = filteredPackages.filter(pkg => pkg.type !== 'dependency');
    }

    if (!config.includeDevDeps) {
      filteredPackages = filteredPackages.filter(pkg => pkg.type !== 'devDependency');
    }

    if (!config.includeTransitive) {
      filteredPackages = filteredPackages.filter(pkg => pkg.type !== 'transitive');
    }

    // 跳過常見開發工具
    if (config.skipCommonTools) {
      filteredPackages = filteredPackages.filter(pkg =>
        !this.isCommonTool(pkg.name)
      );
    }

    return filteredPackages.sort((a, b) => {
      // 優先顯示直接相依性
      if (a.type !== b.type) {
        const priority = { 'dependency': 0, 'devDependency': 1, 'transitive': 2 };
        return priority[a.type] - priority[b.type];
      }
      return a.name.localeCompare(b.name);
    });
  }

  // 檢查是否為常見工具套件
  private isCommonTool(packageName: string): boolean {
    // 完全匹配
    if (this.COMMON_TOOLS.has(packageName)) {
      return true;
    }

    // 前綴匹配 (如 @babel/core, @types/node)
    for (const tool of this.COMMON_TOOLS) {
      if (packageName.startsWith(tool)) {
        return true;
      }
    }

    return false;
  }

  // 輔助方法：取得相依性統計
  getDependencyStats(packages: PackageInfo[]): {
    total: number;
    dependencies: number;
    devDependencies: number;
    transitive?: number;
    filtered?: number;
  } {
    const dependencies = packages.filter(pkg => pkg.type === 'dependency').length;
    const devDependencies = packages.filter(pkg => pkg.type === 'devDependency').length;
    const transitive = packages.filter(pkg => pkg.type === 'transitive').length;

    return {
      total: packages.length,
      dependencies,
      devDependencies,
      ...(transitive > 0 && { transitive })
    };
  }

  // 取得掃描配置建議
  getScanConfigRecommendation(totalPackages: number): ScanConfig {
    if (totalPackages < 50) {
      return DEFAULT_SCAN_CONFIGS['comprehensive'];
    } else if (totalPackages < 200) {
      return DEFAULT_SCAN_CONFIGS['balanced'];
    } else {
      return DEFAULT_SCAN_CONFIGS['fast'];
    }
  }

  // 估算掃描時間
  estimateScanTime(packages: PackageInfo[]): {
    estimatedMinutes: number;
    description: string;
  } {
    const count = packages.length;
    // NIST API 每個套件間隔 12 秒 + API 回應時間，再加上版本推薦 5 秒
    const mainScanTimePerPackage = 12; // 秒，對應 NIST API 的 REQUEST_DELAY
    const versionRecommendationTime = 5; // 秒，版本推薦服務的延遲
    const avgTimePerPackage = mainScanTimePerPackage + versionRecommendationTime; // 總共 17 秒/套件
    const totalSeconds = count * avgTimePerPackage;
    const minutes = Math.ceil(totalSeconds / 60);

    let description = '';
    if (minutes <= 3) {
      description = '快速掃描';
    } else if (minutes <= 10) {
      description = '中等掃描時間';
    } else if (minutes <= 30) {
      description = '長時間掃描';
    } else if (minutes <= 60) {
      description = '非常長的掃描時間';
    } else {
      description = '超長掃描時間（建議使用背景掃描）';
    }

    return {
      estimatedMinutes: minutes,
      description: `${description} (約 ${count} 個套件 × ${avgTimePerPackage} 秒 = ${minutes} 分鐘)`
    };
  }
}
