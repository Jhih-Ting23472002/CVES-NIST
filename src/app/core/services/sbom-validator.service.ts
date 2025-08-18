import { Injectable } from '@angular/core';

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  score: number; // 0-100 分數，表示符合標準的程度
}

@Injectable({
  providedIn: 'root'
})
export class SbomValidatorService {

  constructor() { }

  /**
   * 驗證 CycloneDX SBOM 格式
   */
  validateCycloneDX(sbom: any): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
      score: 100
    };

    // 檢查必要的根層級欄位
    this.checkRequiredField(sbom, 'bomFormat', result);
    this.checkRequiredField(sbom, 'specVersion', result);
    this.checkRequiredField(sbom, 'version', result);

    // 檢查 bomFormat 值
    if (sbom.bomFormat && sbom.bomFormat !== 'CycloneDX') {
      result.errors.push('bomFormat 必須為 "CycloneDX"');
      result.isValid = false;
    }

    // 檢查 specVersion 格式
    if (sbom.specVersion && !this.isValidSpecVersion(sbom.specVersion)) {
      result.errors.push(`不支援的 specVersion: ${sbom.specVersion}`);
      result.isValid = false;
    }

    // 檢查 metadata
    if (sbom.metadata) {
      this.validateCycloneDXMetadata(sbom.metadata, result);
    } else {
      result.warnings.push('建議包含 metadata 區段');
      result.score -= 10;
    }

    // 檢查 components
    if (sbom.components && Array.isArray(sbom.components)) {
      this.validateCycloneDXComponents(sbom.components, result);
    } else {
      result.warnings.push('沒有 components 或格式不正確');
      result.score -= 20;
    }

    // 檢查 vulnerabilities（如果存在）
    if (sbom.vulnerabilities && Array.isArray(sbom.vulnerabilities)) {
      this.validateCycloneDXVulnerabilities(sbom.vulnerabilities, result);
    }

    return result;
  }

  /**
   * 驗證 SPDX SBOM 格式
   */
  validateSPDX(sbom: any): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
      score: 100
    };

    // 檢查必要的根層級欄位
    this.checkRequiredField(sbom, 'spdxVersion', result);
    this.checkRequiredField(sbom, 'dataLicense', result);
    this.checkRequiredField(sbom, 'SPDXID', result);
    this.checkRequiredField(sbom, 'name', result);
    this.checkRequiredField(sbom, 'documentNamespace', result);

    // 檢查 SPDX 版本
    if (sbom.spdxVersion && !sbom.spdxVersion.match(/^SPDX-\d+\.\d+$/)) {
      result.errors.push(`無效的 spdxVersion 格式: ${sbom.spdxVersion}`);
      result.isValid = false;
    }

    // 檢查 dataLicense
    if (sbom.dataLicense && sbom.dataLicense !== 'CC0-1.0') {
      result.warnings.push(`dataLicense 建議使用 CC0-1.0，目前為: ${sbom.dataLicense}`);
      result.score -= 5;
    }

    // 檢查 SPDXID 格式
    if (sbom.SPDXID && !sbom.SPDXID.match(/^SPDXRef-[A-Za-z0-9.-]+$/)) {
      result.errors.push(`無效的 SPDXID 格式: ${sbom.SPDXID}`);
      result.isValid = false;
    }

    // 檢查 creationInfo
    if (sbom.creationInfo) {
      this.validateSPDXCreationInfo(sbom.creationInfo, result);
    } else {
      result.errors.push('缺少必要的 creationInfo 區段');
      result.isValid = false;
    }

    // 檢查 packages
    if (sbom.packages && Array.isArray(sbom.packages)) {
      this.validateSPDXPackages(sbom.packages, result);
    } else {
      result.warnings.push('沒有 packages 或格式不正確');
      result.score -= 20;
    }

    // 檢查 relationships
    if (sbom.relationships && Array.isArray(sbom.relationships)) {
      this.validateSPDXRelationships(sbom.relationships, result);
    } else {
      result.warnings.push('建議包含 relationships 區段以描述依賴關係');
      result.score -= 15;
    }

    return result;
  }

  /**
   * 通用 SBOM 品質檢查
   */
  validateSBOMQuality(sbom: any, format: 'cyclonedx' | 'spdx'): ValidationResult {
    const result = format === 'cyclonedx' ? 
      this.validateCycloneDX(sbom) : 
      this.validateSPDX(sbom);

    // 額外品質檢查
    this.performQualityChecks(sbom, format, result);

    return result;
  }

  // 私有方法

  private checkRequiredField(obj: any, field: string, result: ValidationResult): void {
    if (!obj.hasOwnProperty(field) || obj[field] === undefined || obj[field] === null) {
      result.errors.push(`缺少必要欄位: ${field}`);
      result.isValid = false;
      result.score -= 10;
    }
  }

  private isValidSpecVersion(version: string): boolean {
    // 支援的 CycloneDX 版本
    const supportedVersions = ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5'];
    return supportedVersions.includes(version);
  }

  private validateCycloneDXMetadata(metadata: any, result: ValidationResult): void {
    if (!metadata.timestamp) {
      result.warnings.push('metadata 中建議包含 timestamp');
      result.score -= 5;
    }

    if (!metadata.tools || !Array.isArray(metadata.tools) || metadata.tools.length === 0) {
      result.warnings.push('metadata 中建議包含 tools 資訊');
      result.score -= 5;
    }
  }

  private validateCycloneDXComponents(components: any[], result: ValidationResult): void {
    components.forEach((component, index) => {
      if (!component.type) {
        result.errors.push(`component[${index}] 缺少 type 欄位`);
        result.isValid = false;
      }

      if (!component.name) {
        result.errors.push(`component[${index}] 缺少 name 欄位`);
        result.isValid = false;
      }

      if (!component.version) {
        result.warnings.push(`component[${index}] (${component.name}) 缺少 version 欄位`);
        result.score -= 2;
      }

      if (!component.purl) {
        result.warnings.push(`component[${index}] (${component.name}) 建議包含 purl 欄位`);
        result.score -= 2;
      }

      // 檢查 licenses
      if (!component.licenses || !Array.isArray(component.licenses)) {
        result.warnings.push(`component[${index}] (${component.name}) 建議包含 licenses 資訊`);
        result.score -= 1;
      }
    });
  }

  private validateCycloneDXVulnerabilities(vulnerabilities: any[], result: ValidationResult): void {
    vulnerabilities.forEach((vuln, index) => {
      if (!vuln.id) {
        result.errors.push(`vulnerability[${index}] 缺少 id 欄位`);
        result.isValid = false;
      }

      if (!vuln.affects || !Array.isArray(vuln.affects)) {
        result.warnings.push(`vulnerability[${index}] 建議包含 affects 資訊`);
        result.score -= 2;
      }
    });
  }

  private validateSPDXCreationInfo(creationInfo: any, result: ValidationResult): void {
    if (!creationInfo.created) {
      result.errors.push('creationInfo 缺少 created 欄位');
      result.isValid = false;
    }

    if (!creationInfo.creators || !Array.isArray(creationInfo.creators)) {
      result.errors.push('creationInfo 缺少 creators 欄位');
      result.isValid = false;
    }
  }

  private validateSPDXPackages(packages: any[], result: ValidationResult): void {
    packages.forEach((pkg, index) => {
      if (!pkg.SPDXID) {
        result.errors.push(`package[${index}] 缺少 SPDXID 欄位`);
        result.isValid = false;
      }

      if (!pkg.name) {
        result.errors.push(`package[${index}] 缺少 name 欄位`);
        result.isValid = false;
      }

      if (!pkg.downloadLocation) {
        result.errors.push(`package[${index}] 缺少 downloadLocation 欄位`);
        result.isValid = false;
      }

      if (pkg.filesAnalyzed === undefined) {
        result.warnings.push(`package[${index}] (${pkg.name}) 建議明確設定 filesAnalyzed`);
        result.score -= 1;
      }

      if (!pkg.licenseConcluded) {
        result.warnings.push(`package[${index}] (${pkg.name}) 建議包含 licenseConcluded`);
        result.score -= 2;
      }

      if (!pkg.licenseDeclared) {
        result.warnings.push(`package[${index}] (${pkg.name}) 建議包含 licenseDeclared`);
        result.score -= 2;
      }
    });
  }

  private validateSPDXRelationships(relationships: any[], result: ValidationResult): void {
    relationships.forEach((rel, index) => {
      if (!rel.spdxElementId) {
        result.errors.push(`relationship[${index}] 缺少 spdxElementId 欄位`);
        result.isValid = false;
      }

      if (!rel.relatedSpdxElement) {
        result.errors.push(`relationship[${index}] 缺少 relatedSpdxElement 欄位`);
        result.isValid = false;
      }

      if (!rel.relationshipType) {
        result.errors.push(`relationship[${index}] 缺少 relationshipType 欄位`);
        result.isValid = false;
      }
    });
  }

  private performQualityChecks(sbom: any, format: string, result: ValidationResult): void {
    // 檢查整體資料完整性
    let componentCount = 0;
    let licensedComponents = 0;
    let componentsWithPurl = 0;

    if (format === 'cyclonedx' && sbom.components) {
      componentCount = sbom.components.length;
      licensedComponents = sbom.components.filter((c: any) => c.licenses && c.licenses.length > 0).length;
      componentsWithPurl = sbom.components.filter((c: any) => c.purl).length;
    } else if (format === 'spdx' && sbom.packages) {
      componentCount = sbom.packages.length - 1; // 扣除根套件
      licensedComponents = sbom.packages.filter((p: any) => 
        p.licenseConcluded && p.licenseConcluded !== 'NOASSERTION'
      ).length;
      componentsWithPurl = sbom.packages.filter((p: any) => 
        p.externalRefs && p.externalRefs.some((ref: any) => ref.referenceType === 'purl')
      ).length;
    }

    // 計算品質分數調整
    if (componentCount > 0) {
      const licenseRatio = licensedComponents / componentCount;
      const purlRatio = componentsWithPurl / componentCount;

      if (licenseRatio < 0.5) {
        result.warnings.push(`只有 ${Math.round(licenseRatio * 100)}% 的元件包含授權資訊`);
        result.score -= 15;
      } else if (licenseRatio < 0.8) {
        result.warnings.push(`只有 ${Math.round(licenseRatio * 100)}% 的元件包含授權資訊`);
        result.score -= 5;
      }

      if (purlRatio < 0.8) {
        result.warnings.push(`只有 ${Math.round(purlRatio * 100)}% 的元件包含 PURL 識別符`);
        result.score -= 10;
      }
    }

    // 檢查是否包含漏洞資訊
    const hasVulnerabilities = (format === 'cyclonedx' && sbom.vulnerabilities) ||
                              (format === 'spdx' && sbom.vulnerabilities);
    
    if (hasVulnerabilities) {
      result.score += 10; // 包含漏洞資訊加分
    }

    // 確保分數在 0-100 範圍內
    result.score = Math.max(0, Math.min(100, result.score));
  }

  /**
   * 取得驗證結果的可讀摘要
   */
  getValidationSummary(result: ValidationResult): string {
    if (result.isValid && result.score >= 90) {
      return '✅ 優秀：SBOM 格式完全符合標準且品質極佳';
    } else if (result.isValid && result.score >= 75) {
      return '✅ 良好：SBOM 格式符合標準，品質良好';
    } else if (result.isValid && result.score >= 60) {
      return '⚠️ 及格：SBOM 格式符合基本標準，但有改進空間';
    } else if (result.isValid) {
      return '⚠️ 基本：SBOM 格式符合最低標準，建議改進';
    } else {
      return '❌ 不合格：SBOM 格式不符合標準，需要修正';
    }
  }
}