import { Injectable } from '@angular/core';
import * as CDX from '@cyclonedx/cyclonedx-library';
import { PackageInfo, Vulnerability, VexStatus } from '../models/vulnerability.model';
import { buildNpmPurl, base64ToHex, getAdvisoryUrl, getAdvisorySourceName } from '../../shared/utils/sbom-utils';
import { parseNvdDate } from '../../shared/utils/date-utils';

export interface CycloneDxOptions {
  scanTimestamp?: Date;
  includeVulnerabilities?: boolean;
}

/**
 * 使用 OWASP 官方 @cyclonedx/cyclonedx-library 產生 CycloneDX 1.6 SBOM，
 * 由官方 Serializer 保證輸出符合官方 JSON schema。
 */
@Injectable({
  providedIn: 'root'
})
export class CycloneDxSbomService {

  /**
   * 產生 CycloneDX SBOM（序列化後的 JSON 字串）
   */
  generateBomJson(
    packages: PackageInfo[],
    scanResults: { packageName: string, vulnerabilities: Vulnerability[] }[],
    options: CycloneDxOptions = {}
  ): string {
    const bom = new CDX.Models.Bom();
    bom.serialNumber = `urn:uuid:${crypto.randomUUID()}`;
    bom.metadata.timestamp = options.scanTimestamp ?? new Date();
    bom.metadata.component = new CDX.Models.Component(
      CDX.Enums.ComponentType.Application, 'scanned-project'
    );
    bom.metadata.tools.components.add(new CDX.Models.Component(
      CDX.Enums.ComponentType.Application, 'cves-nist', { version: '1.0.0' }
    ));

    const componentMap = new Map<string, CDX.Models.Component>();
    for (const pkg of packages) {
      const component = this.buildComponent(pkg);
      bom.components.add(component);
      componentMap.set(pkg.name, component);
      if (pkg.packageKey) {
        componentMap.set(pkg.packageKey, component);
      }
      componentMap.set(`${pkg.name}@${pkg.version}`, component);
    }

    if (options.includeVulnerabilities) {
      for (const vuln of this.buildVulnerabilities(scanResults, componentMap)) {
        bom.vulnerabilities.add(vuln);
      }
    }

    const serializer = new CDX.Serialize.JsonSerializer(
      new CDX.Serialize.JSON.Normalize.Factory(CDX.Spec.Spec1dot6)
    );
    return serializer.serialize(bom, { space: 2 });
  }

  private buildComponent(pkg: PackageInfo): CDX.Models.Component {
    const purl = buildNpmPurl(pkg.name, pkg.version).toString();
    const component = new CDX.Models.Component(
      CDX.Enums.ComponentType.Library, pkg.name, {
        version: pkg.version,
        purl,
        scope: pkg.type === 'devDependency'
          ? CDX.Enums.ComponentScope.Optional
          : CDX.Enums.ComponentScope.Required
      }
    );
    component.bomRef.value = purl;

    if (pkg.description) {
      component.description = pkg.description;
    }

    // 授權優先序：分析結論 > 作者聲明 > package.json 原始值；查無則不填（不捏造）
    const license = this.buildLicense(pkg.licenseConcluded || pkg.licenseDeclared || pkg.license);
    if (license) {
      component.licenses.add(license);
    }
    if (pkg.licenseSource) {
      component.properties.add(new CDX.Models.Property('license:source', pkg.licenseSource));
    }

    if (pkg.integrity?.startsWith('sha512-')) {
      const hex = base64ToHex(pkg.integrity.slice('sha512-'.length));
      if (hex) {
        component.hashes.set(CDX.Enums.HashAlgorithm['SHA-512'], hex);
      }
    }

    component.externalReferences.add(new CDX.Models.ExternalReference(
      `https://www.npmjs.com/package/${pkg.name}`,
      CDX.Enums.ExternalReferenceType.Website
    ));
    if (pkg.resolved) {
      component.externalReferences.add(new CDX.Models.ExternalReference(
        pkg.resolved,
        CDX.Enums.ExternalReferenceType.Distribution
      ));
    }

    return component;
  }

  /**
   * 授權字串優先當 SPDX ID，其次當 SPDX expression，最後退為 named license。
   * 無授權資訊時回傳 null（不推測、不捏造）。
   */
  private buildLicense(licenseStr?: string): CDX.Models.License | null {
    if (!licenseStr) {
      return null;
    }
    const spdxId = CDX.SPDX.fixupSpdxId(licenseStr);
    if (spdxId) {
      return new CDX.Models.SpdxLicense(spdxId);
    }
    try {
      return new CDX.Models.LicenseExpression(licenseStr);
    } catch { /* 非合法 expression */ }
    return new CDX.Models.NamedLicense(licenseStr);
  }

  private buildVulnerabilities(
    scanResults: { packageName: string, vulnerabilities: Vulnerability[] }[],
    componentMap: Map<string, CDX.Models.Component>
  ): CDX.Models.Vulnerability.Vulnerability[] {
    // 依 CVE ID 合併，同一 CVE 影響多套件時合併 affects
    const vulnMap = new Map<string, CDX.Models.Vulnerability.Vulnerability>();

    for (const result of scanResults) {
      const component = componentMap.get(result.packageName);
      if (!component) {
        continue;
      }

      for (const vuln of result.vulnerabilities) {
        let cdxVuln = vulnMap.get(vuln.cveId);
        if (!cdxVuln) {
          cdxVuln = this.buildVulnerability(vuln);
          vulnMap.set(vuln.cveId, cdxVuln);
        }

        const alreadyAffected = Array.from(cdxVuln.affects)
          .some(a => a.ref === component.bomRef);
        if (!alreadyAffected) {
          const affect = new CDX.Models.Vulnerability.Affect(component.bomRef);
          if (component.version) {
            affect.versions.add(
              new CDX.Models.Vulnerability.AffectedSingleVersion(component.version)
            );
          }
          cdxVuln.affects.add(affect);
        }
      }
    }

    return Array.from(vulnMap.values());
  }

  private buildVulnerability(vuln: Vulnerability): CDX.Models.Vulnerability.Vulnerability {
    const cdxVuln = new CDX.Models.Vulnerability.Vulnerability({
      id: vuln.cveId,
      description: vuln.description,
      source: new CDX.Models.Vulnerability.Source({
        name: getAdvisorySourceName(vuln.cveId),
        url: getAdvisoryUrl(vuln.cveId)
      })
    });

    if (vuln.publishedDate) {
      cdxVuln.published = parseNvdDate(vuln.publishedDate);
    }
    if (vuln.lastModifiedDate) {
      cdxVuln.updated = parseNvdDate(vuln.lastModifiedDate);
    }

    cdxVuln.ratings.add(new CDX.Models.Vulnerability.Rating({
      score: vuln.cvssScore,
      severity: this.mapSeverity(vuln.severity),
      method: this.mapRatingMethod(vuln.cvssVector),
      vector: vuln.cvssVector
    }));

    if (vuln.fixedVersion) {
      cdxVuln.recommendation = `升級至 ${vuln.fixedVersion} 或更新版本`;
    }

    for (const ref of vuln.references) {
      cdxVuln.advisories.add(new CDX.Models.Vulnerability.Advisory(ref));
    }

    if (vuln.vexStatus) {
      cdxVuln.analysis = new CDX.Models.Vulnerability.Analysis({
        state: this.mapVexState(vuln.vexStatus),
        detail: vuln.vexJustification
      });
    }

    return cdxVuln;
  }

  private mapSeverity(severity: Vulnerability['severity']): CDX.Enums.Vulnerability.Severity {
    switch (severity) {
      case 'CRITICAL': return CDX.Enums.Vulnerability.Severity.Critical;
      case 'HIGH': return CDX.Enums.Vulnerability.Severity.High;
      case 'MEDIUM': return CDX.Enums.Vulnerability.Severity.Medium;
      case 'LOW': return CDX.Enums.Vulnerability.Severity.Low;
      case 'NONE': return CDX.Enums.Vulnerability.Severity.None;
      default: return CDX.Enums.Vulnerability.Severity.Unknown;
    }
  }

  private mapRatingMethod(cvssVector?: string): CDX.Enums.Vulnerability.RatingMethod {
    if (cvssVector?.startsWith('CVSS:4.0')) {
      return CDX.Enums.Vulnerability.RatingMethod.CVSSv4;
    }
    if (cvssVector?.startsWith('CVSS:3.1')) {
      return CDX.Enums.Vulnerability.RatingMethod.CVSSv31;
    }
    if (cvssVector?.startsWith('CVSS:3.0')) {
      return CDX.Enums.Vulnerability.RatingMethod.CVSSv3;
    }
    return CDX.Enums.Vulnerability.RatingMethod.CVSSv3;
  }

  private mapVexState(status: VexStatus): CDX.Enums.Vulnerability.AnalysisState {
    switch (status) {
      case 'not_affected': return CDX.Enums.Vulnerability.AnalysisState.NotAffected;
      case 'fixed': return CDX.Enums.Vulnerability.AnalysisState.Resolved;
      case 'under_investigation': return CDX.Enums.Vulnerability.AnalysisState.InTriage;
      case 'affected':
      default: return CDX.Enums.Vulnerability.AnalysisState.Exploitable;
    }
  }
}
