import { TestBed } from '@angular/core/testing';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { SpdxSbomService } from './spdx-sbom.service';
import { PackageInfo, Vulnerability } from '../models/vulnerability.model';
import * as spdxSchema from '../schemas/spdx-2.3-schema.json';

describe('SpdxSbomService', () => {
  let service: SpdxSbomService;

  const packages: PackageInfo[] = [
    {
      name: 'lodash', version: '4.17.20', type: 'dependency', license: 'MIT',
      integrity: 'sha512-3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EqeQk6irqXHi7htmrAw==',
      resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz'
    },
    { name: '@angular/core', version: '17.3.0', type: 'dependency', licenseConcluded: 'MIT', licenseDeclared: 'MIT' },
    { name: 'jest', version: '29.0.0', type: 'devDependency', license: '(MIT OR Apache-2.0)' },
    { name: 'weird', version: '1.0.0', type: 'transitive', license: 'SEE LICENSE IN LICENSE' }
  ];

  const vuln: Vulnerability = {
    cveId: 'CVE-2021-23337',
    description: 'Command injection in lodash',
    severity: 'HIGH',
    cvssScore: 7.2,
    publishedDate: '2021-02-15T00:00:00Z',
    lastModifiedDate: '2021-03-01T00:00:00Z',
    references: [],
    affectedVersions: []
  };

  const scanResults = [
    { packageName: 'lodash', vulnerabilities: [vuln] },
    { packageName: 'jest', vulnerabilities: [] }
  ];

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(SpdxSbomService);
  });

  function generate(includeVulns = false): any {
    return JSON.parse(service.generateSbomJson(packages, scanResults, {
      scanTimestamp: new Date('2026-07-09T00:00:00Z'),
      includeVulnerabilities: includeVulns
    }));
  }

  it('通過 SPDX 2.3 官方 JSON schema 驗證', () => {
    const ajv = new Ajv({ strict: false, allErrors: true });
    addFormats(ajv);
    const validate = ajv.compile(spdxSchema as any);
    const sbom = generate(true);
    const valid = validate(sbom);
    expect(valid).withContext(JSON.stringify(validate.errors, null, 2)).toBeTrue();
  });

  it('根層級欄位正確', () => {
    const sbom = generate();
    expect(sbom.spdxVersion).toBe('SPDX-2.3');
    expect(sbom.dataLicense).toBe('CC0-1.0');
    expect(sbom.SPDXID).toBe('SPDXRef-DOCUMENT');
    expect(sbom.documentNamespace).toMatch(/^https:\/\/.+[0-9a-f-]{36}$/);
    expect(sbom.creationInfo.created).toBe('2026-07-09T00:00:00Z');
    expect(sbom.creationInfo.creators).toEqual(['Tool: cves-nist-1.0.0']);
  });

  it('套件使用 versionInfo 而非 version', () => {
    const sbom = generate();
    const lodash = sbom.packages.find((p: any) => p.name === 'lodash');
    expect(lodash.versionInfo).toBe('4.17.20');
    expect(lodash.version).toBeUndefined();
  });

  it('不含非標準的頂層 vulnerabilities 欄位', () => {
    const sbom = generate(true);
    expect(sbom.vulnerabilities).toBeUndefined();
  });

  it('漏洞以 SECURITY externalRef 附在受影響套件上', () => {
    const sbom = generate(true);
    const lodash = sbom.packages.find((p: any) => p.name === 'lodash');
    const secRefs = lodash.externalRefs.filter((r: any) => r.referenceCategory === 'SECURITY');
    expect(secRefs.length).toBe(1);
    expect(secRefs[0].referenceType).toBe('advisory');
    expect(secRefs[0].referenceLocator).toBe('https://nvd.nist.gov/vuln/detail/CVE-2021-23337');
    // 未含漏洞時不附
    const jest = sbom.packages.find((p: any) => p.name === 'jest');
    expect(jest.externalRefs.some((r: any) => r.referenceCategory === 'SECURITY')).toBeFalse();
  });

  it('GHSA/OSV 編號的 SECURITY externalRef 連到 osv.dev', () => {
    const ghsaVuln: Vulnerability = { ...vuln, cveId: 'GHSA-35jh-r3h4-6jhm' };
    const sbom = JSON.parse(service.generateSbomJson(
      packages,
      [{ packageName: 'lodash', vulnerabilities: [ghsaVuln] }],
      { includeVulnerabilities: true }
    ));
    const lodash = sbom.packages.find((p: any) => p.name === 'lodash');
    const secRefs = lodash.externalRefs.filter((r: any) => r.referenceCategory === 'SECURITY');
    expect(secRefs[0].referenceLocator).toBe('https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm');
  });

  it('purl 使用 PACKAGE-MANAGER 分類（連字號）', () => {
    const sbom = generate();
    const ng = sbom.packages.find((p: any) => p.name === '@angular/core');
    const purlRef = ng.externalRefs.find((r: any) => r.referenceType === 'purl');
    expect(purlRef.referenceCategory).toBe('PACKAGE-MANAGER');
    expect(purlRef.referenceLocator).toBe('pkg:npm/%40angular/core@17.3.0');
  });

  it('license 合法 SPDX 表達式才填，否則 NOASSERTION、不捏造', () => {
    const sbom = generate();
    const lodash = sbom.packages.find((p: any) => p.name === 'lodash');
    expect(lodash.licenseDeclared).toBe('MIT');
    const jest = sbom.packages.find((p: any) => p.name === 'jest');
    expect(jest.licenseDeclared).toBe('(MIT OR Apache-2.0)');
    const weird = sbom.packages.find((p: any) => p.name === 'weird');
    expect(weird.licenseDeclared).toBe('NOASSERTION');
    expect(weird.licenseConcluded).toBe('NOASSERTION');
  });

  it('supplier 與 copyrightText 不捏造', () => {
    const sbom = generate();
    for (const p of sbom.packages.filter((p: any) => p.SPDXID !== 'SPDXRef-Package-root')) {
      expect(p.supplier ?? 'NOASSERTION').toBe('NOASSERTION');
      expect(p.copyrightText ?? 'NOASSERTION').toBe('NOASSERTION');
      expect(p.originator).toBeUndefined();
    }
  });

  it('devDependency 使用 DEV_DEPENDENCY_OF 關係', () => {
    const sbom = generate();
    const jestId = sbom.packages.find((p: any) => p.name === 'jest').SPDXID;
    const rel = sbom.relationships.find((r: any) =>
      r.spdxElementId === jestId && r.relationshipType === 'DEV_DEPENDENCY_OF');
    expect(rel.relatedSpdxElement).toBe('SPDXRef-Package-root');
    // 一般依賴仍為 DEPENDS_ON
    const lodashId = sbom.packages.find((p: any) => p.name === 'lodash').SPDXID;
    expect(sbom.relationships.some((r: any) =>
      r.relatedSpdxElement === lodashId && r.relationshipType === 'DEPENDS_ON')).toBeTrue();
  });

  it('integrity 轉為 hex 格式的 SHA512 checksum', () => {
    const sbom = generate();
    const lodash = sbom.packages.find((p: any) => p.name === 'lodash');
    expect(lodash.checksums[0].algorithm).toBe('SHA512');
    expect(lodash.checksums[0].checksumValue).toMatch(/^[0-9a-f]{128}$/);
  });
});
