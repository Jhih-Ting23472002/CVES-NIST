import { TestBed } from '@angular/core/testing';
import { CycloneDxSbomService } from './cyclonedx-sbom.service';
import { PackageInfo, Vulnerability } from '../models/vulnerability.model';

describe('CycloneDxSbomService', () => {
  let service: CycloneDxSbomService;

  const packages: PackageInfo[] = [
    { name: 'lodash', version: '4.17.20', type: 'dependency', license: 'MIT' },
    { name: '@angular/core', version: '17.3.0', type: 'dependency', license: 'MIT' },
    { name: 'jest', version: '29.0.0', type: 'devDependency', license: '(MIT OR Apache-2.0)' },
    { name: 'unknown-pkg', version: '1.0.0', type: 'dependency' } // 無授權資訊
  ];

  const vuln: Vulnerability = {
    cveId: 'CVE-2021-23337',
    description: 'Command injection in lodash',
    severity: 'HIGH',
    cvssScore: 7.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
    publishedDate: '2021-02-15T00:00:00Z',
    lastModifiedDate: '2021-03-01T00:00:00Z',
    references: ['https://github.com/advisories/GHSA-35jh-r3h4-6jhm'],
    affectedVersions: ['<4.17.21'],
    fixedVersion: '4.17.21'
  };

  const scanResults = [
    { packageName: 'lodash', vulnerabilities: [vuln] },
    { packageName: '@angular/core', vulnerabilities: [] }
  ];

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(CycloneDxSbomService);
  });

  function generate(includeVulns = false): any {
    return JSON.parse(service.generateBomJson(packages, scanResults, {
      scanTimestamp: new Date('2026-07-09T00:00:00Z'),
      includeVulnerabilities: includeVulns
    }));
  }

  it('產生合規的根層級欄位', () => {
    const sbom = generate();
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.6');
    expect(sbom.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
    expect(sbom.metadata.timestamp).toBe('2026-07-09T00:00:00.000Z');
    expect(sbom.components.length).toBe(4);
  });

  it('scoped 套件的 purl 正確編碼', () => {
    const sbom = generate();
    const ng = sbom.components.find((c: any) => c.name === '@angular/core');
    expect(ng.purl).toBe('pkg:npm/%40angular/core@17.3.0');
  });

  it('license 只填 id 或 name 其一，不同時存在', () => {
    const sbom = generate();
    for (const c of sbom.components) {
      for (const entry of c.licenses ?? []) {
        if (entry.license) {
          expect(entry.license.id && entry.license.name).toBeFalsy();
        }
      }
    }
    // SPDX ID 應走 id
    const lodash = sbom.components.find((c: any) => c.name === 'lodash');
    expect(lodash.licenses[0].license.id).toBe('MIT');
    // 複合授權應走 expression
    const jest = sbom.components.find((c: any) => c.name === 'jest');
    expect(jest.licenses[0].expression).toBe('(MIT OR Apache-2.0)');
  });

  it('無授權資訊時不捏造 license', () => {
    const sbom = generate();
    const unknown = sbom.components.find((c: any) => c.name === 'unknown-pkg');
    expect(unknown.licenses ?? []).toEqual([]);
  });

  it('devDependency 對應 scope optional', () => {
    const sbom = generate();
    const jest = sbom.components.find((c: any) => c.name === 'jest');
    expect(jest.scope).toBe('optional');
    const lodash = sbom.components.find((c: any) => c.name === 'lodash');
    expect(lodash.scope).toBe('required');
  });

  it('預設不含 vulnerabilities', () => {
    const sbom = generate(false);
    expect(sbom.vulnerabilities).toBeUndefined();
  });

  it('包含漏洞時產生合規的 vulnerability 條目', () => {
    const sbom = generate(true);
    expect(sbom.vulnerabilities.length).toBe(1);
    const v = sbom.vulnerabilities[0];
    expect(v.id).toBe('CVE-2021-23337');
    expect(v.ratings[0].severity).toBe('high'); // 小寫 enum
    expect(v.ratings[0].method).toBe('CVSSv31'); // 由 vector 推導
    expect(v.ratings[0].score).toBe(7.2);
    // affects.ref 必須對應 component 的 bom-ref
    const lodash = sbom.components.find((c: any) => c.name === 'lodash');
    expect(v.affects[0].ref).toBe(lodash['bom-ref']);
    // 參考連結放 advisories 而非 references
    expect(v.advisories[0].url).toBe('https://github.com/advisories/GHSA-35jh-r3h4-6jhm');
    expect(v.references ?? []).toEqual([]);
  });

  it('VEX 狀態對應到 analysis.state', () => {
    const vexVuln: Vulnerability = { ...vuln, vexStatus: 'not_affected', vexJustification: 'dev only' };
    const json = JSON.parse(service.generateBomJson(
      packages,
      [{ packageName: 'lodash', vulnerabilities: [vexVuln] }],
      { includeVulnerabilities: true }
    ));
    expect(json.vulnerabilities[0].analysis.state).toBe('not_affected');
  });

  it('授權優先序為 concluded > declared > license', () => {
    const pkg: PackageInfo = {
      name: 'x', version: '1.0.0', type: 'dependency',
      license: 'MIT', licenseDeclared: 'ISC', licenseConcluded: 'Apache-2.0'
    };
    const json = JSON.parse(service.generateBomJson([pkg], [], {}));
    expect(json.components[0].licenses[0].license.id).toBe('Apache-2.0');
  });

  it('integrity 轉為 hex 格式的 SHA-512 hash', () => {
    const pkg: PackageInfo = {
      name: 'x', version: '1.0.0', type: 'dependency',
      // 'abc' 的 SHA-512（base64）
      integrity: 'sha512-3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EqeQk6irqXHi7htmrAw=='
    };
    const json = JSON.parse(service.generateBomJson([pkg], [], {}));
    const hash = json.components[0].hashes.find((h: any) => h.alg === 'SHA-512');
    expect(hash.content).toMatch(/^[0-9a-f]{128}$/);
    expect(hash.content.startsWith('ddaf35a193617aba')).toBeTrue();
  });

  it('同一 CVE 影響多套件時合併 affects', () => {
    const json = JSON.parse(service.generateBomJson(
      packages,
      [
        { packageName: 'lodash', vulnerabilities: [vuln] },
        { packageName: 'jest', vulnerabilities: [vuln] }
      ],
      { includeVulnerabilities: true }
    ));
    expect(json.vulnerabilities.length).toBe(1);
    expect(json.vulnerabilities[0].affects.length).toBe(2);
  });
});
