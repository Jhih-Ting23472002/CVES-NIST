import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { OsvApiService } from './osv-api.service';
import { CacheService } from './cache.service';
import { OsvVulnerability } from '../interfaces/osv-api.interface';
import { PackageInfo } from '../models/vulnerability.model';

describe('OsvApiService', () => {
  let service: OsvApiService;
  let httpMock: HttpTestingController;
  let cacheService: CacheService;

  const mockOsvVuln: OsvVulnerability = {
    id: 'GHSA-1234-abcd-efgh',
    summary: 'Test vulnerability',
    details: 'Detailed description',
    aliases: ['CVE-2023-12345'],
    modified: '2023-10-01T00:00:00Z',
    published: '2023-09-01T00:00:00Z',
    severity: [
      { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' }
    ],
    affected: [
      {
        package: { name: 'test-pkg', ecosystem: 'npm' },
        ranges: [
          {
            type: 'SEMVER',
            events: [
              { introduced: '0' },
              { fixed: '1.2.3' }
            ]
          }
        ]
      }
    ],
    references: [
      { type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-1234-abcd-efgh' }
    ]
  };

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule]
    });
    service = TestBed.inject(OsvApiService);
    httpMock = TestBed.inject(HttpTestingController);
    cacheService = TestBed.inject(CacheService);
    cacheService.clear();
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('name and priority', () => {
    it('should have name OSV.dev', () => {
      expect(service.name).toBe('OSV.dev');
    });

    it('should have priority 2', () => {
      expect(service.priority).toBe(2);
    });
  });

  describe('transformOsvToVulnerability', () => {
    it('should extract CVE ID from aliases', () => {
      const result = service.transformOsvToVulnerability(mockOsvVuln);
      expect(result.cveId).toBe('CVE-2023-12345');
    });

    it('should use OSV ID when no CVE alias present', () => {
      const vuln: OsvVulnerability = { ...mockOsvVuln, aliases: [] };
      const result = service.transformOsvToVulnerability(vuln);
      expect(result.cveId).toBe('GHSA-1234-abcd-efgh');
    });

    it('should use OSV ID when aliases is undefined', () => {
      const vuln: OsvVulnerability = { ...mockOsvVuln, aliases: undefined };
      const result = service.transformOsvToVulnerability(vuln);
      expect(result.cveId).toBe('GHSA-1234-abcd-efgh');
    });

    it('should set dataSource to osv', () => {
      const result = service.transformOsvToVulnerability(mockOsvVuln);
      expect(result.dataSource).toBe('osv');
    });

    it('should extract description from summary', () => {
      const result = service.transformOsvToVulnerability(mockOsvVuln);
      expect(result.description).toBe('Test vulnerability');
    });

    it('should fall back to details when summary is absent', () => {
      const vuln: OsvVulnerability = { ...mockOsvVuln, summary: undefined };
      const result = service.transformOsvToVulnerability(vuln);
      expect(result.description).toBe('Detailed description');
    });

    it('should parse fixedVersion from SEMVER range', () => {
      const result = service.transformOsvToVulnerability(mockOsvVuln);
      expect(result.fixedVersion).toBe('1.2.3');
    });

    it('should include affectedVersions', () => {
      const result = service.transformOsvToVulnerability(mockOsvVuln);
      expect(result.affectedVersions.length).toBeGreaterThan(0);
    });

    it('should map references', () => {
      const result = service.transformOsvToVulnerability(mockOsvVuln);
      expect(result.references).toContain('https://github.com/advisories/GHSA-1234-abcd-efgh');
    });

    it('should set publishedDate from published', () => {
      const result = service.transformOsvToVulnerability(mockOsvVuln);
      expect(result.publishedDate).toBe('2023-09-01T00:00:00Z');
    });

    it('should fallback to modified when published is absent', () => {
      const vuln: OsvVulnerability = { ...mockOsvVuln, published: undefined };
      const result = service.transformOsvToVulnerability(vuln);
      expect(result.publishedDate).toBe('2023-10-01T00:00:00Z');
    });

    it('should return NONE severity when no severity info', () => {
      const vuln: OsvVulnerability = { ...mockOsvVuln, severity: [] };
      const result = service.transformOsvToVulnerability(vuln);
      expect(result.severity).toBe('NONE');
      expect(result.cvssScore).toBe(0);
    });

    it('should ignore non-npm ecosystem affected entries', () => {
      const vuln: OsvVulnerability = {
        ...mockOsvVuln,
        affected: [
          {
            package: { name: 'test-pkg', ecosystem: 'PyPI' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }]
          }
        ]
      };
      const result = service.transformOsvToVulnerability(vuln);
      expect(result.fixedVersion).toBeUndefined();
      expect(result.affectedVersions.length).toBe(0);
    });
  });

  describe('searchVulnerabilities', () => {
    it('should return vulnerabilities from OSV API', (done) => {
      service.searchVulnerabilities('test-pkg', '1.0.0').subscribe(vulns => {
        expect(vulns.length).toBe(1);
        expect(vulns[0].cveId).toBe('CVE-2023-12345');
        done();
      });

      const req = httpMock.expectOne('https://api.osv.dev/v1/query');
      expect(req.request.method).toBe('POST');
      req.flush({ vulns: [mockOsvVuln] });
    });

    it('should return empty array on API error', (done) => {
      service.searchVulnerabilities('test-pkg', '1.0.0').subscribe(vulns => {
        expect(vulns).toEqual([]);
        done();
      });

      const req = httpMock.expectOne('https://api.osv.dev/v1/query');
      req.error(new ErrorEvent('Network error'));
    });

    it('should return cached results on second call', (done) => {
      service.searchVulnerabilities('test-pkg', '1.0.0').subscribe(() => {
        service.searchVulnerabilities('test-pkg', '1.0.0').subscribe(vulns => {
          expect(vulns.length).toBe(1);
          done();
        });
        // No second HTTP request expected
        httpMock.expectNone('https://api.osv.dev/v1/query');
      });

      const req = httpMock.expectOne('https://api.osv.dev/v1/query');
      req.flush({ vulns: [mockOsvVuln] });
    });

    it('should return empty array when no vulns in response', (done) => {
      service.searchVulnerabilities('safe-pkg', '1.0.0').subscribe(vulns => {
        expect(vulns).toEqual([]);
        done();
      });

      const req = httpMock.expectOne('https://api.osv.dev/v1/query');
      req.flush({});
    });
  });

  describe('searchBatch', () => {
    const packages: PackageInfo[] = [
      { name: 'test-pkg', version: '1.0.0', type: 'dependency' },
      { name: 'safe-pkg', version: '2.0.0', type: 'dependency' }
    ];

    it('should return empty map for empty packages', (done) => {
      service.searchBatch([]).subscribe(result => {
        expect(result.size).toBe(0);
        done();
      });
    });

    it('should batch query all packages', (done) => {
      service.searchBatch(packages).subscribe(resultMap => {
        expect(resultMap.size).toBe(2);
        done();
      });

      const req = httpMock.expectOne('https://api.osv.dev/v1/querybatch');
      expect(req.request.method).toBe('POST');
      expect(req.request.body.queries.length).toBe(2);
      req.flush({
        results: [
          { vulns: [mockOsvVuln] },
          { vulns: [] }
        ]
      });
    });

    it('should return partial cached + new API results', (done) => {
      // Pre-cache first package
      cacheService.set('osv:test-pkg@1.0.0', [service.transformOsvToVulnerability(mockOsvVuln)]);

      service.searchBatch(packages).subscribe(resultMap => {
        expect(resultMap.size).toBe(2);
        done();
      });

      // Only safe-pkg should be queried
      const req = httpMock.expectOne('https://api.osv.dev/v1/querybatch');
      expect(req.request.body.queries.length).toBe(1);
      expect(req.request.body.queries[0].package.name).toBe('safe-pkg');
      req.flush({ results: [{ vulns: [] }] });
    });

    it('should return existing cached results on API error', (done) => {
      service.searchBatch(packages).subscribe(resultMap => {
        expect(resultMap.size).toBe(0); // No cache, API failed
        done();
      });

      const req = httpMock.expectOne('https://api.osv.dev/v1/querybatch');
      req.error(new ErrorEvent('Network error'));
    });
  });
});
