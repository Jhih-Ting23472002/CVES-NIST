import { TestBed } from '@angular/core/testing';
import { HttpClient } from '@angular/common/http';
import { of, throwError } from 'rxjs';
import { NistApiService } from './nist-api.service';
import { CacheService } from './cache.service';
import { LocalScanService } from './local-scan.service';
import { OsvApiService } from './osv-api.service';
import { VulnerabilityMergeService } from './vulnerability-merge.service';
import { PackageInfo, Vulnerability } from '../models/vulnerability.model';

describe('NistApiService OSV-only 快速掃描', () => {
  let service: NistApiService;
  let localScanSpy: jasmine.SpyObj<LocalScanService>;
  let osvSpy: jasmine.SpyObj<OsvApiService>;

  const packages: PackageInfo[] = [
    { name: 'lodash', version: '4.17.20', type: 'dependency' },
    { name: 'axios', version: '0.21.0', type: 'dependency' }
  ];

  const osvVuln: Vulnerability = {
    cveId: 'CVE-2021-23337',
    description: 'Command injection in lodash',
    severity: 'HIGH',
    cvssScore: 7.2,
    publishedDate: '2021-02-15',
    lastModifiedDate: '2021-02-15',
    references: [],
    affectedVersions: ['<4.17.21'],
    fixedVersion: '4.17.21',
    dataSource: 'osv'
  };

  beforeEach(() => {
    localScanSpy = jasmine.createSpyObj('LocalScanService', ['isDatabaseReady']);
    osvSpy = jasmine.createSpyObj('OsvApiService', ['searchBatch']);

    TestBed.configureTestingModule({
      providers: [
        NistApiService,
        VulnerabilityMergeService,
        { provide: HttpClient, useValue: jasmine.createSpyObj('HttpClient', ['get', 'post']) },
        { provide: CacheService, useValue: jasmine.createSpyObj('CacheService', ['get', 'set']) },
        { provide: LocalScanService, useValue: localScanSpy },
        { provide: OsvApiService, useValue: osvSpy }
      ]
    });

    service = TestBed.inject(NistApiService);
    // 本地資料庫未就緒 → 觸發 OSV-only 快速路徑
    localScanSpy.isDatabaseReady.and.returnValue(of(false));
  });

  afterEach(() => {
    service.ngOnDestroy();
  });

  it('應逐筆發出 packageResult 事件並以 result 收尾（背景掃描依賴 packageResult 累積結果）', (done) => {
    const resultMap = new Map<string, Vulnerability[]>([['lodash@4.17.20', [osvVuln]]]);
    osvSpy.searchBatch.and.returnValue(of(resultMap));

    const events: any[] = [];
    service.searchMultiplePackagesWithProgressResumable(packages, 0, packages.length).subscribe({
      next: e => events.push(e),
      complete: () => {
        const pkgEvents = events.filter(e => e.type === 'packageResult');
        expect(pkgEvents.length).toBe(2);
        expect(pkgEvents[0].packageIndex).toBe(0);
        expect(pkgEvents[0].packageResult.packageName).toBe('lodash@4.17.20');
        expect(pkgEvents[0].packageResult.vulnerabilities.length).toBe(1);
        expect(pkgEvents[1].packageIndex).toBe(1);
        expect(pkgEvents[1].packageResult.packageName).toBe('axios@0.21.0');
        expect(pkgEvents[1].packageResult.vulnerabilities.length).toBe(0);

        const result = events.find(e => e.type === 'result');
        expect(result).toBeTruthy();
        expect(result.results.length).toBe(2);
        done();
      }
    });
  });

  it('OSV 查詢失敗時應回退到 API 掃描（前景路徑）', (done) => {
    osvSpy.searchBatch.and.returnValue(throwError(() => new Error('OSV.dev unreachable')));
    const fallbackSpy = spyOn<any>(service, 'performApiBatchScan')
      .and.returnValue(of({ type: 'result', results: [] }));

    service.searchMultiplePackagesWithProgress(packages).subscribe({
      complete: () => {
        expect(fallbackSpy).toHaveBeenCalledWith(packages);
        done();
      }
    });
  });

  it('OSV 查詢失敗時應回退到 API 掃描並保留斷點索引（背景路徑）', (done) => {
    osvSpy.searchBatch.and.returnValue(throwError(() => new Error('OSV.dev unreachable')));
    const fallbackSpy = spyOn<any>(service, 'performApiBatchScanResumable')
      .and.returnValue(of({ type: 'result', results: [] }));

    service.searchMultiplePackagesWithProgressResumable(packages, 5, 10).subscribe({
      complete: () => {
        expect(fallbackSpy).toHaveBeenCalledWith(packages, 5, 10);
        done();
      }
    });
  });

  it('OSV-only 查詢應要求 searchBatch 傳播錯誤（propagateErrors）', (done) => {
    const resultMap = new Map<string, Vulnerability[]>();
    osvSpy.searchBatch.and.returnValue(of(resultMap));

    service.searchMultiplePackagesWithProgress(packages).subscribe({
      complete: () => {
        expect(osvSpy.searchBatch).toHaveBeenCalledWith(packages, { propagateErrors: true });
        done();
      }
    });
  });
});
