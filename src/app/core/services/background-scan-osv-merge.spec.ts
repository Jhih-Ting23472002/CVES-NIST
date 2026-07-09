import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { BackgroundScanService } from './background-scan.service';
import { NistApiService } from './nist-api.service';
import { FileParserService } from './file-parser.service';
import { PackageInfo, ScanConfig, DEFAULT_SCAN_CONFIGS, Vulnerability } from '../models/vulnerability.model';

describe('BackgroundScanService - 背景任務結果應保留 OSV 合併資料', () => {
  let service: BackgroundScanService;
  let nistApiServiceSpy: jasmine.SpyObj<NistApiService>;

  const mockPackages: PackageInfo[] = [
    { name: 'lodash', version: '4.17.20', type: 'dependency' },
    { name: 'axios', version: '0.21.0', type: 'dependency' }
  ];

  const mockConfig: ScanConfig = DEFAULT_SCAN_CONFIGS['balanced'];

  const nistOnlyVuln: Vulnerability = {
    cveId: 'CVE-2021-23337',
    description: 'NIST description',
    severity: 'HIGH',
    cvssScore: 7.2,
    publishedDate: '2021-02-15',
    lastModifiedDate: '2021-02-15',
    references: [],
    affectedVersions: [],
    dataSource: 'nist'
  };

  const mergedHybridVuln: Vulnerability = {
    ...nistOnlyVuln,
    description: 'OSV description',
    fixedVersion: '4.17.21',
    dataSource: 'hybrid'
  };

  beforeEach(() => {
    localStorage.removeItem('cve_background_scan_state');

    const nistApiSpy = jasmine.createSpyObj('NistApiService', [
      'searchMultiplePackagesWithProgressResumable'
    ]);
    const fileParserSpy = jasmine.createSpyObj('FileParserService', ['estimateScanTime']);
    fileParserSpy.estimateScanTime.and.returnValue({ estimatedMinutes: 1, description: '' });

    TestBed.configureTestingModule({
      providers: [
        BackgroundScanService,
        { provide: NistApiService, useValue: nistApiSpy },
        { provide: FileParserService, useValue: fileParserSpy }
      ]
    });

    service = TestBed.inject(BackgroundScanService);
    nistApiServiceSpy = TestBed.inject(NistApiService) as jasmine.SpyObj<NistApiService>;
  });

  afterEach(() => {
    localStorage.removeItem('cve_background_scan_state');
  });

  it('result 事件帶有 OSV 合併結果時，應以其覆蓋 packageResult 累積的同名結果', async () => {
    // 模擬本地掃描路徑：packageResult 逐筆回報「未合併」的 NIST 結果，
    // 最終 result 事件才帶有 OSV 合併後（hybrid）的完整結果
    nistApiServiceSpy.searchMultiplePackagesWithProgressResumable.and.returnValue(
      of(
        {
          type: 'packageResult' as const,
          packageResult: { packageName: 'lodash@4.17.20', vulnerabilities: [nistOnlyVuln] },
          packageIndex: 0
        },
        {
          type: 'packageResult' as const,
          packageResult: { packageName: 'axios@0.21.0', vulnerabilities: [] },
          packageIndex: 1
        },
        {
          type: 'result' as const,
          results: [
            { packageName: 'lodash@4.17.20', vulnerabilities: [mergedHybridVuln] },
            { packageName: 'axios@0.21.0', vulnerabilities: [] }
          ]
        }
      )
    );

    const taskId = service.createScanTask('測試任務', mockPackages, mockConfig, true);
    await new Promise(resolve => setTimeout(resolve, 100));

    const task = service.getTask(taskId);
    expect(task?.status).toBe('completed');
    expect(task?.results?.length).toBe(2);

    const lodashResult = task?.results?.find(r => r.packageName === 'lodash@4.17.20');
    expect(lodashResult?.vulnerabilities[0].dataSource).toBe('hybrid');
    expect(lodashResult?.vulnerabilities[0].description).toBe('OSV description');
    expect(lodashResult?.vulnerabilities[0].fixedVersion).toBe('4.17.21');
  });

  it('掃描來源重複發出 result 時，已完成任務不應重複（moveToCompleted 冪等）', async () => {
    // 回歸測試：isReady$（永不結束的 BehaviorSubject）重發值會讓 switchMap 重跑掃描，
    // 使同一 task 的 result 事件出現多次。moveToCompleted 必須以 id 去重，避免重複列。
    nistApiServiceSpy.searchMultiplePackagesWithProgressResumable.and.returnValue(
      of(
        {
          type: 'result' as const,
          results: [{ packageName: 'lodash@4.17.20', vulnerabilities: [] }]
        },
        {
          type: 'result' as const,
          results: [{ packageName: 'lodash@4.17.20', vulnerabilities: [] }]
        }
      )
    );

    const taskId = service.createScanTask('重複任務', mockPackages, mockConfig, true);
    await new Promise(resolve => setTimeout(resolve, 100));

    let completedTasks: any[] = [];
    service.state$.subscribe(s => (completedTasks = s.completedTasks)).unsubscribe();
    expect(completedTasks.filter(t => t.id === taskId).length).toBe(1);
  });

  it('斷點續掃時，result 只涵蓋本次掃描的套件，不應弄丟先前已保存的結果', async () => {
    nistApiServiceSpy.searchMultiplePackagesWithProgressResumable.and.returnValue(
      of(
        {
          type: 'packageResult' as const,
          packageResult: { packageName: 'axios@0.21.0', vulnerabilities: [] },
          packageIndex: 0
        },
        {
          type: 'result' as const,
          results: [{ packageName: 'axios@0.21.0', vulnerabilities: [] }]
        }
      )
    );

    const taskId = service.createScanTask('測試任務', mockPackages, mockConfig, false);
    const task = service.getTask(taskId);
    // 模擬前一次執行已掃完第一個套件
    task!.intermediateResults = [
      { packageName: 'lodash@4.17.20', vulnerabilities: [mergedHybridVuln] }
    ];
    task!.lastScannedIndex = 0;
    task!.status = 'paused';

    service.startScanTask(taskId);
    await new Promise(resolve => setTimeout(resolve, 100));

    const completed = service.getTask(taskId);
    expect(completed?.status).toBe('completed');
    expect(completed?.results?.length).toBe(2);
    const lodashResult = completed?.results?.find(r => r.packageName === 'lodash@4.17.20');
    expect(lodashResult?.vulnerabilities[0].dataSource).toBe('hybrid');
  });
});
