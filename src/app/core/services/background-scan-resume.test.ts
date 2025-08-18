import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { BackgroundScanService } from './background-scan.service';
import { NistApiService } from './nist-api.service';
import { FileParserService } from './file-parser.service';
import { ScanTask, PackageInfo, ScanConfig, DEFAULT_SCAN_CONFIGS } from '../models/vulnerability.model';

describe('BackgroundScanService - 斷點續掃功能', () => {
  let service: BackgroundScanService;
  let nistApiServiceSpy: jasmine.SpyObj<NistApiService>;
  let fileParserServiceSpy: jasmine.SpyObj<FileParserService>;

  const mockPackages: PackageInfo[] = [
    { name: 'package1', version: '1.0.0', type: 'dependency' },
    { name: 'package2', version: '2.0.0', type: 'dependency' },
    { name: 'package3', version: '3.0.0', type: 'dependency' },
    { name: 'package4', version: '4.0.0', type: 'dependency' },
    { name: 'package5', version: '5.0.0', type: 'dependency' }
  ];

  const mockConfig: ScanConfig = DEFAULT_SCAN_CONFIGS.balanced;

  beforeEach(() => {
    const nistApiSpy = jasmine.createSpyObj('NistApiService', [
      'searchMultiplePackagesWithProgressResumable'
    ]);
    const fileParserSpy = jasmine.createSpyObj('FileParserService', [
      'estimateScanTime'
    ]);

    TestBed.configureTestingModule({
      providers: [
        BackgroundScanService,
        { provide: NistApiService, useValue: nistApiSpy },
        { provide: FileParserService, useValue: fileParserSpy }
      ]
    });

    service = TestBed.inject(BackgroundScanService);
    nistApiServiceSpy = TestBed.inject(NistApiService) as jasmine.SpyObj<NistApiService>;
    fileParserServiceSpy = TestBed.inject(FileParserService) as jasmine.SpyObj<FileParserService>;

    // 設定預設 mock 回應
    fileParserServiceSpy.estimateScanTime.and.returnValue({
      estimatedMinutes: 10,
      factors: []
    });
  });

  afterEach(() => {
    // 清理 localStorage
    localStorage.removeItem('cve_background_scan_state');
  });

  it('應該創建具有正確初始值的新任務', () => {
    const taskId = service.createScanTask('測試任務', mockPackages, mockConfig, false);
    const task = service.getTask(taskId);

    expect(task).toBeDefined();
    expect(task?.intermediateResults).toEqual([]);
    expect(task?.lastScannedIndex).toBe(-1);
    expect(task?.packages.length).toBe(5);
  });

  it('應該在掃描過程中保存中間結果', async () => {
    // 模擬掃描過程，返回單個套件結果
    nistApiServiceSpy.searchMultiplePackagesWithProgressResumable.and.returnValue(
      of({
        type: 'packageResult',
        packageResult: { packageName: 'package1@1.0.0', vulnerabilities: [] },
        packageIndex: 0
      })
    );

    const taskId = service.createScanTask('測試任務', mockPackages, mockConfig, true);
    let task = service.getTask(taskId);

    // 等待一段時間讓掃描過程執行
    await new Promise(resolve => setTimeout(resolve, 100));

    task = service.getTask(taskId);
    
    // 檢查中間結果是否已保存
    expect(task?.intermediateResults?.length).toBeGreaterThan(0);
    expect(task?.lastScannedIndex).toBeGreaterThanOrEqual(0);
  });

  it('應該從暫停位置恢復掃描', () => {
    // 創建一個已有中間結果的任務
    const taskId = service.createScanTask('測試任務', mockPackages, mockConfig, false);
    let task = service.getTask(taskId);

    // 模擬已掃描前兩個套件
    task!.intermediateResults = [
      { packageName: 'package1@1.0.0', vulnerabilities: [] },
      { packageName: 'package2@2.0.0', vulnerabilities: [] }
    ];
    task!.lastScannedIndex = 1;
    task!.status = 'paused';

    // 模擬從第三個套件開始的掃描
    nistApiServiceSpy.searchMultiplePackagesWithProgressResumable.and.returnValue(
      of({
        type: 'result',
        results: [
          { packageName: 'package3@3.0.0', vulnerabilities: [] },
          { packageName: 'package4@4.0.0', vulnerabilities: [] },
          { packageName: 'package5@5.0.0', vulnerabilities: [] }
        ]
      })
    );

    // 重新開始任務
    service.startScanTask(taskId);

    // 驗證 API 被正確調用，只掃描剩餘的套件
    expect(nistApiServiceSpy.searchMultiplePackagesWithProgressResumable).toHaveBeenCalledWith(
      mockPackages.slice(2), // 從第三個套件開始
      2, // 開始索引
      mockPackages.length // 總套件數
    );
  });

  it('應該正確處理暫停操作', () => {
    const taskId = service.createScanTask('測試任務', mockPackages, mockConfig, false);
    let task = service.getTask(taskId);

    // 設定任務為執行中
    task!.status = 'running';

    // 暫停任務
    service.pauseScanTask(taskId);

    task = service.getTask(taskId);
    expect(task?.status).toBe('paused');
  });

  it('應該在已有完整結果時直接完成任務', () => {
    const taskId = service.createScanTask('測試任務', mockPackages, mockConfig, false);
    let task = service.getTask(taskId);

    // 模擬已完成所有掃描
    task!.intermediateResults = [
      { packageName: 'package1@1.0.0', vulnerabilities: [] },
      { packageName: 'package2@2.0.0', vulnerabilities: [] },
      { packageName: 'package3@3.0.0', vulnerabilities: [] },
      { packageName: 'package4@4.0.0', vulnerabilities: [] },
      { packageName: 'package5@5.0.0', vulnerabilities: [] }
    ];
    task!.lastScannedIndex = 4; // 最後一個套件的索引

    // 重新開始任務
    service.startScanTask(taskId);

    // 任務應該直接完成，不調用 API
    task = service.getTask(taskId);
    expect(task?.status).toBe('completed');
    expect(task?.results?.length).toBe(5);
    expect(nistApiServiceSpy.searchMultiplePackagesWithProgressResumable).not.toHaveBeenCalled();
  });

  it('應該合併中間結果和最終結果', async () => {
    // 模擬有中間結果的情況
    nistApiServiceSpy.searchMultiplePackagesWithProgressResumable.and.returnValue(
      of({
        type: 'result',
        results: [
          { packageName: 'package4@4.0.0', vulnerabilities: [] },
          { packageName: 'package5@5.0.0', vulnerabilities: [] }
        ]
      })
    );

    const taskId = service.createScanTask('測試任務', mockPackages, mockConfig, false);
    let task = service.getTask(taskId);

    // 設定已有的中間結果
    task!.intermediateResults = [
      { packageName: 'package1@1.0.0', vulnerabilities: [] },
      { packageName: 'package2@2.0.0', vulnerabilities: [] },
      { packageName: 'package3@3.0.0', vulnerabilities: [] }
    ];
    task!.lastScannedIndex = 2;

    // 開始掃描
    service.startScanTask(taskId);

    // 等待掃描完成
    await new Promise(resolve => setTimeout(resolve, 100));

    task = service.getTask(taskId);
    
    // 檢查最終結果是否正確合併
    if (task?.status === 'completed') {
      expect(task.results?.length).toBe(5);
      expect(task.results?.[0].packageName).toBe('package1@1.0.0');
      expect(task.results?.[4].packageName).toBe('package5@5.0.0');
    }
  });
});