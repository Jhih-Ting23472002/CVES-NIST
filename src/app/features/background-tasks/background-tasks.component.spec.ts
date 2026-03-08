import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject, Subject } from 'rxjs';

import { BackgroundTasksComponent } from './background-tasks.component';
import { BackgroundScanService } from '../../core/services/background-scan.service';
import { BackgroundScanState, ScanTask } from '../../core/models/vulnerability.model';

describe('BackgroundTasksComponent', () => {
  let component: BackgroundTasksComponent;
  let fixture: ComponentFixture<BackgroundTasksComponent>;

  const mockState: BackgroundScanState = { activeTasks: [], completedTasks: [] };

  const mockBackgroundScanService = {
    state$: new BehaviorSubject<BackgroundScanState>(mockState),
    currentTask$: new Subject<ScanTask | null>(),
    getTaskStats: () => ({ active: 0, running: 0, paused: 0, completed: 0, failed: 0 }),
    getNextCleanupTime: () => new Date(),
    startScanTask: jasmine.createSpy('startScanTask'),
    pauseScanTask: jasmine.createSpy('pauseScanTask'),
    cancelScanTask: jasmine.createSpy('cancelScanTask'),
    deleteCompletedTask: jasmine.createSpy('deleteCompletedTask'),
    clearCompletedTasks: jasmine.createSpy('clearCompletedTasks'),
    manualCleanupExpiredTasks: jasmine.createSpy('manualCleanupExpiredTasks').and.returnValue(0),
    moveTaskUp: jasmine.createSpy('moveTaskUp'),
    moveTaskDown: jasmine.createSpy('moveTaskDown'),
    getTask: jasmine.createSpy('getTask')
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [BackgroundTasksComponent],
      providers: [
        { provide: BackgroundScanService, useValue: mockBackgroundScanService }
      ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(BackgroundTasksComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
