import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: '/upload', pathMatch: 'full' },
  { 
    path: 'upload', 
    loadComponent: () => import('./features/upload/upload.component').then(m => m.UploadComponent)
  },
  { 
    path: 'scan', 
    loadComponent: () => import('./features/scan/scan.component').then(m => m.ScanComponent)
  },
  { 
    path: 'report', 
    loadComponent: () => import('./features/report/report.component').then(m => m.ReportComponent)
  },
  { 
    path: 'background-tasks', 
    loadComponent: () => import('./features/background-tasks/background-tasks.component').then(m => m.BackgroundTasksComponent)
  },
  { 
    path: 'database', 
    loadComponent: () => import('./features/database-management/database-management.component').then(m => m.DatabaseManagementComponent)
  },
  { path: '**', redirectTo: '/upload' }
];
