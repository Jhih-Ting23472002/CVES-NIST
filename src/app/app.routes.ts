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
  { path: '**', redirectTo: '/upload' }
];
