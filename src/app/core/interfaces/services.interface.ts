import { Observable } from 'rxjs';
import { PackageInfo, Vulnerability, ScanResult, ValidationResult, PackageVulnerability } from '../models/vulnerability.model';

export interface IFileParserService {
  parsePackageJson(file: File): Observable<PackageInfo[]>;
  validateFileFormat(file: File): Observable<ValidationResult>;
  extractDependencies(content: string): PackageInfo[];
}

export interface ICveService {
  scanPackages(packages: PackageInfo[]): Observable<ScanResult>;
  searchVulnerabilities(packageName: string, version: string): Observable<Vulnerability[]>;
  validateApiKey(): Observable<boolean>;
  checkPackageUpdates(packageName: string, currentVersion: string): Observable<string | null>;
}

export interface ICacheService {
  get<T>(key: string): T | null;
  set<T>(key: string, value: T, ttl?: number): void;
  clear(): void;
  has(key: string): boolean;
  remove(key: string): void;
  getKeys(): string[];
}

export interface IProgressTrackingService {
  startTracking(totalItems: number): string;
  updateProgress(trackingId: string, completed: number, currentItem?: string): void;
  getProgress(trackingId: string): ProgressInfo | null;
  completeTracking(trackingId: string): void;
  pauseTracking(trackingId: string): void;
  resumeTracking(trackingId: string): void;
}

export interface IReportService {
  generateScanReport(scanResult: ScanResult): Observable<ReportData>;
  exportReport(scanResult: ScanResult, format: 'pdf' | 'csv' | 'json'): Observable<Blob>;
  generateSummaryStats(vulnerabilities: PackageVulnerability[]): SummaryStats;
}

export interface INotificationService {
  showSuccess(message: string, action?: string): void;
  showError(message: string, action?: string): void;
  showWarning(message: string, action?: string): void;
  showInfo(message: string, action?: string): void;
}

export interface ProgressInfo {
  trackingId: string;
  current: number;
  total: number;
  percentage: number;
  currentItem: string;
  status: 'running' | 'paused' | 'completed' | 'error';
  startTime: Date;
  estimatedCompletion?: Date;
}

export interface ReportData {
  title: string;
  generatedAt: Date;
  summary: SummaryStats;
  vulnerabilities: PackageVulnerability[];
  recommendations: RecommendationItem[];
}

export interface SummaryStats {
  totalPackages: number;
  vulnerablePackages: number;
  totalVulnerabilities: number;
  severityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  riskScore: number;
}

export interface RecommendationItem {
  packageName: string;
  currentVersion: string;
  recommendedVersion: string;
  severity: string;
  reason: string;
  priority: 'high' | 'medium' | 'low';
}

export interface IVulnerabilityProvider {
  name: string;
  priority: number;
  searchVulnerabilities(packageName: string, version: string): Observable<Vulnerability[]>;
  isAvailable(): Observable<boolean>;
}

export interface IConfigService {
  getApiKey(): string | null;
  setApiKey(key: string): void;
  getApiEndpoint(): string;
  setApiEndpoint(endpoint: string): void;
  getRequestTimeout(): number;
  setRequestTimeout(timeout: number): void;
  getCacheSettings(): CacheSettings;
  setCacheSettings(settings: CacheSettings): void;
}

export interface CacheSettings {
  enabled: boolean;
  ttl: number;
  maxSize: number;
}