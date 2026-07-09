# CVE Security Scanner / CVE 安全掃描工具

[English](#english) | [繁體中文](#繁體中文)

---

## English

### Overview

A vulnerability scanner for Node.js projects that analyzes `package.json` and `package-lock.json` dependencies. It scans npm packages primarily against **OSV.dev** (the npm-native, free, download-free vulnerability source) and can supplement or fall back to the **NIST NVD** database (local IndexedDB copy or remote API) when needed. Built with Angular 17, it provides fast online scanning, offline scanning, background task management, detailed reporting, standards-compliant SBOM export, and multiple export formats.

> **Source priority**: This tool scans npm packages. OSV.dev is npm-native, free, requires no download and offers complete coverage, so it is the **primary source**. NIST NVD (local DB or remote API) models data via CPE, giving limited match accuracy for npm, so it serves only as a **supplement / offline fallback**. When merging, the OSV entry for a CVE wins; NIST only fills in descriptive fields OSV is missing (see `VulnerabilityMergeService`).

### Features

#### 🔍 **Multi-Source Vulnerability Scanning**
- **OSV-first**: OSV.dev is the primary source — free, npm-native, no local database download required, using `/querybatch` (up to 1000 packages per request)
- **NIST NVD as fallback**: Local IndexedDB scan for offline use, or remote NIST API as a last resort (rate-limited)
- **Vulnerability Merge Engine**: Deduplicates and merges reports across sources, keeping OSV data and filling gaps from NIST
- **Smart switching**: Local DB not ready + OSV enabled → OSV-only fast path; otherwise falls back to API; local scan failure auto-falls back too
- Support for `package.json` and `package-lock.json` files
- CVSS scoring and severity classification (Critical, High, Medium, Low)

#### 🛡️ **Supply Chain Security**
- **Standards-compliant SBOM export**: CycloneDX 1.6 (via OWASP's official `@cyclonedx/cyclonedx-library`) and SPDX 2.3 (hand-built, validated against the official JSON schema)
- **VEX-ready**: Vulnerabilities are expressed as CycloneDX vulnerability data; SPDX 2.3 represents them as SECURITY external references (VEX requires CycloneDX)
- **Version Recommendation**: Suggests safe upgrade paths for vulnerable dependencies

#### ⚡ **Data Management & Performance**
- **NVD 2.0 optimization**: Optimized data structure and querying for the NVD 2.0 schema
- **Web Workers**: Asynchronous processing of large local databases without blocking the UI
- **Smart versioning**: Automated cleanup of expired data and version management
- **Local scan optimization**: Efficient IndexedDB operations and composite indexing

#### 🌙 **Background Scanning**
- **Non-blocking scans**: Continue using other features while scanning runs in background
- **Persistent progress**: Scan progress persists across page refreshes and browser restarts
- **Browser notifications**: Get notified when background scans complete
- **Task management**: View, pause, resume, or cancel background scans
- **Foreground switching**: Convert background scans to foreground view anytime

#### ⚡ **Smart Task Management**
- **Automatic cleanup**: Tasks older than 24 hours are automatically removed
- **Manual cleanup**: Instantly remove expired tasks with one click
- **Task persistence**: All task states saved to local storage
- **Real-time updates**: Task status updates automatically when scans complete

#### 📊 **Reporting**
- Interactive dashboard with vulnerability statistics
- **Sticky toolbar**: Report actions always accessible while scrolling
- Visual charts showing risk distribution
- Package and vulnerability tables with sorting and filtering
- Detailed vulnerability information including:
  - CVE identifiers and descriptions
  - CVSS scores and severity levels
  - Publication and modification dates
  - Affected versions, fixed versions, and reference links

#### 📁 **Multiple Export Formats**
- **JSON**: Complete structured data with metadata
- **CSV**: Spreadsheet-compatible format for analysis
- **SBOM**: CycloneDX 1.6 and SPDX 2.3 software bill of materials
- **HTML Reports**: Scan report and package inventory as formatted HTML
- All exports include scan timestamps and comprehensive metadata

#### 🎨 **User Interface**
- Modern Material Design interface with responsive layout
- Five main navigation sections:
  - Upload: File upload and validation
  - Scan: Real-time scanning with progress tracking
  - Report: Detailed analysis with sticky action toolbar
  - Background Tasks: Manage all background scans
  - Database: Local database management and synchronization

#### 🚀 **Performance Features**
- LRU caching system (24-hour TTL, 1000 item capacity)
- Intelligent API rate limiting with automatic backoff
- Progress tracking for long-running scans
- Error handling and retry mechanisms
- Optimized database operations using Web Workers

### Quick Start

#### Prerequisites
- Node.js 18+
- npm or yarn package manager

#### Installation

```bash
# Clone the repository
git clone <repository-url>
cd cves-nist

# Install dependencies
npm install

# Start development server
npm start
```

The application will be available at `http://localhost:4300`

> Online usage does **not** require downloading a database — OSV.dev is used by default. The local NVD database is only needed for offline scanning or to supplement non-npm ecosystems with NIST.

#### Usage

1. **Upload Package File**
   - Navigate to the upload page
   - Select your `package.json` or `package-lock.json` file
   - The tool will validate and extract dependencies

2. **Choose Scan Mode**
   - **OSV Scan** (default): Free, npm-native, no download required, fast batch queries via OSV.dev
   - **Local Scan**: Offline scanning using the local NVD database (requires prior download)
   - **API Scan**: Remote NIST API, used only when OSV is disabled and the local DB is not ready (rate-limited, slower)
   - **Background Scan**: Non-blocking scan; continue using other features

3. **Setup Local Database** (Optional)
   - Access `/database` to manage the local NVD database
   - Download and synchronize the NVD dataset
   - Monitor sync progress and database status

4. **Manage Background Tasks**
   - Access `/background-tasks` to view all scans
   - Pause, resume, or cancel running scans
   - Switch background scans to foreground view

5. **View Report**
   - Access detailed vulnerability information
   - Use the sticky toolbar for easy access to actions while scrolling
   - Browse packages and vulnerabilities
   - Read risk analysis and security recommendations

6. **Export Results**
   - Choose from JSON, CSV, HTML, or SBOM (CycloneDX / SPDX) formats
   - All exports include scan timestamps

### Technical Stack

- **Frontend**: Angular 17 (Standalone Components)
- **UI Components**: Angular Material 17
- **Charts**: Chart.js with ng2-charts
- **Reactive Programming**: RxJS
- **Styling**: SCSS
- **Testing**: Karma + Jasmine
- **Sources**: OSV.dev API (primary), NIST NVD REST API (fallback)
- **SBOM**: `@cyclonedx/cyclonedx-library` (CycloneDX), custom SPDX + ajv schema validation
- **Local Database**: IndexedDB for NVD data storage
- **Workers**: Web Workers for database operations
- **Storage**: Browser LocalStorage for task persistence

### Architecture

```
src/app/
├── core/                    # Core services and models
│   ├── config/              # Configuration files
│   ├── interfaces/          # TypeScript interfaces
│   ├── models/              # Data models
│   ├── schemas/             # JSON schemas (e.g. SPDX 2.3 validation)
│   ├── utils/               # Utility functions
│   ├── workers/             # Web Worker scripts
│   └── services/            # Business logic services
│       ├── background-scan.service.ts        # Background task management
│       ├── cache.service.ts                  # LRU caching system
│       ├── cve-optimization.service.ts       # NVD 2.0 optimization
│       ├── cyclonedx-sbom.service.ts         # CycloneDX 1.6 SBOM export
│       ├── database-worker.service.ts        # Web Worker management
│       ├── file-parser.service.ts            # File parsing logic
│       ├── local-scan-optimizer.service.ts   # Local scan performance tuning
│       ├── local-scan.service.ts             # Local database scanning
│       ├── nist-api.service.ts               # NIST API integration (fallback)
│       ├── nvd-database.service.ts           # IndexedDB management
│       ├── nvd-download.service.ts           # NVD data download
│       ├── nvd-parser.service.ts             # NVD data parsing
│       ├── nvd-sync.service.ts               # Database synchronization
│       ├── optimized-query.service.ts        # Database query optimization
│       ├── osv-api.service.ts                # OSV API integration (primary)
│       ├── report-export.service.ts          # Export functionality
│       ├── spdx-sbom.service.ts              # SPDX 2.3 SBOM export
│       ├── version-recommendation.service.ts # Upgrade path recommendations
│       └── vulnerability-merge.service.ts     # Multi-source data merging
├── features/                # Feature modules
│   ├── upload/              # File upload component
│   ├── scan/                # Scanning interface
│   ├── report/              # Reporting dashboard
│   ├── background-tasks/    # Background task management
│   └── database-management/ # Local database management
└── shared/                  # Shared components
    ├── components/          # Reusable UI components
    ├── material/            # Material Design modules
    └── utils/               # Shared utilities
```

---

## 繁體中文

### 概述

這是一個針對 Node.js 專案的安全漏洞掃描工具，能分析 `package.json` 和 `package-lock.json` 相依性套件。工具掃描的是 npm 套件，**主要**與 **OSV.dev**（npm 原生、免費、免下載的漏洞來源）比對，並可在需要時以 **NIST NVD**（本地 IndexedDB 副本或遠端 API）補充或後備。使用 Angular 17 建構，提供快速線上掃描、離線掃描、背景任務管理、詳細報告、符合官方標準的 SBOM 匯出和多種匯出格式。

> **來源優先序**：本工具掃描 npm 套件。OSV.dev 為 npm 原生、免費、免下載且涵蓋完整，是**主要資料源**；NIST NVD（本地庫或遠端 API）以 CPE 建模，對 npm 比對準確率有限，僅作為**補充 / 離線後備**。合併時同一 CVE 保留 OSV 版本，NIST 僅補足 OSV 缺漏的描述性欄位（見 `VulnerabilityMergeService`）。

### 功能特色

#### 🔍 **多源漏洞掃描**
- **OSV 優先**：OSV.dev 為主要來源——免費、npm 原生、免下載本地庫，透過 `/querybatch` 批次查詢（一次最多 1000 筆）
- **NIST NVD 後備**：本地 IndexedDB 掃描供離線使用，或遠端 NIST API 作為最後手段（受速率節流）
- **漏洞合併引擎**：跨來源去重與合併，保留 OSV 資料並以 NIST 補足缺漏欄位
- **智慧切換**：本地庫未就緒且啟用 OSV → 走 OSV-only 快速路徑；否則回退 API；本地掃描失敗亦自動回退
- 支援 `package.json` 和 `package-lock.json` 檔案
- CVSS 評分和嚴重性分類（嚴重、高、中、低風險）

#### 🛡️ **軟體供應鏈安全**
- **符合官方標準的 SBOM 匯出**：CycloneDX 1.6（採 OWASP 官方 `@cyclonedx/cyclonedx-library`）與 SPDX 2.3（手刻結構，並以官方 JSON schema 驗證）
- **VEX 支援**：漏洞以 CycloneDX vulnerability 資料表達；SPDX 2.3 則以 SECURITY external reference 呈現（VEX 需使用 CycloneDX）
- **版本升級建議**：針對具漏洞的相依性套件提供安全的升級路徑建議

#### ⚡ **資料管理與效能最佳化**
- **NVD 2.0 最佳化**：針對 NVD 2.0 格式進行資料結構與查詢效能最佳化
- **Web Workers**：非同步處理大型本地資料庫，確保 UI 零阻塞
- **智慧版本管理**：自動清理過期資料並進行版本控制
- **本地掃描優化**：高效的 IndexedDB 操作與複合索引設計

#### 🌙 **背景掃描**
- **非阻塞掃描**：掃描期間可繼續使用其他功能
- **持久性進度**：進度在頁面重新整理和瀏覽器重啟後保持
- **瀏覽器通知**：背景掃描完成時收到通知
- **任務管理**：查看、暫停、繼續或取消背景掃描
- **前景切換**：隨時將背景掃描切換為前景顯示

#### ⚡ **智慧任務管理**
- **自動清理**：超過 24 小時的任務自動移除
- **手動清理**：一鍵立即移除過期任務
- **任務持久化**：所有任務狀態保存至本地儲存
- **即時更新**：掃描完成時任務狀態自動更新

#### 📊 **報告**
- 互動式儀表板顯示漏洞統計
- **黏性工具列**：滾動時報告操作按鈕始終可見
- 視覺化圖表顯示風險分佈
- 套件和漏洞表格含排序和篩選功能
- 詳細漏洞資訊包含：
  - CVE 識別碼和描述
  - CVSS 分數和嚴重性等級
  - 發布和修改日期
  - 受影響版本、修復版本和參考連結

#### 📁 **多種匯出格式**
- **JSON**：完整結構化資料含中繼資料
- **CSV**：相容試算表的分析格式
- **SBOM**：CycloneDX 1.6 和 SPDX 2.3 軟體物料清單
- **HTML 報告**：掃描報告與套件清單的格式化 HTML
- 所有匯出皆包含掃描時間戳記和完整中繼資料

#### 🎨 **使用者介面**
- 現代化 Material Design 介面含響應式佈局
- 五個主要導航區域：
  - 上傳：檔案上傳和驗證
  - 掃描：即時掃描含進度追蹤
  - 報告：詳細分析含黏性操作工具列
  - 背景任務：管理所有背景掃描
  - 資料庫：本地資料庫管理與同步

#### 🚀 **效能特色**
- LRU 快取系統（24小時 TTL，1000 項目容量）
- 智慧型 API 限制處理含自動退避機制
- 長時間掃描的進度追蹤
- 錯誤處理和重試機制
- 使用 Web Workers 優化資料庫操作

### 快速開始

#### 系統需求
- Node.js 18+
- npm 或 yarn 套件管理器

#### 安裝步驟

```bash
# 複製儲存庫
git clone <repository-url>
cd cves-nist

# 安裝相依性套件
npm install

# 啟動開發伺服器
npm start
```

應用程式將在 `http://localhost:4300` 提供服務

> 線上使用**不需要下載資料庫**——預設使用 OSV.dev。本地 NVD 資料庫僅在離線掃描，或想以 NIST 補充非 npm 生態時才需要。

#### 使用方法

1. **上傳套件檔案**
   - 導航至上傳頁面
   - 選擇您的 `package.json` 或 `package-lock.json` 檔案
   - 工具會驗證並提取相依性套件

2. **選擇掃描模式**
   - **OSV 掃描**（預設）：免費、npm 原生、免下載，透過 OSV.dev 批次快速查詢
   - **本地掃描**：離線掃描使用本地 NVD 資料庫（需先下載）
   - **API 掃描**：遠端 NIST API，僅在關閉 OSV 且本地庫未就緒時使用（受速率節流，較慢）
   - **背景掃描**：非阻塞掃描，可繼續使用其他功能

3. **設定本地資料庫**（選用）
   - 造訪 `/database` 頁面管理本地 NVD 資料庫
   - 下載並同步 NVD 資料集
   - 監控同步進度和資料庫狀態

4. **管理背景任務**
   - 造訪 `/background-tasks` 頁面查看所有掃描
   - 暫停、繼續或取消執行中的掃描
   - 將背景掃描切換為前景顯示

5. **檢視報告**
   - 存取詳細漏洞資訊
   - 使用黏性工具列在滾動時輕鬆存取操作功能
   - 瀏覽套件和漏洞
   - 閱讀風險分析和安全建議

6. **匯出結果**
   - 選擇 JSON、CSV、HTML 或 SBOM（CycloneDX / SPDX）格式
   - 所有匯出皆包含掃描時間戳記

### 開發指令

```bash
# 開發伺服器（執行於 4300 連接埠）
npm start

# 正式環境建置
npm run build

# 執行測試
npm test

# 監視模式建置
npm run watch
```

---

## Changelog / 更新日誌

### v4.1.0 (Current) ⭐ OSV-first & Standards-Compliant SBOM
- ✅ **OSV as primary source**: OSV.dev `/querybatch` is the default, download-free source; NIST NVD demoted to supplement / offline fallback
- ✅ **querybatch detail backfill**: fetches `/vulns/{id}` details to fill fixed versions and other fields
- ✅ **Official SBOM export**: CycloneDX 1.6 via OWASP's official library; SPDX 2.3 validated against the official JSON schema
- ✅ **HTML export overhaul**: scan report and package inventory HTML
- ✅ **Merge fixes**: corrected source links, merge logic, and date/timezone handling

### v4.0.0 ⭐ Supply Chain Security & Performance Optimization
- ✅ **Multi-Source Intelligence**: Integrated OSV API alongside NIST NVD
- ✅ **Performance Overhaul**: NVD 2.0 format optimization, Web Worker asynchronous processing, and advanced query optimizations
- ✅ **Smart Data Management**: Automated cleanup, data versioning, and composite indexing for local database
- ✅ **Vulnerability Merge Engine**: Intelligent deduplication for multi-source scan reports

### v3.1.0 ⭐ UI/UX Improvements
- ✅ **Sticky toolbar**: Report actions always accessible while scrolling
- ✅ **Layout stability**: Fixed button positioning issues during interactions
- ✅ **Background task improvements**: Enhanced real-time updates and automatic task completion detection

### v3.0.0 ⭐ Local Database Scanning
- ✅ **Local database scanning**: Complete NVD database stored in IndexedDB
- ✅ **Offline capability**: Scan packages without internet connection
- ✅ **Database synchronization**: Download and sync complete NVD dataset
- ✅ **Web Workers**: Background database operations for better performance

### v2.0.0 ⭐ Background Scanning
- ✅ **Background scanning system**: Non-blocking scans with task management
- ✅ **Persistent task states**: Tasks survive page refreshes and browser restarts
- ✅ **Browser notifications**: Get notified when background scans complete
- ✅ **Automatic task cleanup**: Tasks older than 24 hours automatically removed

### v1.0.0 (Initial)
- ✅ Complete NIST API integration
- ✅ Real-time vulnerability scanning
- ✅ Comprehensive reporting dashboard
- ✅ Multiple export formats (JSON, CSV, SBOM)
- ✅ LRU caching system

---

**Built with ❤️ using Angular and Material Design**  
**使用 Angular 和 Material Design 用心建構**
