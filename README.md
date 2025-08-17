# CVE Security Scanner / CVE 安全掃描工具

[English](#english) | [繁體中文](#繁體中文)

---

## English

### Overview

A comprehensive security vulnerability scanner for Node.js projects that analyzes `package.json` and `package-lock.json` dependencies against the NIST CVE database. Built with Angular 17, this tool provides real-time vulnerability scanning, background task management, detailed reporting, and multiple export formats.

### Features

#### 🔍 **Vulnerability Scanning**
- **Dual Scanning Modes**: API scanning and local database scanning
- **Local Database**: Complete NVD database stored in IndexedDB for offline use
- **Offline Support**: Scan packages without internet connection using local database
- Integration with NIST National Vulnerability Database (NVD)
- Support for `package.json` and `package-lock.json` files
- CVSS scoring and severity classification (Critical, High, Medium, Low)
- Automated API rate limiting and retry mechanisms

#### 🌙 **Background Scanning** ⭐ NEW
- **Non-blocking scans**: Continue using other features while scanning runs in background
- **Persistent progress**: Scan progress persists across page refreshes and browser restarts
- **Browser notifications**: Get notified when background scans complete
- **Task management**: View, pause, resume, or cancel background scans
- **Foreground switching**: Convert background scans to foreground view anytime

#### ⚡ **Smart Task Management** ⭐ NEW
- **Automatic cleanup**: Tasks older than 24 hours are automatically removed
- **Manual cleanup**: Instantly remove expired tasks with one click
- **Task persistence**: All task states saved to local storage
- **Real-time updates**: Task status updates automatically when scans complete
- **Improved stability**: Fixed button positioning and layout stability issues

#### 📊 **Enhanced Reporting** ⭐ IMPROVED
- Interactive dashboard with vulnerability statistics
- **Sticky toolbar**: Report actions always accessible while scrolling
- Visual charts showing risk distribution
- Package and vulnerability tables with sorting and filtering
- Detailed vulnerability information including:
  - CVE identifiers and descriptions
  - CVSS scores and severity levels
  - Publication and modification dates
  - Affected versions and reference links

#### 📁 **Multiple Export Formats**
- **JSON**: Complete structured data with metadata
- **CSV**: Spreadsheet-compatible format for analysis
- **SBOM Formats**: CycloneDX and SPDX software bill of materials
- **HTML Reports**: Comprehensive security reports with visual formatting
- All exports include scan timestamps and comprehensive metadata

#### 🎨 **User Interface** ⭐ IMPROVED
- Modern Material Design interface with responsive layout
- **Optimized buttons**: 40px buttons for better usability
- **Fixed layout issues**: Stable button positioning during interactions
- Five main navigation sections:
  - Upload: File upload and validation
  - Scan: Real-time scanning with progress tracking
  - Report: Detailed analysis with sticky action toolbar
  - Background Tasks: Manage all background scans with improved UI
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

#### Usage

1. **Upload Package File**
   - Navigate to the upload page
   - Select your `package.json` or `package-lock.json` file
   - The tool will validate and extract dependencies

2. **Choose Scan Mode**
   - **API Scan**: Online scanning using NIST API (requires internet)
   - **Local Scan**: Offline scanning using local database (faster)
   - **Foreground Scan**: Traditional blocking scan with immediate results
   - **Background Scan**: Non-blocking scan, continue using other features

3. **Setup Local Database** (Optional)
   - Access `/database` to manage local NVD database
   - Download and synchronize complete NVD dataset
   - Monitor sync progress and database status

4. **Manage Background Tasks**
   - Access `/background-tasks` to view all scans
   - Pause, resume, or cancel running scans
   - Switch background scans to foreground view
   - View completed scan results with improved interface

5. **View Report**
   - Access detailed vulnerability information
   - Use sticky toolbar for easy access to actions while scrolling
   - Browse packages and vulnerabilities with enhanced UI
   - Read risk analysis and security recommendations

6. **Export Results**
   - Choose from JSON, CSV, HTML, or SBOM formats
   - All exports include scan timestamps
   - Download reports locally

### Technical Stack

- **Frontend**: Angular 17 (Standalone Components)
- **UI Components**: Angular Material 17
- **Charts**: Chart.js with ng2-charts
- **Reactive Programming**: RxJS
- **Styling**: SCSS
- **Testing**: Karma + Jasmine
- **API**: NIST CVE Database REST API
- **Local Database**: IndexedDB for NVD data storage
- **Workers**: Web Workers for database operations
- **Storage**: Browser LocalStorage for task persistence

### Architecture

```
src/app/
├── core/                    # Core services and models
│   ├── interfaces/          # TypeScript interfaces
│   ├── models/             # Data models
│   └── services/           # Business logic services
│       ├── background-scan.service.ts  # Background task management
│       ├── cache.service.ts            # LRU caching system
│       ├── file-parser.service.ts      # File parsing logic
│       ├── nist-api.service.ts         # NIST API integration
│       ├── local-scan.service.ts       # Local database scanning
│       ├── nvd-database.service.ts     # IndexedDB management
│       ├── nvd-download.service.ts     # NVD data download
│       ├── nvd-parser.service.ts       # NVD data parsing
│       ├── nvd-sync.service.ts         # Database synchronization
│       ├── database-worker.service.ts  # Web Worker management
│       └── report-export.service.ts    # Export functionality
├── features/               # Feature modules
│   ├── upload/            # File upload component
│   ├── scan/              # Scanning interface
│   ├── report/            # Reporting dashboard
│   ├── background-tasks/  # Background task management
│   └── database-management/ # Local database management
└── shared/                # Shared components
    ├── components/        # Reusable UI components
    └── material/          # Material Design modules
```

---

## 繁體中文

### 概述

這是一個針對 Node.js 專案的綜合性安全漏洞掃描工具，能夠分析 `package.json` 和 `package-lock.json` 相依性套件並與 NIST CVE 資料庫進行比對。使用 Angular 17 建構，提供即時漏洞掃描、背景任務管理、詳細報告和多種匯出格式。

### 功能特色

#### 🔍 **漏洞掃描**
- **雙模式掃描**: 支援 API 掃描和本地資料庫掃描
- **本地資料庫**: 使用 IndexedDB 儲存完整的 NVD 資料庫副本
- **離線支援**: 本地掃描可在無網路連線時使用
- 整合 NIST 國家漏洞資料庫 (NVD)
- 支援 `package.json` 和 `package-lock.json` 檔案
- CVSS 評分和嚴重性分類（嚴重、高、中、低風險）
- 自動化 API 限制處理和重試機制

#### 🌙 **背景掃描** ⭐ 全新功能
- **非阻塞掃描**：掃描期間可繼續使用其他功能
- **持久性進度**：進度在頁面重新整理和瀏覽器重啟後保持
- **瀏覽器通知**：背景掃描完成時收到通知
- **任務管理**：查看、暫停、繼續或取消背景掃描
- **前景切換**：隨時將背景掃描切換為前景顯示

#### ⚡ **智慧任務管理** ⭐ 全新功能
- **自動清理**：超過 24 小時的任務自動移除
- **手動清理**：一鍵立即移除過期任務
- **任務持久化**：所有任務狀態保存至本地儲存
- **即時更新**：掃描完成時任務狀態自動更新
- **穩定性改善**：修正按鈕定位和佈局穩定性問題

#### 📊 **增強型報告** ⭐ 功能改善
- 互動式儀表板顯示漏洞統計
- **黏性工具列**：滾動時報告操作按鈕始終可見
- 視覺化圖表顯示風險分佈
- 套件和漏洞表格含排序和篩選功能
- 詳細漏洞資訊包含：
  - CVE 識別碼和描述
  - CVSS 分數和嚴重性等級
  - 發布和修改日期
  - 受影響版本和參考連結

#### 📁 **多種匯出格式**
- **JSON**：完整結構化資料含中繼資料
- **CSV**：相容試算表的分析格式
- **SBOM 格式**：CycloneDX 和 SPDX 軟體物料清單
- **HTML 報告**：具視覺化格式的完整安全報告
- 所有匯出皆包含掃描時間戳記和完整中繼資料

#### 🎨 **使用者介面** ⭐ 介面改善
- 現代化 Material Design 介面含響應式佈局
- **優化按鈕**：40px 按鈕提供更好的可用性
- **修正佈局問題**：互動時按鈕位置保持穩定
- 五個主要導航區域：
  - 上傳：檔案上傳和驗證
  - 掃描：即時掃描含進度追蹤
  - 報告：詳細分析含黏性操作工具列
  - 背景任務：管理所有背景掃描（介面已改善）
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

#### 使用方法

1. **上傳套件檔案**
   - 導航至上傳頁面
   - 選擇您的 `package.json` 或 `package-lock.json` 檔案
   - 工具會驗證並提取相依性套件

2. **選擇掃描模式**
   - **API 掃描**：線上掃描使用 NIST API（需要網路連線）
   - **本地掃描**：離線掃描使用本地資料庫（更快速）
   - **前景掃描**：傳統阻塞式掃描，立即顯示結果
   - **背景掃描**：非阻塞掃描，可繼續使用其他功能

3. **設定本地資料庫**（選用）
   - 造訪 `/database` 頁面管理本地 NVD 資料庫
   - 下載並同步完整的 NVD 資料集
   - 監控同步進度和資料庫狀態

4. **管理背景任務**
   - 造訪 `/background-tasks` 頁面查看所有掃描
   - 暫停、繼續或取消執行中的掃描
   - 將背景掃描切換為前景顯示
   - 透過改善的介面檢視已完成的掃描結果

5. **檢視報告**
   - 存取詳細漏洞資訊
   - 使用黏性工具列在滾動時輕鬆存取操作功能
   - 透過增強的 UI 瀏覽套件和漏洞
   - 閱讀風險分析和安全建議

6. **匯出結果**
   - 選擇 JSON、CSV、HTML 或 SBOM 格式
   - 所有匯出皆包含掃描時間戳記
   - 本地下載報告檔案

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

### v3.1.0 (Current) ⭐ UI/UX Improvements
- ✅ **Sticky toolbar**: Report actions always accessible while scrolling
- ✅ **Button optimization**: 40px buttons for better usability
- ✅ **Layout stability**: Fixed button positioning issues during interactions
- ✅ **Background task improvements**: Enhanced real-time updates and automatic task completion detection
- ✅ **Upload page cleanup**: Removed inappropriate SBOM HTML export from upload stage

### v3.0.0 (Previous) ⭐ Local Database Scanning
- ✅ **Local database scanning**: Complete NVD database stored in IndexedDB
- ✅ **Offline capability**: Scan packages without internet connection
- ✅ **Database synchronization**: Download and sync complete NVD dataset
- ✅ **Web Workers**: Background database operations for better performance
- ✅ **Dual scan modes**: Choose between API and local database scanning

### v2.0.0 (Previous) ⭐ Background Scanning
- ✅ **Background scanning system**: Non-blocking scans with task management
- ✅ **Persistent task states**: Tasks survive page refreshes and browser restarts
- ✅ **Browser notifications**: Get notified when background scans complete
- ✅ **Automatic task cleanup**: Tasks older than 24 hours automatically removed
- ✅ **Task management UI**: Comprehensive background task management page

### v1.0.0 (Initial)
- ✅ Complete NIST API integration
- ✅ Real-time vulnerability scanning
- ✅ Comprehensive reporting dashboard
- ✅ Multiple export formats (JSON, CSV, SBOM)
- ✅ LRU caching system
- ✅ Automatic rate limiting with retry logic

---

**Built with ❤️ using Angular and Material Design**  
**使用 Angular 和 Material Design 用心建構**

**⭐ Now with Enhanced UI/UX - Smooth & Stable Experience!**  
**⭐ 現在具備增強的 UI/UX - 流暢且穩定的體驗！**