# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

- 過程用zh-TW回答
- 不知道的事情不要亂回答
- 程式碼必須具備可維護跟擴充性

## 開發指令

### 基本指令
- `npm start` - 啟動開發伺服器 (實際執行於 localhost:4300，而非預設的 4200)
- `ng serve --host 0.0.0.0 --port 4300` - 開發伺服器完整指令
- `npm run build` - 正式環境建置 (含 base-href 設定)
- `ng build --base-href=/cves-nist/` - 建置完整指令
- `npm test` - 執行單元測試 (使用 Karma + Jasmine)
- `npm run watch` - 監視模式建置

### Angular CLI 指令
- `ng generate component component-name` - 產生新元件 (預設使用 SCSS)
- `ng generate service service-name` - 產生新服務
- `ng generate guard guard-name` - 產生路由守衛

## 專案架構

### 核心概念
這是一個 CVE (Common Vulnerabilities and Exposures) 安全掃描工具，用於分析 package.json 檔案中的套件漏洞。

### 主要架構層次
- **Core Layer** (`src/app/core/`):
  - `services/` - 核心服務：快取服務、檔案解析服務
  - `models/` - 資料模型：漏洞模型、套件資訊
  - `interfaces/` - TypeScript 介面：NIST API 介面、服務介面
  - `guards/` - 路由守衛

- **Features Layer** (`src/app/features/`):
  - `upload/` - 檔案上傳與驗證元件
  - `scan/` - 漏洞掃描執行元件  
  - `report/` - 掃描結果報告元件
  - `background-tasks/` - 背景任務管理元件
  - `database-management/` - 本地資料庫管理元件

- **Shared Layer** (`src/app/shared/`):
  - `components/` - 共用元件
  - `material/` - Angular Material 模組配置
  - `pipes/` - 自訂管道
  - `directives/` - 自訂指令

### 資料流程

> **來源優先序（重要）**：本工具掃描的是 npm 套件。OSV.dev 是 npm 原生、免費、免下載、涵蓋完整的來源，為**主要資料源**；NIST NVD（本地庫或遠端 API）以 CPE 建模，對 npm 比對準確率有限，僅作為**補充 / 離線後備**。合併時同一 CVE 保留 OSV 版本，NIST 僅補足 OSV 缺漏的描述性欄位（見 `VulnerabilityMergeService`）。

#### OSV 掃描流程（主要，免下載）
1. Upload Component: 上傳並驗證 package.json 檔案
2. File Parser Service: 解析套件相依性清單
3. Scan Component: 本地庫未就緒且啟用 OSV 時，走 OSV-only 快速路徑
4. OSV Api Service: 以 `/querybatch` 批次查詢 OSV.dev（一次最多 1000 筆）
5. Report Component: 產生掃描報告並支援匯出

#### 本地掃描流程（離線 / NIST 補充）
1. Upload Component: 上傳並驗證 package.json 檔案
2. File Parser Service: 解析套件相依性清單
3. Scan Component: 檢查本地資料庫狀態
4. Local Scan Service: 使用本地 IndexedDB 進行掃描
5. Vulnerability Merge Service: 與 OSV 結果合併（OSV 優先）
6. Report Component: 產生掃描報告並支援匯出

#### API 掃描流程（最後手段）
1. Upload Component: 上傳並驗證 package.json 檔案
2. File Parser Service: 解析套件相依性清單
3. Scan Component: 本地庫未就緒且未啟用 OSV 時，透過 NIST API 掃描（受節流：12 秒/套件、10 請求/分，每套件 2 請求，約 5 套件/分）
4. Cache Service: 快取 API 回應以提升效能
5. Report Component: 產生掃描報告並支援匯出

#### 本地資料庫建置流程
1. Database Management: 啟動初始同步或增量更新
2. NVD Download Service: 下載 NVD 資料檔案
3. NVD Parser Service: 解析 JSON 資料為結構化記錄
4. Database Worker Service: 批次儲存資料到 IndexedDB
5. 完成後本地掃描即可使用

### 關鍵服務
- `CacheService`: 實作 LRU 快取機制，預設 TTL 24小時，最大快取 1000 項目
- `FileParserService`: 解析和驗證 package.json 檔案格式
- `BackgroundScanService`: 管理背景掃描任務和狀態
- `OsvApiService`: 查詢 OSV.dev（npm 原生、免費、主要來源），支援 `/querybatch` 批次查詢
- `VulnerabilityMergeService`: 合併多來源結果，OSV 優先、NIST 補足缺漏欄位
- `CycloneDxSbomService`: 以 OWASP 官方 `@cyclonedx/cyclonedx-library` 產生 CycloneDX 1.6 SBOM（官方 Serializer 保證 schema 合規）
- `SpdxSbomService`: 產生 SPDX 2.3 SBOM；SPDX 無官方瀏覽器函式庫，故手刻結構並在測試中以官方 JSON schema（`core/schemas/spdx-2.3-schema.json`）+ ajv 驗證。漏洞以 SECURITY externalRef 表達；VEX 無法在 SPDX 2.3 表達，需 VEX 請用 CycloneDX
- `NistApiService`: 查詢遠端 NIST CVE 資料庫（API 掃描，補充 / 最後手段）；本地庫未就緒且啟用 OSV 時改走 OSV-only 快速路徑
- `LocalScanService`: 本地資料庫掃描服務（離線 / NIST 補充）
- `NvdDatabaseService`: 本地 IndexedDB 資料庫管理
- `DatabaseWorkerService`: Web Worker 處理資料庫密集操作
- `NvdSyncService`: 管理 NVD 資料同步
- `NvdDownloadService`: 下載 NVD 資料檔案
- `NvdParserService`: 解析 NVD JSON 資料

### 技術棧
- Angular 17 (Standalone Components)
- Angular Material 17 (UI 元件)
- RxJS (響應式程式設計)
- Chart.js + ng2-charts (圖表視覺化)
- TypeScript 5.4
- SCSS (樣式)
- Karma + Jasmine (測試)

### 路由結構
- `/upload` - 檔案上傳頁面 (預設)
- `/scan` - 掃描執行頁面（支援本地掃描和 API 掃描）
- `/report` - 報告檢視頁面
- `/background-tasks` - 背景任務管理頁面
- `/database` - 本地資料庫管理頁面

### 掃描模式
- **OSV 掃描**: 預設主要來源，免費、npm 原生、免下載本地庫，透過 OSV.dev 批次查詢，快速且涵蓋完整
- **本地掃描**: 使用本地 IndexedDB 資料庫，適合離線使用或補充 NIST 資料；需先下載本地庫
- **API 掃描**: 透過 NIST API 查詢，僅在關閉 OSV 且本地庫未就緒時使用（受速率節流，較慢）
- **智慧切換**: 本地庫未就緒 → 啟用 OSV 走 OSV-only 快速路徑，否則回退 API；本地掃描失敗亦自動回退
- **背景掃描**: 支援非阻塞掃描，可同時使用其他功能

> 一般線上使用**不需要下載資料庫**；本地庫僅在離線或想以 NIST 補充非 npm 生態時才需要。

### 本地資料庫架構
- **IndexedDB**: 使用瀏覽器 IndexedDB 儲存 NVD 資料庫副本
- **Web Workers**: 處理資料庫密集操作，避免阻塞主執行緒
- **版本控制**: 支援資料庫 schema 升級機制
- **批次處理**: 大量資料處理使用批次模式提升效能
- **資料同步**: 支援完整同步和增量更新
- **智慧清理**: 自動清理過期資料以節省儲存空間

### 國際化注意事項
- UI 文字使用繁體中文 (zh-TW)
- 註解和變數名稱混合使用中英文
- 錯誤訊息和使用者提示皆為中文
