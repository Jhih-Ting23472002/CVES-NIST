# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

- 過程用zh-TW回答
- 不知道的事情不要亂回答

## 開發指令

### 基本指令
- `npm start` 或 `ng serve` - 啟動開發伺服器 (localhost:4200)
- `npm run build` 或 `ng build` - 建置專案 (輸出至 dist/)
- `npm test` 或 `ng test` - 執行單元測試 (使用 Karma + Jasmine)
- `npm run watch` 或 `ng build --watch --configuration development` - 監視模式建置

### Angular CLI 指令
- `ng generate component component-name` - 產生新元件
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

- **Shared Layer** (`src/app/shared/`):
  - `components/` - 共用元件
  - `material/` - Angular Material 模組配置
  - `pipes/` - 自訂管道
  - `directives/` - 自訂指令

### 資料流程
1. Upload Component: 上傳並驗證 package.json 檔案
2. File Parser Service: 解析套件相依性清單
3. Scan Component: 透過 NIST API 掃描漏洞
4. Cache Service: 快取 API 回應以提升效能
5. Report Component: 產生掃描報告並支援匯出

### 關鍵服務
- `CacheService`: 實作 LRU 快取機制，預設 TTL 24小時，最大快取 1000 項目
- `FileParserService`: 解析和驗證 package.json 檔案格式
- NIST API 整合: 查詢 CVE 資料庫取得漏洞資訊

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
- `/scan` - 掃描執行頁面
- `/report` - 報告檢視頁面

### 國際化注意事項
- UI 文字使用繁體中文 (zh-TW)
- 註解和變數名稱混合使用中英文
- 錯誤訊息和使用者提示皆為中文
