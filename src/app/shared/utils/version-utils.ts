/**
 * 版本比較工具函數
 * 支援 semantic versioning (semver) 格式的版本比較
 */

/**
 * 比較兩個版本號
 * @param version1 第一個版本號
 * @param version2 第二個版本號
 * @returns -1 如果 version1 < version2, 0 如果相等, 1 如果 version1 > version2
 */
export function compareVersions(version1: string, version2: string): number {
  // 清理版本字串，移除前綴符號和空白
  const clean1 = cleanVersion(version1);
  const clean2 = cleanVersion(version2);
  
  if (clean1 === clean2) return 0;
  
  // 分割版本號並轉換為數字陣列
  const parts1 = parseVersionParts(clean1);
  const parts2 = parseVersionParts(clean2);
  
  // 比較每個部分
  const maxLength = Math.max(parts1.length, parts2.length);
  
  for (let i = 0; i < maxLength; i++) {
    const part1 = parts1[i] || 0;
    const part2 = parts2[i] || 0;
    
    if (part1 < part2) return -1;
    if (part1 > part2) return 1;
  }
  
  return 0;
}

/**
 * 檢查版本是否大於等於指定版本
 * @param currentVersion 當前版本
 * @param minimumVersion 最小版本
 * @returns true 如果當前版本 >= 最小版本
 */
export function isVersionGreaterOrEqual(currentVersion: string, minimumVersion: string): boolean {
  return compareVersions(currentVersion, minimumVersion) >= 0;
}

/**
 * 檢查版本是否小於指定版本
 * @param currentVersion 當前版本
 * @param maximumVersion 最大版本
 * @returns true 如果當前版本 < 最大版本
 */
export function isVersionLess(currentVersion: string, maximumVersion: string): boolean {
  return compareVersions(currentVersion, maximumVersion) < 0;
}

/**
 * 檢查版本是否在指定範圍內（受影響）
 * @param currentVersion 當前版本
 * @param affectedRange 受影響的版本範圍描述（如 "< 4.2.0", ">= 1.0.0 < 2.0.0"）
 * @returns true 如果版本在受影響範圍內
 */
export function isVersionInAffectedRange(currentVersion: string, affectedRange: string): boolean {
  if (!affectedRange || !currentVersion) return false;
  
  // 移除多餘空白並分割條件
  const conditions = affectedRange.trim().split(/\s+/);
  
  for (let i = 0; i < conditions.length; i++) {
    const condition = conditions[i];
    
    // 處理 >= 條件
    if (condition.startsWith('>=')) {
      const version = condition.substring(2).trim();
      if (!isVersionGreaterOrEqual(currentVersion, version)) {
        return false;
      }
    }
    // 處理 > 條件
    else if (condition.startsWith('>')) {
      const version = condition.substring(1).trim();
      if (compareVersions(currentVersion, version) <= 0) {
        return false;
      }
    }
    // 處理 <= 條件
    else if (condition.startsWith('<=')) {
      const version = condition.substring(2).trim();
      if (compareVersions(currentVersion, version) > 0) {
        return false;
      }
    }
    // 處理 < 條件
    else if (condition.startsWith('<')) {
      const version = condition.substring(1).trim();
      if (!isVersionLess(currentVersion, version)) {
        return false;
      }
    }
    // 處理 = 或 == 條件
    else if (condition.startsWith('=') || condition.startsWith('==')) {
      const version = condition.replace(/^==?/, '').trim();
      if (compareVersions(currentVersion, version) !== 0) {
        return false;
      }
    }
    // 處理 != 條件
    else if (condition.startsWith('!=')) {
      const version = condition.substring(2).trim();
      if (compareVersions(currentVersion, version) === 0) {
        return false;
      }
    }
    // 如果條件不包含操作符，視為精確匹配
    else if (!condition.match(/[<>=!]/)) {
      if (compareVersions(currentVersion, condition) !== 0) {
        return false;
      }
    }
  }
  
  return true;
}

/**
 * 檢查版本是否已修復指定漏洞
 * @param currentVersion 當前版本
 * @param affectedVersions 受影響版本描述陣列
 * @param fixedVersion 修復版本（可選）
 * @returns true 如果版本已修復該漏洞
 */
export function isVulnerabilityFixed(
  currentVersion: string, 
  affectedVersions: string[] = [], 
  fixedVersion?: string
): boolean {
  // 如果有明確的修復版本，檢查當前版本是否 >= 修復版本
  if (fixedVersion) {
    return isVersionGreaterOrEqual(currentVersion, fixedVersion);
  }
  
  // 如果沒有修復版本，檢查當前版本是否不在受影響範圍內
  if (affectedVersions.length === 0) {
    return false; // 無法確定，視為未修復
  }
  
  // 檢查是否在任何受影響範圍內
  for (const range of affectedVersions) {
    if (isVersionInAffectedRange(currentVersion, range)) {
      return false; // 在受影響範圍內，未修復
    }
  }
  
  return true; // 不在任何受影響範圍內，視為已修復
}

/**
 * 清理版本字串
 */
function cleanVersion(version: string): string {
  if (!version) return '0.0.0';
  
  // 移除常見的前綴符號
  return version
    .replace(/^[v^~>=<]+/, '') // 移除 v, ^, ~, >=, <, > 等前綴
    .replace(/[+\-].*$/, '')   // 移除 build metadata 和 pre-release 標識符
    .trim();
}

/**
 * 解析版本部分為數字陣列
 */
function parseVersionParts(version: string): number[] {
  return version
    .split('.')
    .map(part => {
      // 處理包含非數字字符的部分（如 "1.0.0-alpha"）
      const numMatch = part.match(/^\d+/);
      return numMatch ? parseInt(numMatch[0], 10) : 0;
    });
}

/**
 * 格式化版本範圍描述為更易讀的格式
 * @param affectedVersions 受影響版本陣列
 * @returns 格式化後的描述
 */
export function formatAffectedVersions(affectedVersions: string[]): string {
  if (!affectedVersions || affectedVersions.length === 0) {
    return '所有版本';
  }
  
  return affectedVersions.join(', ');
}

/**
 * 取得下一個建議的安全版本
 * @param currentVersion 當前版本
 * @param fixedVersion 修復版本
 * @returns 建議的版本號
 */
export function getSuggestedVersion(currentVersion: string, fixedVersion?: string): string | null {
  if (!fixedVersion) return null;
  
  // 如果當前版本已經 >= 修復版本，返回當前版本
  if (isVersionGreaterOrEqual(currentVersion, fixedVersion)) {
    return currentVersion;
  }
  
  return fixedVersion;
}