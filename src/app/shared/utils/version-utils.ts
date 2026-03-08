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

  // 分離主版本號和 pre-release 標識
  const { base: base1, prerelease: pre1 } = splitPrerelease(clean1);
  const { base: base2, prerelease: pre2 } = splitPrerelease(clean2);

  // 比較主版本號數字部分
  const parts1 = parseVersionParts(base1);
  const parts2 = parseVersionParts(base2);
  const maxLength = Math.max(parts1.length, parts2.length);

  for (let i = 0; i < maxLength; i++) {
    const part1 = parts1[i] || 0;
    const part2 = parts2[i] || 0;

    if (part1 < part2) return -1;
    if (part1 > part2) return 1;
  }

  // 主版本號相等時，比較 pre-release
  // 根據 semver：有 pre-release 的版本 < 無 pre-release 的同版本
  if (pre1 && !pre2) return -1;
  if (!pre1 && pre2) return 1;
  if (pre1 && pre2) return comparePrereleaseIdentifiers(pre1, pre2);

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
  
  // 正規化：移除運算符與版本號之間的空格，再分割條件
  const normalized = affectedRange.trim().replace(/([<>=!]+)\s+/g, '$1');
  const conditions = normalized.split(/\s+/);
  
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

  return version
    .replace(/^[v^~>=<]+/, '') // 移除 v, ^, ~, >=, <, > 等前綴
    .replace(/\+.*$/, '')      // 只移除 build metadata（+ 之後），保留 pre-release（-）
    .trim();
}

/**
 * 分離主版本號和 pre-release 標識
 * "1.0.0-alpha.1" → { base: "1.0.0", prerelease: "alpha.1" }
 * "1.0.0" → { base: "1.0.0", prerelease: undefined }
 */
function splitPrerelease(version: string): { base: string; prerelease: string | undefined } {
  const hyphenIndex = version.indexOf('-');
  if (hyphenIndex === -1) {
    return { base: version, prerelease: undefined };
  }
  return {
    base: version.substring(0, hyphenIndex),
    prerelease: version.substring(hyphenIndex + 1)
  };
}

/**
 * 比較 pre-release 標識符（依 semver 規範）
 * 數字段按數值比較，非數字段按字典序比較，數字 < 非數字
 */
function comparePrereleaseIdentifiers(pre1: string, pre2: string): number {
  const ids1 = pre1.split('.');
  const ids2 = pre2.split('.');
  const maxLen = Math.max(ids1.length, ids2.length);

  for (let i = 0; i < maxLen; i++) {
    // 較短的 pre-release 排在前面（fewer identifiers = lower precedence）
    if (i >= ids1.length) return -1;
    if (i >= ids2.length) return 1;

    const a = ids1[i];
    const b = ids2[i];
    const aNum = /^\d+$/.test(a) ? parseInt(a, 10) : undefined;
    const bNum = /^\d+$/.test(b) ? parseInt(b, 10) : undefined;

    // 都是數字：按數值比較
    if (aNum !== undefined && bNum !== undefined) {
      if (aNum < bNum) return -1;
      if (aNum > bNum) return 1;
    }
    // 數字 < 非數字
    else if (aNum !== undefined) return -1;
    else if (bNum !== undefined) return 1;
    // 都是字串：字典序比較
    else {
      if (a < b) return -1;
      if (a > b) return 1;
    }
  }

  return 0;
}

/**
 * 解析版本部分為數字陣列
 */
function parseVersionParts(version: string): number[] {
  return version
    .split('.')
    .map(part => {
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