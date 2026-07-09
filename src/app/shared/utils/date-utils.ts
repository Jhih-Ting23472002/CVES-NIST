/**
 * NVD API 的日期字串沒有時區資訊（如 2023-10-25T21:15:10.307），
 * 直接 new Date() 會被當成本地時間，導致顯示、排序與匯出的時間不一致。
 * 沒有時區標記時補 Z 視為 UTC；OSV 等已帶時區的字串原樣解析。
 */
export function parseNvdDate(dateStr: string): Date {
  const hasTimezone = /(Z|[+-]\d{2}:?\d{2})$/.test(dateStr);
  return new Date(hasTimezone ? dateStr : `${dateStr}Z`);
}
