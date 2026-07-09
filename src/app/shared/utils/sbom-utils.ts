import { PackageURL } from 'packageurl-js';

/**
 * 組出 npm 套件的 purl（scoped 套件自動拆 namespace，並正確編碼）
 */
export function buildNpmPurl(pkgName: string, version: string): PackageURL {
  let namespace: string | undefined;
  let name = pkgName;
  if (name.startsWith('@') && name.includes('/')) {
    const [scope, rest] = name.slice(1).split('/');
    namespace = `@${scope}`;
    name = rest;
  }
  return new PackageURL('npm', namespace, name, version, undefined, undefined);
}

/**
 * 依漏洞編號決定 advisory 連結：CVE 連 NVD，其餘（GHSA/OSV 等）連 osv.dev
 */
export function getAdvisoryUrl(vulnId: string): string {
  return vulnId.startsWith('CVE-')
    ? `https://nvd.nist.gov/vuln/detail/${vulnId}`
    : `https://osv.dev/vulnerability/${vulnId}`;
}

/**
 * 依漏洞編號決定來源名稱：CVE 為 NVD，其餘為 OSV
 */
export function getAdvisorySourceName(vulnId: string): string {
  return vulnId.startsWith('CVE-') ? 'NVD' : 'OSV';
}

/**
 * npm integrity 是 base64，SBOM hash/checksum 規定為 hex
 */
export function base64ToHex(base64: string): string | null {
  try {
    const binary = atob(base64);
    let hex = '';
    for (let i = 0; i < binary.length; i++) {
      hex += binary.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return hex;
  } catch {
    return null;
  }
}
