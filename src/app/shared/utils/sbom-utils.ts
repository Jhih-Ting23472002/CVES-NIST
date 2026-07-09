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
