import {
  compareVersions,
  isVersionGreaterOrEqual,
  isVersionLess,
  isVersionInAffectedRange,
  isVulnerabilityFixed,
  formatAffectedVersions,
  getSuggestedVersion
} from './version-utils';

describe('version-utils', () => {

  describe('compareVersions', () => {
    it('should return 0 for equal versions', () => {
      expect(compareVersions('1.0.0', '1.0.0')).toBe(0);
    });

    it('should return -1 when first version is less', () => {
      expect(compareVersions('1.0.0', '2.0.0')).toBe(-1);
    });

    it('should return 1 when first version is greater', () => {
      expect(compareVersions('2.0.0', '1.0.0')).toBe(1);
    });

    it('should handle versions with different segment counts', () => {
      expect(compareVersions('1.0', '1.0.0')).toBe(0);
      expect(compareVersions('1.0.0', '1.0.0.1')).toBe(-1);
    });

    it('should handle versions with v prefix', () => {
      expect(compareVersions('v1.2.3', '1.2.3')).toBe(0);
    });

    it('should treat pre-release as less than release (semver)', () => {
      expect(compareVersions('1.0.0-alpha', '1.0.0')).toBe(-1);
      expect(compareVersions('1.0.0', '1.0.0-alpha')).toBe(1);
    });

    it('should order pre-release identifiers correctly', () => {
      // alpha < beta
      expect(compareVersions('1.0.0-alpha', '1.0.0-beta')).toBe(-1);
      // alpha.1 < alpha.2
      expect(compareVersions('1.0.0-alpha.1', '1.0.0-alpha.2')).toBe(-1);
      // numeric < string identifier
      expect(compareVersions('1.0.0-1', '1.0.0-alpha')).toBe(-1);
    });

    it('should handle pre-release vs different major version', () => {
      expect(compareVersions('2.0.0-alpha', '1.0.0')).toBe(1);
      expect(compareVersions('1.0.0-alpha', '2.0.0')).toBe(-1);
    });

    it('should strip build metadata but keep pre-release', () => {
      expect(compareVersions('1.0.0+build1', '1.0.0+build2')).toBe(0);
      expect(compareVersions('1.0.0-alpha+build', '1.0.0')).toBe(-1);
    });
  });

  describe('isVersionGreaterOrEqual', () => {
    it('should return true for equal versions', () => {
      expect(isVersionGreaterOrEqual('1.0.0', '1.0.0')).toBeTrue();
    });

    it('should return true for greater version', () => {
      expect(isVersionGreaterOrEqual('2.0.0', '1.0.0')).toBeTrue();
    });

    it('should return false for lesser version', () => {
      expect(isVersionGreaterOrEqual('0.9.0', '1.0.0')).toBeFalse();
    });
  });

  describe('isVersionLess', () => {
    it('should return true for lesser version', () => {
      expect(isVersionLess('1.0.0', '2.0.0')).toBeTrue();
    });

    it('should return false for equal version', () => {
      expect(isVersionLess('1.0.0', '1.0.0')).toBeFalse();
    });

    it('should return false for greater version', () => {
      expect(isVersionLess('2.0.0', '1.0.0')).toBeFalse();
    });
  });

  describe('isVersionInAffectedRange', () => {
    it('should return false for empty inputs', () => {
      expect(isVersionInAffectedRange('', '<2.0.0')).toBeFalse();
      expect(isVersionInAffectedRange('1.0.0', '')).toBeFalse();
    });

    // 無空格格式（原有行為）
    describe('no-space format', () => {
      it('should handle <version', () => {
        expect(isVersionInAffectedRange('1.9.0', '<2.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('2.0.0', '<2.0.0')).toBeFalse();
        expect(isVersionInAffectedRange('2.0.1', '<2.0.0')).toBeFalse();
      });

      it('should handle <=version', () => {
        expect(isVersionInAffectedRange('1.9.0', '<=2.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('2.0.0', '<=2.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('2.0.1', '<=2.0.0')).toBeFalse();
      });

      it('should handle >version', () => {
        expect(isVersionInAffectedRange('2.0.1', '>2.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('2.0.0', '>2.0.0')).toBeFalse();
        expect(isVersionInAffectedRange('1.9.0', '>2.0.0')).toBeFalse();
      });

      it('should handle >=version', () => {
        expect(isVersionInAffectedRange('2.0.1', '>=2.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('2.0.0', '>=2.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('1.9.0', '>=2.0.0')).toBeFalse();
      });
    });

    // 有空格格式（Bug #1 修復 — 防禦性處理）
    describe('with-space format (defensive normalization)', () => {
      it('should handle "< 2.0.0" with space', () => {
        expect(isVersionInAffectedRange('1.9.0', '< 2.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('2.0.0', '< 2.0.0')).toBeFalse();
      });

      it('should handle "<= 2.0.0" with space', () => {
        expect(isVersionInAffectedRange('2.0.0', '<= 2.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('2.0.1', '<= 2.0.0')).toBeFalse();
      });

      it('should handle "> 1.0.0" with space', () => {
        expect(isVersionInAffectedRange('1.0.1', '> 1.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('1.0.0', '> 1.0.0')).toBeFalse();
      });

      it('should handle ">= 1.0.0" with space', () => {
        expect(isVersionInAffectedRange('1.0.0', '>= 1.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('0.9.0', '>= 1.0.0')).toBeFalse();
      });
    });

    // 複合條件
    describe('compound conditions', () => {
      it('should handle ">=1.0.0 <2.0.0" range', () => {
        expect(isVersionInAffectedRange('1.0.0', '>=1.0.0 <2.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('1.5.0', '>=1.0.0 <2.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('0.9.0', '>=1.0.0 <2.0.0')).toBeFalse();
        expect(isVersionInAffectedRange('2.0.0', '>=1.0.0 <2.0.0')).toBeFalse();
      });

      it('should handle compound conditions with spaces (defensive)', () => {
        expect(isVersionInAffectedRange('1.5.0', '>= 1.0.0 < 2.0.0')).toBeTrue();
        expect(isVersionInAffectedRange('0.9.0', '>= 1.0.0 < 2.0.0')).toBeFalse();
        expect(isVersionInAffectedRange('2.0.0', '>= 1.0.0 < 2.0.0')).toBeFalse();
      });
    });

    // 精確匹配
    describe('exact match', () => {
      it('should match exact version string', () => {
        expect(isVersionInAffectedRange('1.2.3', '1.2.3')).toBeTrue();
        expect(isVersionInAffectedRange('1.2.4', '1.2.3')).toBeFalse();
      });
    });

    // Pre-release 版本
    describe('pre-release versions', () => {
      it('should treat pre-release as affected when range is <release', () => {
        // 1.0.0-alpha < 1.0.0，所以在 <1.0.0 範圍內
        expect(isVersionInAffectedRange('1.0.0-alpha', '<1.0.0')).toBeTrue();
      });

      it('should treat release as not affected when range is <release', () => {
        expect(isVersionInAffectedRange('1.0.0', '<1.0.0')).toBeFalse();
      });

      it('should handle pre-release in compound range', () => {
        // 2.0.0-rc.1 < 2.0.0，所以在 >=1.0.0 <2.0.0 內
        expect(isVersionInAffectedRange('2.0.0-rc.1', '>=1.0.0 <2.0.0')).toBeTrue();
      });
    });

    // 邊界值
    describe('boundary values', () => {
      it('should handle 0.0.0 version', () => {
        expect(isVersionInAffectedRange('0.0.0', '<1.0.0')).toBeTrue();
      });

      it('should handle large version numbers', () => {
        expect(isVersionInAffectedRange('99.99.99', '<100.0.0')).toBeTrue();
      });
    });
  });

  describe('isVulnerabilityFixed', () => {
    describe('with fixedVersion', () => {
      it('should return true if current version >= fixedVersion', () => {
        expect(isVulnerabilityFixed('2.0.0', [], '1.5.0')).toBeTrue();
        expect(isVulnerabilityFixed('1.5.0', [], '1.5.0')).toBeTrue();
      });

      it('should return false if current version < fixedVersion', () => {
        expect(isVulnerabilityFixed('1.0.0', [], '1.5.0')).toBeFalse();
      });
    });

    describe('with affectedVersions only (no fixedVersion)', () => {
      it('should return false when version is in affected range', () => {
        expect(isVulnerabilityFixed('1.0.0', ['<2.0.0'])).toBeFalse();
      });

      it('should return true when version is NOT in any affected range', () => {
        expect(isVulnerabilityFixed('3.0.0', ['<2.0.0'])).toBeTrue();
      });

      it('should handle affected versions with spaces (defensive)', () => {
        expect(isVulnerabilityFixed('1.0.0', ['< 2.0.0'])).toBeFalse();
        expect(isVulnerabilityFixed('3.0.0', ['< 2.0.0'])).toBeTrue();
      });

      it('should return false when no affectedVersions provided', () => {
        expect(isVulnerabilityFixed('1.0.0', [])).toBeFalse();
      });
    });

    describe('fixedVersion takes precedence', () => {
      it('should use fixedVersion even when affectedVersions exist', () => {
        expect(isVulnerabilityFixed('2.0.0', ['<3.0.0'], '1.5.0')).toBeTrue();
      });
    });

    describe('pre-release versions', () => {
      it('should treat pre-release as not fixed when fixedVersion is the release', () => {
        // 1.5.0-rc.1 < 1.5.0，所以未修復
        expect(isVulnerabilityFixed('1.5.0-rc.1', [], '1.5.0')).toBeFalse();
      });

      it('should treat pre-release as vulnerable via affectedVersions', () => {
        // 2.0.0-beta < 2.0.0，所以在 <2.0.0 範圍內
        expect(isVulnerabilityFixed('2.0.0-beta', ['<2.0.0'])).toBeFalse();
      });
    });
  });

  describe('formatAffectedVersions', () => {
    it('should return "所有版本" for empty array', () => {
      expect(formatAffectedVersions([])).toBe('所有版本');
    });

    it('should join versions with comma', () => {
      expect(formatAffectedVersions(['<2.0.0', '>=1.0.0'])).toBe('<2.0.0, >=1.0.0');
    });
  });

  describe('getSuggestedVersion', () => {
    it('should return null when no fixedVersion', () => {
      expect(getSuggestedVersion('1.0.0')).toBeNull();
    });

    it('should return fixedVersion when current is less', () => {
      expect(getSuggestedVersion('1.0.0', '2.0.0')).toBe('2.0.0');
    });

    it('should return currentVersion when already fixed', () => {
      expect(getSuggestedVersion('2.0.0', '1.5.0')).toBe('2.0.0');
    });
  });
});
