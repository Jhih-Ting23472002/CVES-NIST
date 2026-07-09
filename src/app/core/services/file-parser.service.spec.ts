import { TestBed } from '@angular/core/testing';
import { firstValueFrom } from 'rxjs';
import { FileParserService } from './file-parser.service';
import { DEFAULT_SCAN_CONFIGS, ScanConfig } from '../models/vulnerability.model';

// 模擬 lockfileVersion 3：express 為正式相依、karma 為 dev 相依，
// socket.io 是 karma 底下的 dev-only transitive（npm 會標 "dev": true）
const LOCK_V3 = {
  name: 'demo',
  version: '1.0.0',
  lockfileVersion: 3,
  packages: {
    '': {
      name: 'demo',
      version: '1.0.0',
      dependencies: { express: '^4.18.2' },
      devDependencies: { karma: '^6.4.0' }
    },
    'node_modules/express': { version: '4.18.2' },
    'node_modules/body-parser': { version: '1.20.1' },
    'node_modules/karma': { version: '6.4.0', dev: true },
    'node_modules/socket.io': { version: '4.7.0', dev: true }
  }
};

function lockFile(): File {
  return new File([JSON.stringify(LOCK_V3)], 'package-lock.json', { type: 'application/json' });
}

describe('FileParserService - package-lock.json dev 相依過濾', () => {
  let service: FileParserService;
  const baseConfig: ScanConfig = DEFAULT_SCAN_CONFIGS['comprehensive'];

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(FileParserService);
  });

  it('includeDevDeps=true 時應包含 dev 相依與 dev-only transitive', async () => {
    const packages = await firstValueFrom(service.parsePackageFile(lockFile(), baseConfig));
    const names = packages.map(p => p.name);
    expect(names).toContain('express');
    expect(names).toContain('body-parser');
    expect(names).toContain('karma');
    expect(names).toContain('socket.io');
  });

  it('includeDevDeps=false 時應排除 dev 相依（等同 npm --omit dev，含 dev-only transitive）', async () => {
    const config: ScanConfig = { ...baseConfig, includeDevDeps: false };
    const packages = await firstValueFrom(service.parsePackageFile(lockFile(), config));
    const names = packages.map(p => p.name);
    expect(names).toContain('express');
    expect(names).toContain('body-parser');
    expect(names).not.toContain('karma');
    expect(names).not.toContain('socket.io');
  });
});
