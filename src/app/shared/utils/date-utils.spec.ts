import { parseNvdDate } from './date-utils';

describe('parseNvdDate', () => {
  it('無時區的 NVD 字串視為 UTC', () => {
    expect(parseNvdDate('2023-10-25T21:15:10.307').toISOString())
      .toBe('2023-10-25T21:15:10.307Z');
  });

  it('已帶 Z 的字串原樣解析', () => {
    expect(parseNvdDate('2023-09-01T00:00:00Z').toISOString())
      .toBe('2023-09-01T00:00:00.000Z');
  });

  it('帶時區偏移的字串原樣解析', () => {
    expect(parseNvdDate('2023-09-01T08:00:00+08:00').toISOString())
      .toBe('2023-09-01T00:00:00.000Z');
  });
});
