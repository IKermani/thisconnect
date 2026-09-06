// SPDX-License-Identifier: GPL-3.0-or-later
import { get } from 'svelte/store';
import { describe, expect, it } from 'vitest';
import { logLines, pushLogLine, MAX_LOG_LINES } from './log';

describe('log store', () => {
  it('keeps only the most recent MAX_LOG_LINES entries', () => {
    for (let i = 0; i < MAX_LOG_LINES + 10; i++) {
      pushLogLine({ level: 'info', message: `line ${i}`, unix_millis: i });
    }
    const lines = get(logLines);
    expect(lines.length).toBe(MAX_LOG_LINES);
    expect(lines[lines.length - 1].message).toBe(`line ${MAX_LOG_LINES + 9}`);
  });
});
