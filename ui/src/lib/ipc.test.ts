// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it, vi } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(async (cmd: string) => {
    if (cmd === 'profile_list') return [];
    throw new Error(`unexpected command in test: ${cmd}`);
  }),
}));

import { profileList } from './ipc';

describe('profileList', () => {
  it('invokes the profile_list command and returns its result', async () => {
    const profiles = await profileList();
    expect(profiles).toEqual([]);
  });
});
