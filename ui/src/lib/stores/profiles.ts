// SPDX-License-Identifier: GPL-3.0-or-later
import { writable } from 'svelte/store';
import { profileDelete, profileImport, profileList } from '../ipc';
import type { ProfileSummary } from '../types';

export const profiles = writable<ProfileSummary[]>([]);

export async function refreshProfiles(): Promise<void> {
  profiles.set(await profileList());
}

export async function importProfile(name: string, config: string): Promise<ProfileSummary> {
  const summary = await profileImport(name, config);
  await refreshProfiles();
  return summary;
}

export async function deleteProfile(profileId: string): Promise<void> {
  await profileDelete(profileId);
  await refreshProfiles();
}
