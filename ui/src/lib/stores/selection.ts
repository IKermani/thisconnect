// SPDX-License-Identifier: GPL-3.0-or-later
import { writable } from 'svelte/store';
import type { ProfileId } from '../types';

export const selectedProfileId = writable<ProfileId | null>(null);
