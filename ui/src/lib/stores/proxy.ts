// SPDX-License-Identifier: GPL-3.0-or-later
import { writable } from 'svelte/store';
import {
  onDaemonEvent,
  proxyInfo as fetchProxyInfo,
  proxyStats as fetchProxyStats,
} from '../ipc';
import type { ProxyInfo, ProxySessionStats } from '../types';
import { connectionState } from './connection';

export const proxyInfo = writable<ProxyInfo | null>(null);
export const proxyStats = writable<ProxySessionStats | null>(null);

let pollHandle: ReturnType<typeof setInterval> | null = null;

export function startProxyStatsPolling(): void {
  if (pollHandle !== null) return;
  pollHandle = setInterval(async () => {
    try {
      proxyStats.set(await fetchProxyStats());
    } catch {
      // Tunnel isn't up yet, or the daemon is between states — the next
      // tick tries again; nothing to surface mid-poll.
    }
  }, 2000);
}

export function stopProxyStatsPolling(): void {
  if (pollHandle !== null) {
    clearInterval(pollHandle);
    pollHandle = null;
  }
}

export function initProxyStore(): void {
  connectionState.subscribe((state) => {
    if (state === 'connected') {
      fetchProxyInfo()
        .then((info) => proxyInfo.set(info))
        .catch(() => proxyInfo.set(null));
      startProxyStatsPolling();
    } else {
      stopProxyStatsPolling();
      proxyStats.set(null);
    }
  });

  void onDaemonEvent((event) => {
    if (event.type === 'proxy_listener_up') {
      fetchProxyInfo()
        .then((info) => proxyInfo.set(info))
        .catch(() => proxyInfo.set(null));
    } else if (event.type === 'proxy_listener_down') {
      proxyInfo.set(null);
    }
  });
}
