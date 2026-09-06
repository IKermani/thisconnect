// SPDX-License-Identifier: GPL-3.0-or-later
import { writable } from 'svelte/store';
import {
  onConnectionLost,
  onConnectionRestored,
  onDaemonEvent,
  reachability as reachabilityCmd,
  status,
} from '../ipc';
import type { ConnectionState, DaemonEvent, DaemonUnreachableReason, TunnelInfo } from '../types';

export const connectionState = writable<ConnectionState>('disconnected');
export const tunnel = writable<TunnelInfo | null>(null);
export const byteCount = writable<{ bytes_in: number; bytes_out: number }>({
  bytes_in: 0,
  bytes_out: 0,
});
export const lastError = writable<string | null>(null);

export type Reachability = { reachable: true } | { reachable: false; reason: DaemonUnreachableReason };
export const reachability = writable<Reachability>({ reachable: true });

export function applyDaemonEvent(event: DaemonEvent): void {
  switch (event.type) {
    case 'state':
      connectionState.set(event.state);
      lastError.set(event.detail);
      break;
    case 'byte_count':
      byteCount.set({ bytes_in: event.bytes_in, bytes_out: event.bytes_out });
      break;
    case 'tunnel_up':
      tunnel.set(event.tunnel);
      break;
    case 'tunnel_down':
      tunnel.set(null);
      break;
    default:
      break;
  }
}

export async function initConnectionStore(): Promise<void> {
  // Register listeners before any await that can reject, so a rejection
  // from the initial fetch below can never prevent registration.
  await onDaemonEvent(applyDaemonEvent);
  await onConnectionLost((reason: DaemonUnreachableReason) =>
    reachability.set({ reachable: false, reason }),
  );
  await onConnectionRestored(async () => {
    reachability.set({ reachable: true });
    try {
      const current = await status();
      connectionState.set(current.state);
      tunnel.set(current.tunnel);
      byteCount.set({ bytes_in: current.bytes_in, bytes_out: current.bytes_out });
      lastError.set(current.last_error);
    } catch {
      // A connection-lost event will follow if this races a fresh drop;
      // nothing useful to do with this particular failure.
    }
  });

  // Pull current reachability rather than relying solely on the push path:
  // the actor may have already settled reachability (e.g. daemon not
  // running) before this webview finished mounting and calling listen(),
  // and Tauri does not replay events emitted before a listener registers.
  const current = await reachabilityCmd();
  if (current.type === 'unreachable') {
    reachability.set({ reachable: false, reason: current.reason });
    return;
  }
  reachability.set({ reachable: true });

  try {
    const status_ = await status();
    connectionState.set(status_.state);
    tunnel.set(status_.tunnel);
    byteCount.set({ bytes_in: status_.bytes_in, bytes_out: status_.bytes_out });
    lastError.set(status_.last_error);
  } catch {
    // Daemon went down between the reachability pull above and this call;
    // the push listener registered above will catch the transition.
  }
}
