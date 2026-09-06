// SPDX-License-Identifier: GPL-3.0-or-later
import { writable } from 'svelte/store';
import { onConnectionLost, onConnectionRestored, onDaemonEvent, status } from '../ipc';
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
  const current = await status();
  connectionState.set(current.state);
  tunnel.set(current.tunnel);
  byteCount.set({ bytes_in: current.bytes_in, bytes_out: current.bytes_out });
  lastError.set(current.last_error);

  await onDaemonEvent(applyDaemonEvent);
  await onConnectionLost((reason: DaemonUnreachableReason) =>
    reachability.set({ reachable: false, reason }),
  );
  await onConnectionRestored(() => reachability.set({ reachable: true }));
}
