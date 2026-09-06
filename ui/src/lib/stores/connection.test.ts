// SPDX-License-Identifier: GPL-3.0-or-later
import { get } from 'svelte/store';
import { describe, expect, it } from 'vitest';
import { applyDaemonEvent, connectionState, reachability, tunnel } from './connection';

describe('connection store', () => {
  it('updates state and tunnel info from daemon events', () => {
    applyDaemonEvent({ type: 'state', state: 'connecting', detail: null });
    expect(get(connectionState)).toBe('connecting');

    applyDaemonEvent({
      type: 'tunnel_up',
      tunnel: {
        device: 'tun0',
        ipv4: '10.8.0.2',
        ipv6: null,
        mtu: 1400,
        tunnel_has_v6: false,
        dns_servers: ['10.8.0.1'],
        dns_source: 'pushed',
        search_domains: [],
      },
    });
    expect(get(tunnel)?.device).toBe('tun0');

    applyDaemonEvent({ type: 'tunnel_down', reason: 'EXITING' });
    expect(get(tunnel)).toBeNull();
  });

  it('tracks reachability independently of connection state', () => {
    reachability.set({ reachable: true });
    expect(get(reachability)).toEqual({ reachable: true });
  });
});
