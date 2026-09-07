<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { byteCount, connectionState, lastError, tunnel } from '../lib/stores/connection';
  import { profiles } from '../lib/stores/profiles';
  import { selectedProfileId } from '../lib/stores/selection';
  import { proxyStats } from '../lib/stores/proxy';
  import { logLines } from '../lib/stores/log';
  import { connect, disconnect } from '../lib/ipc';

  let acting = $state(false);

  async function handleConnect() {
    if ($selectedProfileId === null) return;
    acting = true;
    try {
      await connect($selectedProfileId);
    } finally {
      acting = false;
    }
  }

  async function handleDisconnect() {
    acting = true;
    try {
      await disconnect();
    } finally {
      acting = false;
    }
  }

  const selectedProfileName = $derived(
    $profiles.find((p) => p.id === $selectedProfileId)?.name ?? null,
  );

  const statusStyle = $derived(
    $connectionState === 'connected'
      ? 'bg-(--color-accent-muted) text-(--color-accent)'
      : $connectionState === 'connecting' || $connectionState === 'disconnecting'
        ? 'bg-(--color-warning-muted) text-(--color-warning)'
        : 'bg-(--color-surface-2) text-(--color-fg-muted)',
  );

  function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let value = n / 1024;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return `${value.toFixed(1)} ${units[unit]}`;
  }
</script>

<div class="mx-auto flex max-w-2xl flex-col gap-5">
  <section class="rounded-xl border border-(--color-border) bg-(--color-surface) p-5">
    <div class="flex items-center justify-between gap-4">
      <div>
        <span class="inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wide {statusStyle}">
          {$connectionState}
        </span>
        <p class="mt-2 text-sm text-(--color-fg-muted)">
          {selectedProfileName ?? 'No profile selected — pick one on the Profiles tab'}
        </p>
      </div>
      <div class="flex gap-2">
        <button
          onclick={handleConnect}
          disabled={acting || $selectedProfileId === null || $connectionState !== 'disconnected'}
          class="rounded-md bg-(--color-accent) px-4 py-2 text-sm font-medium text-(--color-accent-fg) transition hover:brightness-105 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Connect
        </button>
        <button
          onclick={handleDisconnect}
          disabled={acting || $connectionState === 'disconnected'}
          class="rounded-md border border-(--color-border) px-4 py-2 text-sm font-medium text-(--color-fg) transition hover:bg-(--color-surface-2) disabled:cursor-not-allowed disabled:opacity-40"
        >
          Disconnect
        </button>
      </div>
    </div>
    {#if $lastError}
      <p class="mt-3 rounded-md bg-(--color-danger-muted) px-3 py-2 text-sm text-(--color-danger)">
        {$lastError}
      </p>
    {/if}
  </section>

  {#if $tunnel}
    <section class="rounded-xl border border-(--color-border) bg-(--color-surface) p-5">
      <h3 class="mb-3 text-xs font-semibold uppercase tracking-wide text-(--color-fg-muted)">
        Tunnel
      </h3>
      <dl class="grid grid-cols-2 gap-x-6 gap-y-2 font-mono text-sm">
        <dt class="text-(--color-fg-muted)">Device</dt>
        <dd>{$tunnel.device}</dd>
        <dt class="text-(--color-fg-muted)">IPv4</dt>
        <dd>{$tunnel.ipv4 ?? '—'}</dd>
        <dt class="text-(--color-fg-muted)">IPv6</dt>
        <dd>{$tunnel.ipv6 ?? ($tunnel.tunnel_has_v6 ? '—' : 'not offered by this tunnel')}</dd>
        <dt class="text-(--color-fg-muted)">MTU</dt>
        <dd>{$tunnel.mtu ?? '—'}</dd>
        <dt class="text-(--color-fg-muted)">DNS</dt>
        <dd>{$tunnel.dns_servers.join(', ') || '—'} <span class="text-(--color-fg-muted)">({$tunnel.dns_source})</span></dd>
      </dl>
    </section>
  {/if}

  <div class="grid grid-cols-2 gap-5">
    <section class="rounded-xl border border-(--color-border) bg-(--color-surface) p-5">
      <h3 class="mb-3 text-xs font-semibold uppercase tracking-wide text-(--color-fg-muted)">
        Bytes
      </h3>
      <div class="flex justify-between font-mono text-sm">
        <span class="text-(--color-fg-muted)">In</span>
        <span>{formatBytes($byteCount.bytes_in)}</span>
      </div>
      <div class="mt-1 flex justify-between font-mono text-sm">
        <span class="text-(--color-fg-muted)">Out</span>
        <span>{formatBytes($byteCount.bytes_out)}</span>
      </div>
    </section>

    {#if $proxyStats}
      <section class="rounded-xl border border-(--color-border) bg-(--color-surface) p-5">
        <h3 class="mb-3 text-xs font-semibold uppercase tracking-wide text-(--color-fg-muted)">
          Leak proof
        </h3>
        <div class="flex justify-between font-mono text-sm">
          <span class="text-(--color-fg-muted)">Local DNS</span>
          <span>{$proxyStats.local_dns_lookups}</span>
        </div>
        <div class="mt-1 flex justify-between font-mono text-sm">
          <span class="text-(--color-fg-muted)">Tunnelled DNS</span>
          <span>{$proxyStats.tunnel_dns_lookups}</span>
        </div>
      </section>
    {/if}
  </div>

  <section class="rounded-xl border border-(--color-border) bg-(--color-surface) p-5">
    <h3 class="mb-3 text-xs font-semibold uppercase tracking-wide text-(--color-fg-muted)">Log</h3>
    <ul class="max-h-52 space-y-0.5 overflow-y-auto font-mono text-xs">
      {#each $logLines.slice(-50) as line}
        <li
          class={line.level === 'error'
            ? 'text-(--color-danger)'
            : line.level === 'warn'
              ? 'text-(--color-warning)'
              : 'text-(--color-fg-muted)'}
        >
          {line.message}
        </li>
      {/each}
    </ul>
  </section>
</div>
