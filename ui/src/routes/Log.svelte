<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { logLines } from '../lib/stores/log';
  import type { LogLevel } from '../lib/types';

  let filter = $state<LogLevel | 'all'>('all');

  const filtered = $derived(
    filter === 'all' ? $logLines : $logLines.filter((line) => line.level === filter),
  );

  function levelColor(level: LogLevel): string {
    if (level === 'error') return 'text-(--color-danger)';
    if (level === 'warn') return 'text-(--color-warning)';
    if (level === 'debug' || level === 'trace') return 'text-(--color-fg-muted)';
    return 'text-(--color-fg)';
  }
</script>

<div class="mx-auto flex max-w-3xl flex-col gap-4">
  <section class="rounded-xl border border-(--color-border) bg-(--color-surface) p-5">
    <div class="mb-3 flex items-center justify-between">
      <h2 class="text-sm font-semibold">Log</h2>
      <select
        bind:value={filter}
        class="rounded-md border border-(--color-border) bg-(--color-surface-2) px-2 py-1 text-xs text-(--color-fg) outline-none focus:border-(--color-accent)"
      >
        <option value="all">All</option>
        <option value="error">Error</option>
        <option value="warn">Warn</option>
        <option value="info">Info</option>
        <option value="debug">Debug</option>
        <option value="trace">Trace</option>
      </select>
    </div>
    <ul class="max-h-[60vh] space-y-0.5 overflow-y-auto font-mono text-xs">
      {#each filtered as line}
        <li class={levelColor(line.level)}>
          <span class="text-(--color-fg-muted)"
            >[{new Date(line.unix_millis).toLocaleTimeString()}]</span
          >
          {line.message}
        </li>
      {:else}
        <li class="text-(--color-fg-muted)">No log lines yet.</li>
      {/each}
    </ul>
  </section>
</div>
