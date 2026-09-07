<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { proxyInfo, proxyStats } from '../lib/stores/proxy';

  let copied = $state(false);
  let copyError = $state(false);

  async function copyUrl() {
    if (!$proxyInfo) return;
    try {
      await navigator.clipboard.writeText($proxyInfo.socks5h_url);
      copied = true;
      copyError = false;
      setTimeout(() => (copied = false), 1500);
    } catch {
      copyError = true;
      copied = false;
    }
  }
</script>

<div class="mx-auto flex max-w-2xl flex-col gap-5">
  {#if $proxyInfo}
    {#if !$proxyInfo.is_loopback_only}
      <div
        class="rounded-xl border border-(--color-warning) bg-(--color-warning-muted) px-4 py-3 text-sm text-(--color-warning)"
      >
        Proxy is listening on a non-loopback address ({$proxyInfo.listen_addrs.join(', ')}).
        {$proxyStats?.distinct_remote_peers ?? 0} distinct remote peer(s) seen this session.
      </div>
    {/if}

    <section class="rounded-xl border border-(--color-border) bg-(--color-surface) p-5">
      <h2 class="mb-4 text-sm font-semibold">Proxy</h2>
      <dl class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
        <dt class="text-(--color-fg-muted)">Listening on</dt>
        <dd class="font-mono">{$proxyInfo.listen_addrs.join(', ')}</dd>
        <dt class="text-(--color-fg-muted)">Auth</dt>
        <dd>
          {$proxyInfo.auth.type === 'disabled' ? 'disabled' : `enabled (${$proxyInfo.auth.username})`}
        </dd>
      </dl>

      <div class="mt-4 flex items-center gap-2">
        <input
          type="text"
          readonly
          value={$proxyInfo.socks5h_url}
          onclick={(e) => (e.target as HTMLInputElement).select()}
          class="flex-1 rounded-md border border-(--color-border) bg-(--color-surface-2) px-2.5 py-1.5 font-mono text-xs text-(--color-fg) outline-none focus:border-(--color-accent)"
        />
        <button
          onclick={copyUrl}
          class="shrink-0 rounded-md border border-(--color-border) px-3 py-1.5 text-xs font-medium hover:bg-(--color-surface-2)"
        >
          Copy
        </button>
      </div>
      {#if copied}
        <p class="mt-2 text-xs text-(--color-accent)">Copied</p>
      {/if}
      {#if copyError}
        <p class="mt-2 text-xs text-(--color-danger)">Copy failed — select the URL and copy manually.</p>
      {/if}
    </section>
  {:else}
    <p class="text-sm text-(--color-fg-muted)">Proxy is not active — connect a profile first.</p>
  {/if}
</div>
