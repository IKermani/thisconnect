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

{#if $proxyInfo}
  {#if !$proxyInfo.is_loopback_only}
    <div class="banner">
      Proxy is listening on a non-loopback address ({$proxyInfo.listen_addrs.join(', ')}).
      {$proxyStats?.distinct_remote_peers ?? 0} distinct remote peer(s) seen this session.
    </div>
  {/if}

  <section>
    <h2>Proxy</h2>
    <p>Listening on: {$proxyInfo.listen_addrs.join(', ')}</p>
    <p>Auth: {$proxyInfo.auth.type === 'disabled' ? 'disabled' : `enabled (${$proxyInfo.auth.username})`}</p>
    <button onclick={copyUrl}>Copy socks5h:// URL</button>
    {#if copied}<span>Copied</span>{/if}
    {#if copyError}<span class="error">Copy failed — select the URL below and copy manually.</span>{/if}
    <input
      type="text"
      readonly
      value={$proxyInfo.socks5h_url}
      onclick={(e) => (e.target as HTMLInputElement).select()}
    />
  </section>
{:else}
  <p>Proxy is not active — connect a profile first.</p>
{/if}

<style>
  .error {
    color: darkred;
  }
</style>
