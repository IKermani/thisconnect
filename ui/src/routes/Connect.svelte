<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { byteCount, connectionState, lastError, reachability, tunnel } from '../lib/stores/connection';
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
</script>

{#if !$reachability.reachable}
  <div class="banner">
    {#if $reachability.reason.reason === 'permission_denied'}
      Daemon unreachable: your account was just added to the required group. Log out and back
      in, then reopen thisconnect.
    {:else if $reachability.reason.reason === 'protocol_mismatch'}
      Daemon speaks a different protocol version ({$reachability.reason.daemon_version}) than
      this GUI. Update one of them to match.
    {:else}
      thisconnectd is not running. Start the daemon service and reopen thisconnect.
    {/if}
  </div>
{/if}

<section>
  <h2>Status: {$connectionState}</h2>
  <p>Selected profile: {selectedProfileName ?? 'none — pick one on the Profiles tab'}</p>
  <button onclick={handleConnect} disabled={acting || $selectedProfileId === null || $connectionState !== 'disconnected'}>
    Connect
  </button>
  <button onclick={handleDisconnect} disabled={acting || $connectionState === 'disconnected'}>
    Disconnect
  </button>
  {#if $lastError}
    <p class="error">{$lastError}</p>
  {/if}
</section>

{#if $tunnel}
  <section>
    <h3>Tunnel</h3>
    <p>Device: {$tunnel.device}</p>
    <p>IPv4: {$tunnel.ipv4 ?? '—'}</p>
    <p>IPv6: {$tunnel.ipv6 ?? (($tunnel.tunnel_has_v6) ? '—' : 'not offered by this tunnel')}</p>
    <p>MTU: {$tunnel.mtu ?? '—'}</p>
    <p>DNS: {$tunnel.dns_servers.join(', ') || '—'} ({$tunnel.dns_source})</p>
  </section>
{/if}

<section>
  <h3>Bytes</h3>
  <p>In: {$byteCount.bytes_in}</p>
  <p>Out: {$byteCount.bytes_out}</p>
</section>

{#if $proxyStats}
  <section>
    <h3>Leak proof</h3>
    <p>{$proxyStats.local_dns_lookups} local DNS lookups this session</p>
    <p>{$proxyStats.tunnel_dns_lookups} tunnelled DNS lookups this session</p>
  </section>
{/if}

<section>
  <h3>Log</h3>
  <ul class="log">
    {#each $logLines.slice(-50) as line}
      <li class="log-{line.level}">{line.message}</li>
    {/each}
  </ul>
</section>

<style>
  .banner {
    background: #b30000;
    color: white;
    padding: 0.5rem 1rem;
  }
  .error {
    color: darkred;
  }
  .log {
    max-height: 200px;
    overflow-y: auto;
    font-family: monospace;
    font-size: 0.85rem;
  }
</style>
