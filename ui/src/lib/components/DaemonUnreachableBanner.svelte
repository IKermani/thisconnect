<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { reachability } from '../stores/connection';
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

<style>
  .banner {
    background: #b30000;
    color: white;
    padding: 0.5rem 1rem;
  }
</style>
