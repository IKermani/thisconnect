<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { reachability } from '../stores/connection';
</script>

{#if !$reachability.reachable}
  <div
    class="border-b border-(--color-danger) bg-(--color-danger) px-4 py-2 text-sm font-medium text-white"
  >
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
