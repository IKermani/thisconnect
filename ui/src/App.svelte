<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { invoke } from '@tauri-apps/api/core';

  let pong = $state('');

  async function testPing() {
    pong = await invoke<string>('ping');
  }
</script>

<main>
  <h1>thisconnect</h1>
  <button onclick={testPing}>ping</button>
  {#if pong}<p>{pong}</p>{/if}
</main>
