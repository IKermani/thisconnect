<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { onMount } from 'svelte';
  import PromptDialog from './lib/components/PromptDialog.svelte';
  import { initConnectionStore } from './lib/stores/connection';
  import { initLogStore } from './lib/stores/log';
  import { initPromptStore } from './lib/stores/prompts';
  import { initProxyStore } from './lib/stores/proxy';
  import { refreshProfiles } from './lib/stores/profiles';
  import Connect from './routes/Connect.svelte';

  onMount(async () => {
    await Promise.all([initConnectionStore(), initLogStore(), initPromptStore()]);
    initProxyStore();
    await refreshProfiles();
  });
</script>

<main>
  <Connect />
</main>
<PromptDialog />
