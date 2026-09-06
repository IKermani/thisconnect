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
  import Profiles from './routes/Profiles.svelte';
  import ProxyInfo from './routes/ProxyInfo.svelte';
  import Settings from './routes/Settings.svelte';
  import Log from './routes/Log.svelte';

  type Tab = 'connect' | 'profiles' | 'proxy' | 'settings' | 'log';
  let activeTab = $state<Tab>('connect');

  onMount(async () => {
    await Promise.all([initConnectionStore(), initLogStore(), initPromptStore()]);
    initProxyStore();
    await refreshProfiles();
  });
</script>

<nav>
  <button onclick={() => (activeTab = 'connect')} aria-current={activeTab === 'connect'}>
    Connect
  </button>
  <button onclick={() => (activeTab = 'profiles')} aria-current={activeTab === 'profiles'}>
    Profiles
  </button>
  <button onclick={() => (activeTab = 'proxy')} aria-current={activeTab === 'proxy'}>
    Proxy
  </button>
  <button onclick={() => (activeTab = 'settings')} aria-current={activeTab === 'settings'}>
    Settings
  </button>
  <button onclick={() => (activeTab = 'log')} aria-current={activeTab === 'log'}>
    Log
  </button>
</nav>

<main>
  {#if activeTab === 'connect'}
    <Connect />
  {:else if activeTab === 'profiles'}
    <Profiles />
  {:else if activeTab === 'proxy'}
    <ProxyInfo />
  {:else if activeTab === 'settings'}
    <Settings />
  {:else if activeTab === 'log'}
    <Log />
  {/if}
</main>
<PromptDialog />
