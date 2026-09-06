<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import DaemonUnreachableBanner from './lib/components/DaemonUnreachableBanner.svelte';
  import PromptDialog from './lib/components/PromptDialog.svelte';
  import { connect, disconnect } from './lib/ipc';
  import { initConnectionStore } from './lib/stores/connection';
  import { initLogStore } from './lib/stores/log';
  import { initPromptStore } from './lib/stores/prompts';
  import { initProxyStore } from './lib/stores/proxy';
  import { refreshProfiles } from './lib/stores/profiles';
  import { selectedProfileId } from './lib/stores/selection';
  import Connect from './routes/Connect.svelte';
  import Profiles from './routes/Profiles.svelte';
  import ProxyInfo from './routes/ProxyInfo.svelte';
  import Settings from './routes/Settings.svelte';
  import Log from './routes/Log.svelte';

  type Tab = 'connect' | 'profiles' | 'proxy' | 'settings' | 'log';
  let activeTab = $state<Tab>('connect');

  onMount(async () => {
    await Promise.allSettled([initConnectionStore(), initLogStore(), initPromptStore()]);
    initProxyStore();
    try {
      await refreshProfiles();
    } catch {
      // Daemon may be down at startup; the Profiles tab has its own Refresh button.
    }

    await listen('tray-connect-requested', () => {
      let id: string | null = null;
      selectedProfileId.subscribe((v) => (id = v))();
      if (id !== null) void connect(id);
    });
    await listen('tray-disconnect-requested', () => {
      void disconnect();
    });
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

<DaemonUnreachableBanner />

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
