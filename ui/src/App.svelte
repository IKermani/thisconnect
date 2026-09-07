<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import DaemonUnreachableBanner from './lib/components/DaemonUnreachableBanner.svelte';
  import PromptDialog from './lib/components/PromptDialog.svelte';
  import { connect, disconnect } from './lib/ipc';
  import { connectionState, initConnectionStore } from './lib/stores/connection';
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

  const tabs: { id: Tab; label: string }[] = [
    { id: 'connect', label: 'Connect' },
    { id: 'profiles', label: 'Profiles' },
    { id: 'proxy', label: 'Proxy' },
    { id: 'settings', label: 'Settings' },
    { id: 'log', label: 'Log' },
  ];

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

<div class="flex h-screen w-screen overflow-hidden bg-(--color-bg) text-(--color-fg) antialiased">
  <nav
    class="flex w-44 shrink-0 flex-col gap-1 border-r border-(--color-border) bg-(--color-surface) p-3"
  >
    <div class="mb-3 flex items-center gap-2 px-2 pt-1">
      <span
        class="h-2 w-2 rounded-full {$connectionState === 'connected'
          ? 'bg-(--color-accent)'
          : 'bg-(--color-fg-muted)'}"
      ></span>
      <span class="text-sm font-semibold tracking-tight">thisconnect</span>
    </div>

    {#each tabs as tab (tab.id)}
      <button
        onclick={() => (activeTab = tab.id)}
        aria-current={activeTab === tab.id}
        class="rounded-md px-3 py-1.5 text-left text-sm font-medium transition-colors
          {activeTab === tab.id
          ? 'bg-(--color-accent-muted) text-(--color-accent)'
          : 'text-(--color-fg-muted) hover:bg-(--color-surface-2) hover:text-(--color-fg)'}"
      >
        {tab.label}
      </button>
    {/each}
  </nav>

  <div class="flex min-w-0 flex-1 flex-col overflow-hidden">
    <DaemonUnreachableBanner />

    <main class="flex-1 overflow-y-auto p-6">
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
  </div>
</div>
<PromptDialog />
