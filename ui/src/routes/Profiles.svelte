<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { profilePickFile } from '../lib/ipc';
  import { deleteProfile, importProfile, profiles, refreshProfiles } from '../lib/stores/profiles';
  import { selectedProfileId } from '../lib/stores/selection';
  import type { UiError, ValidationError } from '../lib/types';

  let importName = $state('');
  let importConfig = $state('');
  let importError = $state<ValidationError | string | null>(null);
  let importing = $state(false);
  let picking = $state(false);

  async function handleBrowse() {
    picking = true;
    try {
      const picked = await profilePickFile();
      if (picked === null) return;
      importName = picked.name;
      importConfig = picked.config;
      importError = null;
    } catch (err) {
      importError = String(err);
    } finally {
      picking = false;
    }
  }

  function isUiError(err: unknown): err is UiError {
    return typeof err === 'object' && err !== null && 'type' in err;
  }

  async function handleImport() {
    importing = true;
    importError = null;
    try {
      await importProfile(importName, importConfig);
      importName = '';
      importConfig = '';
    } catch (err) {
      if (isUiError(err) && err.type === 'daemon' && err.validation) {
        importError = err.validation;
      } else if (isUiError(err) && err.type === 'daemon') {
        importError = err.message;
      } else if (isUiError(err) && err.type === 'internal') {
        importError = err.message;
      } else if (isUiError(err)) {
        importError = 'Request timed out.';
      } else {
        importError = String(err);
      }
    } finally {
      importing = false;
    }
  }

  async function handleDelete(id: string) {
    await deleteProfile(id);
    if ($selectedProfileId === id) {
      selectedProfileId.set(null);
    }
  }
</script>

<div class="mx-auto flex max-w-2xl flex-col gap-5">
  <section class="rounded-xl border border-(--color-border) bg-(--color-surface) p-5">
    <div class="mb-4 flex items-center justify-between">
      <h2 class="text-sm font-semibold">Import profile</h2>
      <button
        onclick={handleBrowse}
        disabled={picking}
        class="rounded-md border border-(--color-border) px-3 py-1 text-xs font-medium text-(--color-fg-muted) hover:bg-(--color-surface-2) hover:text-(--color-fg) disabled:cursor-not-allowed disabled:opacity-40"
      >
        Browse…
      </button>
    </div>
    <div class="flex flex-col gap-3">
      <label class="flex flex-col gap-1 text-sm text-(--color-fg-muted)">
        Name
        <input
          type="text"
          bind:value={importName}
          class="rounded-md border border-(--color-border) bg-(--color-surface-2) px-2.5 py-1.5 text-sm text-(--color-fg) outline-none focus:border-(--color-accent)"
        />
      </label>
      <label class="flex flex-col gap-1 text-sm text-(--color-fg-muted)">
        .ovpn contents
        <textarea
          rows="8"
          bind:value={importConfig}
          class="resize-y rounded-md border border-(--color-border) bg-(--color-surface-2) px-2.5 py-1.5 font-mono text-xs text-(--color-fg) outline-none focus:border-(--color-accent)"
        ></textarea>
      </label>
      <div>
        <button
          onclick={handleImport}
          disabled={importing || !importName || !importConfig}
          class="rounded-md bg-(--color-accent) px-4 py-2 text-sm font-medium text-(--color-accent-fg) transition hover:brightness-105 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Import
        </button>
      </div>
      {#if importError}
        <p class="rounded-md bg-(--color-danger-muted) px-3 py-2 text-sm text-(--color-danger)">
          {typeof importError === 'string'
            ? importError
            : `${importError.reason}${importError.directive ? ` (${importError.directive})` : ''}: ${importError.detail}`}
        </p>
      {/if}
    </div>
  </section>

  <section class="rounded-xl border border-(--color-border) bg-(--color-surface) p-5">
    <div class="mb-3 flex items-center justify-between">
      <h2 class="text-sm font-semibold">Profiles</h2>
      <button
        onclick={refreshProfiles}
        class="rounded-md border border-(--color-border) px-3 py-1 text-xs font-medium text-(--color-fg-muted) hover:bg-(--color-surface-2) hover:text-(--color-fg)"
      >
        Refresh
      </button>
    </div>
    <ul class="flex flex-col divide-y divide-(--color-border)">
      {#each $profiles as profile (profile.id)}
        <li class="flex items-center justify-between gap-3 py-2.5 first:pt-0 last:pb-0">
          <label class="flex flex-1 cursor-pointer items-center gap-2.5 text-sm">
            <input
              type="radio"
              name="selected-profile"
              checked={$selectedProfileId === profile.id}
              onchange={() => selectedProfileId.set(profile.id)}
              class="accent-(--color-accent)"
            />
            {profile.name}
          </label>
          <button
            onclick={() => handleDelete(profile.id)}
            class="rounded-md px-2.5 py-1 text-xs font-medium text-(--color-danger) hover:bg-(--color-danger-muted)"
          >
            Delete
          </button>
        </li>
      {:else}
        <li class="py-2 text-sm text-(--color-fg-muted)">No profiles imported yet.</li>
      {/each}
    </ul>
  </section>
</div>
