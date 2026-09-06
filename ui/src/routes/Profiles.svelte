<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { deleteProfile, importProfile, profiles, refreshProfiles } from '../lib/stores/profiles';
  import { selectedProfileId } from '../lib/stores/selection';
  import type { UiError, ValidationError } from '../lib/types';

  let importName = $state('');
  let importConfig = $state('');
  let importError = $state<ValidationError | string | null>(null);
  let importing = $state(false);

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

<section>
  <h2>Import profile</h2>
  <label>
    Name
    <input type="text" bind:value={importName} />
  </label>
  <label>
    .ovpn contents
    <textarea rows="8" bind:value={importConfig}></textarea>
  </label>
  <button onclick={handleImport} disabled={importing || !importName || !importConfig}>
    Import
  </button>
  {#if importError}
    <p class="error">
      {typeof importError === 'string'
        ? importError
        : `${importError.reason}${importError.directive ? ` (${importError.directive})` : ''}: ${importError.detail}`}
    </p>
  {/if}
</section>

<section>
  <h2>Profiles</h2>
  <button onclick={refreshProfiles}>Refresh</button>
  <ul>
    {#each $profiles as profile (profile.id)}
      <li>
        <label>
          <input
            type="radio"
            name="selected-profile"
            checked={$selectedProfileId === profile.id}
            onchange={() => selectedProfileId.set(profile.id)}
          />
          {profile.name}
        </label>
        <button onclick={() => handleDelete(profile.id)}>Delete</button>
      </li>
    {:else}
      <li>No profiles imported yet.</li>
    {/each}
  </ul>
</section>

<style>
  .error {
    color: darkred;
  }
</style>
