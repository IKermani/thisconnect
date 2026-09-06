<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  import { activePrompt, replyToActivePrompt } from '../stores/prompts';

  let username = $state('');
  let password = $state('');
  let challengeResponse = $state('');
  let submitting = $state(false);

  async function submitUsernamePassword() {
    submitting = true;
    try {
      await replyToActivePrompt({ type: 'username_password', username, password });
    } finally {
      username = '';
      password = '';
      submitting = false;
    }
  }

  async function submitChallenge() {
    submitting = true;
    try {
      await replyToActivePrompt({ type: 'challenge_response', response: challengeResponse });
    } finally {
      challengeResponse = '';
      submitting = false;
    }
  }

  async function cancel() {
    submitting = true;
    try {
      await replyToActivePrompt({ type: 'cancel' });
    } finally {
      submitting = false;
    }
  }
</script>

{#if $activePrompt}
  <div class="prompt-backdrop">
    <div class="prompt-dialog">
      {#if $activePrompt.prompt.type === 'username_password'}
        <h2>Sign in</h2>
        <label>
          Username
          <input
            type="text"
            bind:value={username}
            placeholder={$activePrompt.prompt.username_hint ?? ''}
          />
        </label>
        <label>
          Password
          <input type="password" bind:value={password} />
        </label>
        <div class="actions">
          <button onclick={cancel} disabled={submitting}>Cancel</button>
          <button onclick={submitUsernamePassword} disabled={submitting}>Sign in</button>
        </div>
      {:else if $activePrompt.prompt.type === 'static_challenge' || $activePrompt.prompt.type === 'dynamic_challenge'}
        <h2>Verification required</h2>
        <p>{$activePrompt.prompt.challenge_text}</p>
        <label>
          Code
          <input
            type={$activePrompt.prompt.echo ? 'text' : 'password'}
            bind:value={challengeResponse}
          />
        </label>
        <div class="actions">
          <button onclick={cancel} disabled={submitting}>Cancel</button>
          <button onclick={submitChallenge} disabled={submitting}>Submit</button>
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .prompt-backdrop {
    position: fixed;
    inset: 0;
    background: color-mix(in srgb, black 45%, transparent);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .prompt-dialog {
    background: canvas;
    color: canvastext;
    padding: 1.5rem;
    border-radius: 0.5rem;
    min-width: 320px;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
  }
</style>
