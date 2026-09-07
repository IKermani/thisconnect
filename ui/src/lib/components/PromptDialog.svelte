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
  <div class="fixed inset-0 flex items-center justify-center bg-black/45 backdrop-blur-[2px]">
    <div
      class="flex min-w-80 flex-col gap-3 rounded-xl border border-(--color-border) bg-(--color-surface) p-6 shadow-2xl"
    >
      {#if $activePrompt.prompt.type === 'username_password'}
        <h2 class="text-base font-semibold">Sign in</h2>
        <label class="flex flex-col gap-1 text-sm text-(--color-fg-muted)">
          Username
          <input
            type="text"
            bind:value={username}
            placeholder={$activePrompt.prompt.username_hint ?? ''}
            class="rounded-md border border-(--color-border) bg-(--color-surface-2) px-2.5 py-1.5 text-sm text-(--color-fg) outline-none focus:border-(--color-accent)"
          />
        </label>
        <label class="flex flex-col gap-1 text-sm text-(--color-fg-muted)">
          Password
          <input
            type="password"
            bind:value={password}
            class="rounded-md border border-(--color-border) bg-(--color-surface-2) px-2.5 py-1.5 text-sm text-(--color-fg) outline-none focus:border-(--color-accent)"
          />
        </label>
        <div class="mt-1 flex justify-end gap-2">
          <button
            onclick={cancel}
            disabled={submitting}
            class="rounded-md px-3 py-1.5 text-sm font-medium text-(--color-fg-muted) hover:bg-(--color-surface-2) disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onclick={submitUsernamePassword}
            disabled={submitting}
            class="rounded-md bg-(--color-accent) px-3 py-1.5 text-sm font-medium text-(--color-accent-fg) hover:brightness-105 disabled:opacity-50"
          >
            Sign in
          </button>
        </div>
      {:else if $activePrompt.prompt.type === 'static_challenge' || $activePrompt.prompt.type === 'dynamic_challenge'}
        <h2 class="text-base font-semibold">Verification required</h2>
        <p class="text-sm text-(--color-fg-muted)">{$activePrompt.prompt.challenge_text}</p>
        <label class="flex flex-col gap-1 text-sm text-(--color-fg-muted)">
          Code
          <input
            type={$activePrompt.prompt.echo ? 'text' : 'password'}
            bind:value={challengeResponse}
            class="rounded-md border border-(--color-border) bg-(--color-surface-2) px-2.5 py-1.5 text-sm text-(--color-fg) outline-none focus:border-(--color-accent)"
          />
        </label>
        <div class="mt-1 flex justify-end gap-2">
          <button
            onclick={cancel}
            disabled={submitting}
            class="rounded-md px-3 py-1.5 text-sm font-medium text-(--color-fg-muted) hover:bg-(--color-surface-2) disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onclick={submitChallenge}
            disabled={submitting}
            class="rounded-md bg-(--color-accent) px-3 py-1.5 text-sm font-medium text-(--color-accent-fg) hover:brightness-105 disabled:opacity-50"
          >
            Submit
          </button>
        </div>
      {/if}
    </div>
  </div>
{/if}
