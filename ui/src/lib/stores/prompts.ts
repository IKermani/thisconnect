// SPDX-License-Identifier: GPL-3.0-or-later
import { writable } from 'svelte/store';
import { onDaemonPrompt, onPromptCancelled, promptReply as sendPromptReply } from '../ipc';
import type { CredentialPrompt, PromptId, PromptReply } from '../types';

export const activePrompt = writable<{ promptId: PromptId; prompt: CredentialPrompt } | null>(
  null,
);

export async function initPromptStore(): Promise<void> {
  await onDaemonPrompt((promptId, prompt) => {
    activePrompt.update((current) => {
      if (current !== null) {
        // Daemon contract violation (design doc §6): at most one prompt is
        // ever supposed to be live. Log and keep the existing one rather
        // than silently dropping either.
        console.error('received a second prompt while one was already active', {
          existing: current.promptId,
          incoming: promptId,
        });
        return current;
      }
      return { promptId, prompt };
    });
  });

  await onPromptCancelled((promptId) => {
    activePrompt.update((current) => (current?.promptId === promptId ? null : current));
  });
}

export async function replyToActivePrompt(reply: PromptReply): Promise<void> {
  let promptId: PromptId | null = null;
  activePrompt.subscribe((current) => {
    promptId = current?.promptId ?? null;
  })();
  if (promptId === null) {
    throw new Error('no active prompt to reply to');
  }
  await sendPromptReply(promptId, reply);
  activePrompt.set(null);
}
