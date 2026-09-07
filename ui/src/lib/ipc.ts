// SPDX-License-Identifier: GPL-3.0-or-later
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type {
  ConnectionStatus,
  DaemonEvent,
  DaemonUnreachableReason,
  CredentialPrompt,
  PickedProfileFile,
  ProfileId,
  ProfileSummary,
  PromptId,
  PromptReply,
  ProxyInfo,
  ProxySessionStats,
  ReachabilityWire,
} from './types';

export function profileImport(name: string, config: string): Promise<ProfileSummary> {
  return invoke('profile_import', { name, config });
}

export function profilePickFile(): Promise<PickedProfileFile | null> {
  return invoke('profile_pick_file');
}

export function profileList(): Promise<ProfileSummary[]> {
  return invoke('profile_list');
}

export function profileGet(profileId: ProfileId): Promise<ProfileSummary> {
  return invoke('profile_get', { profileId });
}

export function profileDelete(profileId: ProfileId): Promise<void> {
  return invoke('profile_delete', { profileId });
}

export function connect(profileId: ProfileId): Promise<void> {
  return invoke('connect', { profileId });
}

export function disconnect(): Promise<void> {
  return invoke('disconnect');
}

export function status(): Promise<ConnectionStatus> {
  return invoke('status');
}

export function proxyInfo(): Promise<ProxyInfo> {
  return invoke('proxy_info');
}

export function proxyStats(): Promise<ProxySessionStats> {
  return invoke('proxy_stats');
}

export function promptReply(promptId: PromptId, reply: PromptReply): Promise<void> {
  return invoke('prompt_reply', { promptId, reply });
}

export function reachability(): Promise<ReachabilityWire> {
  return invoke('reachability');
}

export function onDaemonEvent(handler: (event: DaemonEvent) => void): Promise<UnlistenFn> {
  return listen<DaemonEvent>('daemon-event', (e) => handler(e.payload));
}

export function onDaemonPrompt(
  handler: (promptId: PromptId, prompt: CredentialPrompt) => void,
): Promise<UnlistenFn> {
  return listen<{ prompt_id: PromptId; prompt: CredentialPrompt }>('daemon-prompt', (e) =>
    handler(e.payload.prompt_id, e.payload.prompt),
  );
}

export function onPromptCancelled(handler: (promptId: PromptId) => void): Promise<UnlistenFn> {
  return listen<{ prompt_id: PromptId }>('prompt-cancelled', (e) =>
    handler(e.payload.prompt_id),
  );
}

export function onConnectionLost(
  handler: (reason: DaemonUnreachableReason) => void,
): Promise<UnlistenFn> {
  return listen<DaemonUnreachableReason>('connection-lost', (e) => handler(e.payload));
}

export function onConnectionRestored(handler: () => void): Promise<UnlistenFn> {
  return listen('connection-restored', () => handler());
}
