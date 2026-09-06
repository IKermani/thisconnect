// SPDX-License-Identifier: GPL-3.0-or-later
import { writable } from 'svelte/store';
import { onDaemonEvent } from '../ipc';
import type { LogLevel } from '../types';

export const MAX_LOG_LINES = 500;

export interface LogLine {
  level: LogLevel;
  message: string;
  unix_millis: number;
}

export const logLines = writable<LogLine[]>([]);

export function pushLogLine(line: LogLine): void {
  logLines.update((lines) => {
    const next = [...lines, line];
    return next.length > MAX_LOG_LINES ? next.slice(next.length - MAX_LOG_LINES) : next;
  });
}

export async function initLogStore(): Promise<void> {
  await onDaemonEvent((event) => {
    if (event.type === 'log') {
      pushLogLine({ level: event.level, message: event.message, unix_millis: event.unix_millis });
    }
  });
}
