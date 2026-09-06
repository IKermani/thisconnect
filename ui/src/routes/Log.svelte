<script lang="ts">
	// SPDX-License-Identifier: GPL-3.0-or-later
	import { logLines } from '../lib/stores/log';
	import type { LogLevel } from '../lib/types';

	let filter = $state<LogLevel | 'all'>('all');

	const filtered = $derived(
		filter === 'all' ? $logLines : $logLines.filter((line) => line.level === filter),
	);
</script>

<section>
	<h2>Log</h2>
	<label>
		Filter
		<select bind:value={filter}>
			<option value="all">All</option>
			<option value="error">Error</option>
			<option value="warn">Warn</option>
			<option value="info">Info</option>
			<option value="debug">Debug</option>
			<option value="trace">Trace</option>
		</select>
	</label>
	<ul class="log">
		{#each filtered as line}
			<li>[{new Date(line.unix_millis).toLocaleTimeString()}] {line.message}</li>
		{:else}
			<li>No log lines yet.</li>
		{/each}
	</ul>
</section>

<style>
	.log {
		font-family: monospace;
		font-size: 0.85rem;
		max-height: 60vh;
		overflow-y: auto;
	}
</style>
