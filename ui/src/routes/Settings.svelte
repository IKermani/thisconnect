<script lang="ts">
	// SPDX-License-Identifier: GPL-3.0-or-later
	// Local-only for now: shared::ipc has no settings request/response pair yet
	// (see design doc §11). Values here are not persisted across restarts.
	let tunnelFallbackDns = $state('9.9.9.9, 1.1.1.1');
	let totpEnabled = $state(false);
</script>

<section>
	<h2>Settings</h2>
	<p class="notice">
		Not yet wired to the daemon — there is no settings request in the current IPC protocol.
		Changes here are not saved.
	</p>
	<label>
		Tunnel fallback DNS
		<input type="text" bind:value={tunnelFallbackDns} />
	</label>
	<label>
		<input type="checkbox" bind:checked={totpEnabled} />
		Enable TOTP autofill
	</label>
	{#if totpEnabled}
		<p class="warning">
			Storing a TOTP seed next to your password in the same application collapses two factors
			of authentication into one: anything that compromises this machine gets both. Every
			other OpenVPN client deliberately pushes TOTP to an external tool for exactly this
			reason. This is offered as a convenience tradeoff that is yours to make.
		</p>
	{/if}
</section>

<style>
	.notice {
		color: gray;
		font-style: italic;
	}
	.warning {
		color: darkorange;
	}
</style>
