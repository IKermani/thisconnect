<script lang="ts">
  // SPDX-License-Identifier: GPL-3.0-or-later
  // Local-only for now: shared::ipc has no settings request/response pair yet
  // (see design doc §11). Values here are not persisted across restarts.
  let tunnelFallbackDns = $state('9.9.9.9, 1.1.1.1');
  let totpEnabled = $state(false);
</script>

<div class="mx-auto flex max-w-2xl flex-col gap-5">
  <section class="rounded-xl border border-(--color-border) bg-(--color-surface) p-5">
    <h2 class="mb-1 text-sm font-semibold">Settings</h2>
    <p class="mb-4 text-xs text-(--color-fg-muted) italic">
      Not yet wired to the daemon — there is no settings request in the current IPC protocol.
      Changes here are not saved.
    </p>

    <label class="flex flex-col gap-1 text-sm text-(--color-fg-muted)">
      Tunnel fallback DNS
      <input
        type="text"
        bind:value={tunnelFallbackDns}
        class="rounded-md border border-(--color-border) bg-(--color-surface-2) px-2.5 py-1.5 font-mono text-sm text-(--color-fg) outline-none focus:border-(--color-accent)"
      />
    </label>

    <label class="mt-4 flex items-center gap-2 text-sm">
      <input type="checkbox" bind:checked={totpEnabled} class="accent-(--color-accent)" />
      Enable TOTP autofill
    </label>

    {#if totpEnabled}
      <p class="mt-3 rounded-md bg-(--color-warning-muted) px-3 py-2 text-sm text-(--color-warning)">
        Storing a TOTP seed next to your password in the same application collapses two factors
        of authentication into one: anything that compromises this machine gets both. Every
        other OpenVPN client deliberately pushes TOTP to an external tool for exactly this
        reason. This is offered as a convenience tradeoff that is yours to make.
      </p>
    {/if}
  </section>
</div>
