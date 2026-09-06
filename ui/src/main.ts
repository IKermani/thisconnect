// SPDX-License-Identifier: GPL-3.0-or-later
import { mount } from 'svelte';
import App from './App.svelte';

const target = document.getElementById('app');
if (!target) {
  throw new Error('missing #app mount point');
}

export default mount(App, { target });
