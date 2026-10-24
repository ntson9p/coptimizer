import { api, ApiError, startSession } from './api.js';
import { h } from './dom.js';
import { connectEvents } from './events.js';
import { loadStrings, t } from './i18n.js';
import { store } from './store.js';
import * as explorer from './views/explorer.js';
import * as overview from './views/overview.js';

const views = { overview, explorer };
let unmount = null;
let stopEvents = null;

async function main() {
  await loadStrings('en');
  renderChrome();
  let signedIn = false;
  try {
    signedIn = await startSession();
  } catch {
    signedIn = false;
  }
  if (!signedIn) return showMessage(t('locked.title'), t('locked.body'));
  try {
    const [status, drives] = await Promise.all([api.status(), api.drives()]);
    store.set({ status, drives, scan: status.lastScan, progress: status.lastScan?.progress ?? null });
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return showMessage(t('locked.title'), t('locked.body'));
    return showMessage(t('error.title'), t('error.generic', { message: e.message }));
  }
  stopEvents = connectEvents(onEvent, (conn) => {
    store.set({ conn });
    if (conn === 'unauthorized') showMessage(t('locked.title'), t('locked.body'));
  });
  window.addEventListener('hashchange', route);
  route();
}

function onEvent(type, data) {
  const { scan } = store.state;
  switch (type) {
    case 'hello':
      store.set({ status: data, scan: data.lastScan ?? scan });
      break;
    case 'scan.started':
      store.set({ scan: data, progress: data.progress });
      break;
    case 'scan.progress':
      if (scan && scan.id === data.scanId) store.set({ progress: data });
      break;
    case 'scan.finished':
      store.set({ scan: data, progress: data.progress });
      api.drives().then((drives) => store.set({ drives }), () => {});
      break;
  }
}

// parseHash reads routes like #/explorer?path=C%3A%5CUsers.
export function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [name, query = ''] = raw.split('?');
  return { name: name || 'overview', params: new URLSearchParams(query) };
}

function route() {
  const { name, params } = parseHash();
  const view = views[name] ?? overview;
  unmount?.();
  const root = document.getElementById('view');
  root.replaceChildren();
  unmount = view.mount(root, params) ?? null;
  for (const a of document.querySelectorAll('#tabs a')) {
    a.classList.toggle('active', a.dataset.route === (views[name] ? name : 'overview'));
  }
}

function renderChrome() {
  document.getElementById('app-name').textContent = t('app.name');
  document.getElementById('tabs').replaceChildren(
    h('a', { href: '#/', 'data-route': 'overview' }, t('nav.overview')),
    h('a', { href: '#/explorer', 'data-route': 'explorer' }, t('nav.explorer')),
  );
  const quit = document.getElementById('quit');
  quit.textContent = t('nav.quit');
  quit.addEventListener('click', async () => {
    if (!confirm(t('quit.confirm'))) return;
    try {
      await api.shutdown();
    } finally {
      stopEvents?.();
      showMessage(t('stopped.title'), t('stopped.body'));
    }
  });
  store.subscribe(renderPills);
}

function renderPills({ status, conn }) {
  const rights = document.getElementById('rights');
  const connEl = document.getElementById('conn');
  if (status) {
    const kind = status.demo ? 'demo' : status.elevated ? 'admin' : 'limited';
    rights.textContent = t(`rights.${kind}`);
    rights.title = t(`rights.${kind}.hint`);
    rights.className = `pill pill-${kind}`;
    rights.hidden = false;
    document.getElementById('quit').hidden = false;
  }
  connEl.textContent = t(`conn.${conn}`);
  connEl.className = `pill conn-${conn}`;
  connEl.hidden = false;
}

function showMessage(title, body) {
  unmount?.();
  unmount = null;
  document.getElementById('view').replaceChildren(
    h('section', { class: 'card message' }, h('h1', {}, title), h('p', {}, body)),
  );
}

main();
