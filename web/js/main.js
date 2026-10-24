import { api, ApiError, startSession } from './api.js';
import { h } from './dom.js';
import { connectEvents } from './events.js';
import { loadStrings, t } from './i18n.js';
import { store } from './store.js';
import * as activity from './views/activity.js';
import * as explorer from './views/explorer.js';
import * as findings from './views/findings.js';
import * as overview from './views/overview.js';

const views = { overview, findings, explorer, activity };
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
    const [status, drives, system, jobs] = await Promise.all([api.status(), api.drives(), api.system(), api.jobs()]);
    store.set({
      status, drives, system: system.probes, scan: status.lastScan, progress: status.lastScan?.progress ?? null,
      jobs: Object.fromEntries(jobs.map((j) => [j.id, j])),
    });
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
  const { scan, status } = store.state;
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
    case 'scan.updated':
      // A cleanup measured some folders again: same scan, new findings.
      if (type === 'scan.finished' || scan?.id === data.id) store.set({ scan: data, progress: data.progress });
      api.drives().then((drives) => store.set({ drives }), () => {});
      break;
    case 'system.updated': {
      const others = store.state.system.filter((p) => p.name !== data.name);
      store.set({ system: [...others, data] });
      break;
    }
    case 'job.queued':
    case 'job.started':
    case 'job.finished':
      store.set({ jobs: { ...store.state.jobs, [data.id]: data }, status: { ...status, busy: busyAfter(data) } });
      if (type === 'job.finished') api.drives().then((drives) => store.set({ drives }), () => {});
      break;
    case 'job.progress':
      store.set({ jobProgress: { ...store.state.jobProgress, [data.jobId]: data.progress } });
      break;
    case 'job.log': {
      const lines = [...(store.state.jobLog[data.jobId] ?? []), data.line].slice(-200);
      store.set({ jobLog: { ...store.state.jobLog, [data.jobId]: lines } });
      break;
    }
    case 'config.updated':
      store.set({ status: { ...status, simulate: data.simulate, cleanups: data.cleanups } });
      break;
  }
}

// busyAfter tells whether a cleanup is still queued or running once job has
// its new state.
function busyAfter(job) {
  const jobs = { ...store.state.jobs, [job.id]: job };
  return Object.values(jobs).some((j) => j.state === 'queued' || j.state === 'running');
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
    h('a', { href: '#/findings', 'data-route': 'findings' }, t('nav.findings')),
    h('a', { href: '#/explorer', 'data-route': 'explorer' }, t('nav.explorer')),
    h('a', { href: '#/activity', 'data-route': 'activity' }, t('nav.activity')),
  );
  const quit = document.getElementById('quit');
  quit.textContent = t('nav.quit');
  quit.addEventListener('click', async () => {
    if (!confirm(t('quit.confirm'))) return;
    try {
      await api.shutdown();
    } catch (e) {
      // A cleanup that is running keeps the server up.
      alert(t('error.generic', { message: e.message }));
      return;
    }
    stopEvents?.();
    showMessage(t('stopped.title'), t('stopped.body'));
  });
  store.subscribe(renderPills);
}

function renderPills({ status, conn }) {
  const rights = document.getElementById('rights');
  const connEl = document.getElementById('conn');
  const sim = document.getElementById('simulate');
  if (status) {
    const kind = status.demo ? 'demo' : status.elevated ? 'admin' : 'limited';
    rights.textContent = t(`rights.${kind}`);
    rights.title = t(`rights.${kind}.hint`);
    rights.className = `pill pill-${kind}`;
    rights.hidden = false;
    sim.textContent = t('simulate.pill');
    sim.title = t('simulate.pill.hint');
    sim.hidden = !status.simulate;
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
