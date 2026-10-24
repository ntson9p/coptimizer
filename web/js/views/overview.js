import { api } from '../api.js';
import { bar, h, setBar } from '../dom.js';
import { bytes, count, duration, percent } from '../format.js';
import { t } from '../i18n.js';
import { store } from '../store.js';

// The overview shows the drives, starts scans, follows their progress and
// sums up the result.
export function mount(root) {
  const drivesCard = h('section', { class: 'card' });
  const scanCard = h('section', { class: 'card' });
  const topCard = h('section', { class: 'card', hidden: true });
  root.append(h('h1', {}, t('nav.overview')), drivesCard, scanCard, topCard);

  let drivesKey = '';
  let scanKey = '';
  let topFor = '';
  let live = null; // elements updated in place while a scan runs

  function render(state) {
    const running = state.scan?.state === 'running';
    const key = JSON.stringify([state.drives, running, state.scan?.state]);
    if (key !== drivesKey) {
      drivesKey = key;
      renderDrives(drivesCard, state.drives, running);
    }
    const sKey = `${state.scan?.id}:${state.scan?.state}`;
    if (sKey !== scanKey) {
      scanKey = sKey;
      live = renderScan(scanCard, state.scan);
    }
    if (running && live) updateLive(live, state.progress ?? state.scan.progress);
    if (state.scan?.state === 'done' && state.scan.id !== topFor) {
      topFor = state.scan.id;
      renderTop(topCard, state.scan);
    }
  }

  render(store.state);
  return store.subscribe(render);
}

function driveName(d) {
  const letter = d.root.replace(/\\$/, '');
  return t('drive.name', { label: d.label || t('drive.localDisk'), letter });
}

function renderDrives(card, drives, running) {
  const list = h('div', { class: 'drives' });
  for (const d of drives) {
    const scanned = store.state.scan?.roots?.includes(d.root);
    list.append(
      h('div', { class: 'drive' },
        h('div', { class: 'drive-head' },
          h('span', { class: 'drive-name' }, driveName(d)),
          h('button', {
            type: 'button',
            class: d.root.toUpperCase().startsWith('C:') ? 'primary' : '',
            disabled: running,
            onclick: () => startScan(d.root),
          }, t(scanned ? 'drive.scanAgain' : 'drive.scan')),
        ),
        bar(d.used / d.total, d.free / d.total < 0.1 ? 'danger' : ''),
        h('div', { class: 'muted' }, t('drive.free', { free: bytes(d.free), total: bytes(d.total) })),
      ),
    );
  }
  card.replaceChildren(h('h2', {}, t('drives.title')), list);
}

async function startScan(root) {
  try {
    const scan = await api.startScan([root]);
    store.set({ scan, progress: scan.progress });
  } catch (e) {
    alert(t('error.generic', { message: e.message }));
  }
}

// renderScan draws the scan card. For a running scan it returns the elements
// that updateLive changes, so that buttons aren't rebuilt under the pointer.
function renderScan(card, scan) {
  const title = h('h2', {}, t('scan.title'));
  if (!scan) {
    card.replaceChildren(title, h('p', { class: 'muted' }, t('scan.empty')));
    return null;
  }
  const roots = scan.roots.join(', ');
  if (scan.state === 'running') {
    const live = {
      bar: bar(0, 'progress'),
      percent: h('span', { class: 'big' }),
      counted: h('strong'),
      files: h('strong'),
      folders: h('strong'),
      elapsed: h('strong'),
      current: h('div', { class: 'scan-path muted' }),
    };
    card.replaceChildren(
      h('div', { class: 'scan-head' },
        h('h2', {}, t('scan.running', { roots })),
        h('button', { type: 'button', onclick: () => api.cancelScan(scan.id).catch(() => {}) }, t('scan.cancel')),
      ),
      h('div', { class: 'progress-row' }, live.bar, live.percent),
      h('div', { class: 'stats' },
        stat(t('scan.stat.counted'), live.counted),
        stat(t('scan.stat.files'), live.files),
        stat(t('scan.stat.folders'), live.folders),
        stat(t('scan.stat.elapsed'), live.elapsed),
      ),
      live.current,
    );
    return live;
  }
  if (scan.state === 'cancelled' || scan.state === 'failed') {
    const key = scan.state === 'failed' ? 'scan.failed' : 'scan.cancelled';
    card.replaceChildren(title, h('p', {}, t(key, { roots, error: scan.error ?? '' })));
    return null;
  }

  const s = scan.summary;
  const elapsed = duration(new Date(scan.finished) - new Date(scan.started));
  const notes = [];
  if (s.errors > 0) notes.push(h('p', { class: 'note' }, t('scan.hint.denied')));
  if (s.unaccounted > 0) notes.push(h('p', { class: 'note' }, t('scan.hint.unaccounted')));
  card.replaceChildren(
    h('div', { class: 'scan-head' },
      h('h2', {}, t('scan.done', { roots, time: elapsed })),
      h('a', { class: 'button primary', href: `#/explorer?path=${encodeURIComponent(scan.roots[0])}` }, t('scan.explore')),
    ),
    h('div', { class: 'stats' },
      stat(t('scan.stat.counted'), h('strong', {}, bytes(s.allocated))),
      stat(t('scan.stat.files'), h('strong', {}, count(s.files))),
      stat(t('scan.stat.folders'), h('strong', {}, count(s.folders))),
      stat(t('scan.stat.shared'), h('strong', {}, bytes(s.shared))),
      stat(t('scan.stat.cloud'), h('strong', {}, count(s.cloudOnly))),
      stat(t('scan.stat.errors'), h('strong', {}, count(s.errors))),
      stat(t('scan.stat.unaccounted'), h('strong', {}, bytes(s.unaccounted))),
    ),
    ...notes,
  );
  return null;
}

function updateLive(live, p) {
  if (!p) return;
  setBar(live.bar, p.percent / 100);
  live.percent.textContent = `${Math.floor(p.percent)}%`;
  live.counted.textContent = bytes(p.allocated);
  live.files.textContent = count(p.files);
  live.folders.textContent = count(p.folders);
  live.elapsed.textContent = duration(p.elapsedMs);
  live.current.textContent = p.current;
}

function stat(label, valueEl) {
  return h('div', { class: 'stat' }, h('span', { class: 'muted' }, label), valueEl);
}

async function renderTop(card, scan) {
  const root = scan.roots[0];
  try {
    const node = await api.tree(scan.id, root);
    const rows = [];
    for (const c of (node.children ?? []).filter((c) => c.allocated > 0).slice(0, 8)) {
      rows.push(
        h('a', { class: 'top-row', href: `#/explorer?path=${encodeURIComponent(c.path)}` },
          h('span', { class: 'name' }, c.name),
          bar(c.allocated / (node.allocated || 1)),
          h('span', { class: 'size' }, bytes(c.allocated)),
          h('span', { class: 'muted share' }, percent(c.allocated, node.allocated)),
        ),
      );
    }
    card.replaceChildren(h('h2', {}, t('scan.top', { root })), h('div', { class: 'top-list' }, rows));
    card.hidden = false;
  } catch {
    card.hidden = true;
  }
}
