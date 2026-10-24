import { api } from '../api.js';
import { h, rich } from '../dom.js';
import { bytes, count, date } from '../format.js';
import { t } from '../i18n.js';
import { store } from '../store.js';
import { openCleanup } from './cleanup.js';

const RISKS = ['safe', 'moderate', 'manual', 'info'];

// The findings page: what the latest scan found, grouped by category, with how
// to reclaim each, and below it what Windows reports about itself.
export function mount(root, params) {
  root.append(h('h1', {}, t('nav.findings')));
  const system = h('section', { class: 'card', hidden: true });
  let gone = false;
  const unsubscribers = [];

  const scan = store.state.scan;
  if (!scan || scan.state !== 'done') {
    root.append(
      h('section', { class: 'card message' },
        h('p', {}, t('findings.noScan')),
        h('a', { class: 'button primary', href: '#/' }, t('explorer.toOverview')),
      ),
      system,
    );
  } else {
    const head = h('section', { class: 'card' }, h('p', { class: 'muted' }, '…'));
    const list = h('div', { class: 'finding-groups' });
    root.append(head, list, system);
    let filter = RISKS.includes(params.get('risk')) ? params.get('risk') : 'all';
    let report = null;
    const render = () => {
      renderHead(head, scan, report, filter, (f) => {
        filter = f;
        render();
      });
      renderList(list, report, filter);
    };
    const load = () => api.findings(scan.id).then(
      (rep) => {
        if (gone) return;
        report = rep;
        render();
      },
      (e) => {
        if (!gone) head.replaceChildren(h('p', {}, t('error.generic', { message: e.message })));
      },
    );
    load();
    // A cleanup measures its folders again: the same scan, new findings.
    let updated = scan.updated;
    unsubscribers.push(store.subscribe((state) => {
      if (state.scan?.id === scan.id && state.scan.updated !== updated) {
        updated = state.scan.updated;
        load();
      }
    }));
  }

  let systemKey = '';
  const renderSystemIfChanged = ({ system: probes }) => {
    const key = JSON.stringify(probes);
    if (key !== systemKey) {
      systemKey = key;
      renderSystem(system, probes);
    }
  };
  renderSystemIfChanged(store.state);
  unsubscribers.push(store.subscribe(renderSystemIfChanged));
  return () => {
    gone = true;
    for (const u of unsubscribers) u();
  };
}

function renderHead(head, scan, report, filter, onFilter) {
  const tiles = RISKS.map((risk) =>
    h('button', {
      type: 'button',
      class: `tile risk-${risk}${filter === risk ? ' active' : ''}`,
      'aria-pressed': filter === risk ? 'true' : 'false',
      onclick: () => onFilter(filter === risk ? 'all' : risk),
    },
    h('span', { class: 'tile-label' }, t(`risk.${risk}`)),
    h('strong', {}, bytes(report.totals[risk] ?? 0)),
    ));
  head.replaceChildren(
    h('p', { class: 'muted' }, t('findings.from', { roots: scan.roots.join(', '), date: date(scan.finished) })),
    h('div', { class: 'tiles' }, tiles),
    h('p', { class: 'note' }, t(store.state.status?.cleanups ? 'findings.cleanups' : 'findings.readOnly')),
  );
}

function renderList(list, report, filter) {
  const shown = report.findings.filter((f) => filter === 'all' || f.risk === filter);
  if (!shown.length) {
    list.replaceChildren(h('p', { class: 'muted' }, t('findings.none')));
    return;
  }
  // Group by category; the groups holding the most come first.
  const groups = new Map();
  for (const f of shown) {
    if (!groups.has(f.category)) groups.set(f.category, { findings: [], total: 0 });
    const g = groups.get(f.category);
    g.findings.push(f);
    if (f.id !== 'other.growth') g.total += f.bytes;
  }
  const ordered = [...groups.entries()].sort((a, b) => b[1].total - a[1].total);
  list.replaceChildren(...ordered.map(([category, g]) =>
    h('section', { class: 'finding-group' },
      h('h2', {}, t(`category.${category}`)),
      g.findings.map((f) => card(f, report)),
    )));
}

function card(f, report) {
  const unknownSize = f.bytes === 0 && f.items.some((it) => it.unreadable);
  const items = f.items.map((it) => location(it, f));
  if (f.moreItems) items.push(h('li', { class: 'muted' }, t('findings.more', { count: count(f.moreItems) })));
  return h('article', { class: `finding risk-${f.risk}`, 'data-id': f.id },
    h('header', {},
      h('div', { class: 'finding-title' },
        h('h3', {}, t(`rule.${f.id}.title`)),
        h('span', { class: `badge risk-badge risk-${f.risk}` }, t(`risk.${f.risk}`)),
      ),
      h('span', { class: 'finding-size' }, unknownSize ? t('findings.unknownSize') : bytes(f.bytes)),
    ),
    h('p', {}, rich(t(`rule.${f.id}.what`))),
    f.id === 'other.growth' && report.growthSince ? h('p', { class: 'muted' }, t('findings.since', { date: date(report.growthSince) })) : null,
    f.action && store.state.status?.cleanups
      ? h('div', { class: 'finding-actions' },
        h('button', { type: 'button', class: 'primary small', onclick: () => openCleanup(f) }, t(`action.${f.action.kind}.button`)),
        h('span', { class: 'muted' }, t('findings.previewFirst')))
      : null,
    h('details', {},
      h('summary', {}, t('findings.details', { count: count(f.items.length + (f.moreItems || 0)) })),
      h('h4', {}, t('findings.how')),
      h('p', { class: 'how' }, rich(t(`rule.${f.id}.how`))),
      h('h4', {}, t('findings.where')),
      h('ul', { class: 'locations' }, items),
    ),
  );
}

function location(it, f) {
  const facts = [];
  if (it.unreadable) facts.push(t('findings.unreadable'));
  else if (f.id === 'other.growth') facts.push(t('findings.grew', { grew: bytes(it.bytes), now: bytes(it.current) }));
  else facts.push(bytes(it.bytes));
  if (it.files) facts.push(t('findings.files', { count: count(it.files) }));
  if (it.newest) facts.push(t('findings.changed', { date: date(it.newest) }));

  const copy = h('button', {
    type: 'button',
    class: 'small',
    onclick: async () => {
      try {
        await navigator.clipboard.writeText(it.path);
        copy.textContent = t('findings.copied');
        setTimeout(() => {
          copy.textContent = t('findings.copy');
        }, 1500);
      } catch {
        // The clipboard can be unavailable; the path is on the page anyway.
      }
    },
  }, t('findings.copy'));
  const folder = it.kind === 'folder' ? it.path : it.path.slice(0, it.path.lastIndexOf('\\') + 1);
  return h('li', {},
    h('div', { class: 'location-path' }, it.path, it.hint === 'cache' ? h('span', { class: 'badge' }, t('findings.cacheHint')) : null),
    h('div', { class: 'location-facts muted' }, facts.join(' · ')),
    h('div', { class: 'location-actions' },
      copy,
      h('a', { class: 'button small', href: `#/explorer?path=${encodeURIComponent(folder)}` }, t('findings.open')),
    ),
  );
}

// What Windows reports about itself: one row per probe.

function renderSystem(card, probes) {
  if (!probes?.length) {
    card.hidden = true;
    return;
  }
  const by = Object.fromEntries(probes.map((p) => [p.name, p]));
  card.replaceChildren(
    h('h2', {}, t('system.title')),
    h('dl', { class: 'system-list' },
      row(t('system.hibernation'), by.power, hibernation),
      row(t('system.pageFiles'), by.power, pageFiles),
      row(t('system.reserved'), by.reservedStorage, (d) => t(d.enabled ? 'system.reserved.on' : 'system.reserved.off')),
      row(t('system.wsl'), by.wsl, wsl),
      componentStoreRow(by.componentStore),
    ),
  );
  card.hidden = false;
}

function row(label, p, show) {
  return [h('dt', {}, label), h('dd', {}, value(p, show))];
}

function value(p, show) {
  switch (p?.state) {
    case 'ok':
      return show(p.data);
    case 'running':
      return p.data ? [show(p.data), ' ', h('span', { class: 'muted' }, t('system.running'))] : h('span', { class: 'muted' }, t('system.running'));
    case 'needs-admin':
      return h('span', { class: 'muted' }, t('system.needsAdmin'));
    case 'failed':
      return h('span', { class: 'muted' }, t('system.failed', { message: p.message }));
    default:
      return '–';
  }
}

function hibernation(d) {
  if (d.hibernation !== 'on') return t(`system.hibernation.${d.hibernation}`);
  return d.hiberFile ? t('system.hibernation.on', { size: bytes(d.hiberFile) }) : t('system.hibernation.onNoFile');
}

function pageFiles(d) {
  if (!d.pageFiles.length) return t('system.pageFiles.none');
  return h('ul', { class: 'plain' }, d.pageFiles.map((pf) =>
    h('li', {}, `${pf.path} · ${bytes(pf.bytes)} · ${pageFileSetting(d.pageFileConfig, pf.path)}`)));
}

// pageFileSetting explains a PagingFiles entry: "?:\pagefile.sys" or a size
// of 0 means Windows manages it; "D:\pagefile.sys 8192 8192" is a set size.
function pageFileSetting(config, path) {
  for (const c of config ?? []) {
    const [p, min, max] = c.split(/\s+/);
    if (p.startsWith('?:')) return t('system.pageFiles.auto');
    if (p.slice(0, 2).toUpperCase() === path.slice(0, 2).toUpperCase()) {
      return !min || (min === '0' && max === '0') ? t('system.pageFiles.auto') : t('system.pageFiles.fixed', { min, max });
    }
  }
  return t('system.pageFiles.auto');
}

function wsl(distros) {
  if (!distros.length) return t('system.wsl.none');
  return h('ul', { class: 'plain' }, distros.map((d) =>
    h('li', {},
      h('strong', {}, d.name),
      d.default ? ` (${t('system.wsl.default')})` : '',
      ` · ${d.bytes ? bytes(d.bytes) : '–'} · `,
      h('span', { class: 'muted' }, d.disk),
    )));
}

function componentStoreRow(p) {
  const analyze = h('button', {
    type: 'button',
    class: 'small',
    onclick: () => api.runProbe('componentStore').catch((e) => alert(t('error.generic', { message: e.message }))),
  }, t('system.componentStore.run'));
  const result = (d) => t('system.componentStore.result', {
    actual: bytes(d.actualSize),
    reclaimable: bytes(d.backups + d.cache),
    recommended: t(d.cleanupRecommended ? 'system.yes' : 'system.no'),
  });
  let shown;
  if (!p || p.state === 'not-run') shown = [h('span', { class: 'muted' }, t('system.componentStore.hint')), ' ', analyze];
  else if (p.state === 'running') shown = value(p, result);
  else shown = [value(p, result), ' ', analyze];
  return [h('dt', {}, t('system.componentStore')), h('dd', {}, shown)];
}
