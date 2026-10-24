import { api } from '../api.js';
import { bar, h, setBar } from '../dom.js';
import { bytes, count, dateTime } from '../format.js';
import { n, t } from '../i18n.js';
import { store } from '../store.js';

// The activity page: simulation mode, the cleanups of this session with live
// progress, and the history of every cleanup, kept between runs.
export function mount(root) {
  const settings = h('section', { class: 'card' });
  const jobsCard = h('section', { class: 'card' });
  const historyCard = h('section', { class: 'card' }, h('h2', {}, t('activity.history')), h('p', { class: 'muted' }, '…'));
  root.append(h('h1', {}, t('nav.activity')), settings, jobsCard, historyCard);

  let gone = false;
  let settingsKey = '';
  let jobsKey = '';
  let finished = -1;
  const live = new Map(); // job ID → elements updated in place

  const loadHistory = () => api.history(100).then(
    (entries) => !gone && renderHistory(historyCard, entries),
    (e) => !gone && historyCard.replaceChildren(h('h2', {}, t('activity.history')), h('p', {}, t('error.generic', { message: e.message }))),
  );

  function render(state) {
    const key = JSON.stringify([state.status?.simulate, state.status?.cleanups, state.status?.demo]);
    if (key !== settingsKey) {
      settingsKey = key;
      renderSettings(settings, state.status);
    }
    const jobs = Object.values(state.jobs).sort((a, b) => Number(b.id.slice(1)) - Number(a.id.slice(1)));
    const jKey = JSON.stringify(jobs.map((j) => [j.id, j.state]));
    if (jKey !== jobsKey) {
      jobsKey = jKey;
      renderJobs(jobsCard, jobs, live);
    }
    for (const j of jobs) {
      const el = live.get(j.id);
      if (el) updateLive(el, j, state.jobProgress[j.id]);
    }
    const done = jobs.filter((j) => j.finished).length;
    if (done !== finished) {
      finished = done;
      loadHistory();
    }
  }

  render(store.state);
  const unsubscribe = store.subscribe(render);
  return () => {
    gone = true;
    unsubscribe();
  };
}

function renderSettings(card, status) {
  const box = h('input', {
    type: 'checkbox',
    id: 'simulate-switch',
    checked: Boolean(status?.simulate),
    disabled: !status?.cleanups,
    onchange: async () => {
      box.disabled = true;
      try {
        await api.setConfig({ simulate: box.checked });
      } catch (e) {
        box.checked = !box.checked;
        alert(t('error.generic', { message: e.message }));
      } finally {
        box.disabled = false;
      }
    },
  });
  card.replaceChildren(
    h('h2', {}, t('activity.settings')),
    h('label', { class: 'switch', for: 'simulate-switch' }, box, h('span', {}, t('activity.simulate'))),
    h('p', { class: 'muted' }, t(status?.cleanups ? 'activity.simulate.hint' : 'activity.noCleanups')),
  );
}

function renderJobs(card, jobs, live) {
  live.clear();
  card.replaceChildren(h('h2', {}, t('activity.jobs')));
  if (!jobs.length) {
    card.append(h('p', { class: 'muted' }, t('activity.jobs.none')));
    return;
  }
  card.append(h('ul', { class: 'job-list' }, jobs.map((j) => {
    const facts = h('span', { class: 'muted' });
    const li = h('li', { class: `job job-${j.state}`, 'data-job': j.id },
      h('div', { class: 'job-head' },
        h('strong', {}, t(`rule.${j.ruleId}.title`)),
        h('span', { class: `badge state state-${j.state}` }, t(`activity.state.${j.state}`)),
        j.simulated ? h('span', { class: 'badge' }, t('activity.simulated')) : null,
        h('span', { class: 'muted job-time' }, dateTime(j.finished ?? j.started ?? j.queued)),
      ),
      facts,
    );
    if (j.state === 'queued' || j.state === 'running') {
      const el = { bar: bar(0, 'progress'), facts };
      li.append(h('div', { class: 'progress-row' }, el.bar,
        j.long && !j.simulated ? null : h('button', { type: 'button', class: 'small', onclick: () => api.cancelJob(j.id).catch(() => {}) }, t('cleanup.stop'))));
      live.set(j.id, el);
    } else {
      facts.textContent = outcomeLine(j);
    }
    return li;
  })));
}

function updateLive(el, j, p) {
  let fraction = 0;
  if (p && p.percent >= 0) fraction = p.percent / 100;
  else if (p && j.estimate > 0) fraction = Math.min(0.99, p.bytes / j.estimate);
  setBar(el.bar, fraction);
  el.facts.textContent = j.state === 'queued' ? t('cleanup.queued')
    : p?.files ? t('cleanup.progress', { files: n(p.files, 'file'), bytes: bytes(p.bytes) }) : t('cleanup.running');
}

function outcomeLine(j) {
  const o = j.outcome ?? {};
  if (j.state === 'failed') return t('activity.line.failed', { error: o.error ?? j.error ?? '' });
  if (j.simulated) return j.kind === 'delete' ? t('activity.line.simulated', { files: n(o.files ?? 0, 'file'), bytes: bytes(o.bytes ?? 0) }) : t('activity.line.simulated.tool');
  if (j.unknown || j.kind !== 'delete') return t('activity.line.tool', { freed: bytes(Math.max(0, j.freed)) });
  return t('activity.line.done', { freed: bytes(Math.max(0, j.freed)), estimate: bytes(j.estimate), files: n(o.files ?? 0, 'file') });
}

function renderHistory(card, entries) {
  card.replaceChildren(h('h2', {}, t('activity.history')));
  if (!entries.length) {
    card.append(h('p', { class: 'muted' }, t('activity.history.none')));
    return;
  }
  const real = entries.filter((e) => !e.simulated);
  const total = real.reduce((sum, e) => sum + Math.max(0, e.freed), 0);
  card.append(
    h('p', {}, t('activity.history.total', { freed: bytes(total), cleanups: n(real.length, 'cleanup') })),
    h('div', { class: 'table history', role: 'table' },
      h('div', { class: 'row head', role: 'row' },
        h('span', {}, t('activity.col.when')), h('span', {}, t('activity.col.what')), h('span', {}, t('activity.col.result')),
        h('span', { class: 'num' }, t('activity.col.estimate')), h('span', { class: 'num' }, t('activity.col.freed')),
      ),
      entries.map((e) => h('div', { class: 'row', role: 'row' },
        h('span', { class: 'muted' }, dateTime(e.time)),
        h('span', { class: 'name' }, t(`rule.${e.rule}.title`)),
        h('span', {}, e.simulated ? t('activity.simulated') : t(`activity.state.${e.state}`)),
        h('span', { class: 'num' }, e.unknown ? '–' : bytes(e.estimate)),
        h('span', { class: 'num' }, e.simulated ? '–' : bytes(Math.max(0, e.freed))),
      )),
    ),
  );
}
