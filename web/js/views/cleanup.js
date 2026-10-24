import { api } from '../api.js';
import { bar, h, rich, setBar } from '../dom.js';
import { baseName, bytes, count } from '../format.js';
import { has, n, t } from '../i18n.js';
import { store } from '../store.js';

// Friendlier names for the programs a cleanup asks you to close.
const PROGRAMS = {
  'chrome.exe': 'Google Chrome', 'msedge.exe': 'Microsoft Edge', 'firefox.exe': 'Firefox', 'brave.exe': 'Brave',
  'vivaldi.exe': 'Vivaldi', 'opera.exe': 'Opera', 'browser.exe': 'Cốc Cốc', 'Code.exe': 'Visual Studio Code',
  'Code - Insiders.exe': 'VS Code Insiders', 'Cursor.exe': 'Cursor', 'Windsurf.exe': 'Windsurf',
  'devenv.exe': 'Visual Studio', 'ms-teams.exe': 'Microsoft Teams', 'Teams.exe': 'Microsoft Teams (classic)',
  'slack.exe': 'Slack', 'Discord.exe': 'Discord', 'Zalo.exe': 'Zalo', 'Signal.exe': 'Signal', 'steam.exe': 'Steam',
  'EpicGamesLauncher.exe': 'Epic Games Launcher', 'uv.exe': 'uv',
};

const programName = (exe) => PROGRAMS[exe] ?? exe;

// openCleanup previews the cleanup of finding f in a dialog and, once you
// confirm, follows it to the end. The preview changes nothing: the server
// works it out, with a dry run for deletions.
export function openCleanup(f) {
  const title = h('h2', { id: 'cleanup-title' }, t(`action.${f.action.kind}.title`, { name: t(`rule.${f.id}.title`) }));
  const body = h('div', { class: 'dialog-body' });
  const dlg = h('dialog', { class: 'cleanup', 'aria-labelledby': 'cleanup-title' }, title, body);
  let unsubscribe = null; // following a cleanup
  let unwatch = null; // watching simulation mode while a preview shows
  dlg.addEventListener('close', () => {
    unsubscribe?.();
    unwatch?.();
    dlg.remove();
  });
  document.body.append(dlg);
  dlg.showModal();
  preview();

  async function preview() {
    unwatch?.();
    unwatch = null;
    body.replaceChildren(h('p', { class: 'muted' }, t('cleanup.preparing')));
    try {
      renderPlan(await api.plan(f.id));
    } catch (e) {
      body.replaceChildren(h('p', {}, t('error.generic', { message: e.message })), buttons(close()));
    }
  }

  function close(label = t('cleanup.close')) {
    return h('button', { type: 'button', onclick: () => dlg.close() }, label);
  }

  function renderPlan(plan) {
    const parts = [h('p', {}, summary(plan))];
    if (has(`rule.${plan.ruleId}.action`)) parts.push(h('p', { class: 'note' }, rich(t(`rule.${plan.ruleId}.action`))));
    if (plan.minAgeHours) parts.push(h('p', { class: 'muted' }, t('cleanup.minAge', { hours: plan.minAgeHours })));
    if (plan.command) parts.push(h('p', { class: 'muted' }, t('cleanup.command')), h('pre', { class: 'command' }, plan.command));
    if (plan.long) parts.push(h('p', { class: 'note warn' }, t('cleanup.long')));
    if (plan.kind === 'delete') parts.push(h('p', { class: 'muted' }, t('cleanup.skipped')));
    if (plan.locations?.length) parts.push(locations(plan.locations));
    if (plan.left?.length) parts.push(left(plan.left));
    if (plan.simulate) parts.push(h('p', { class: 'note' }, t('cleanup.simulate')));
    if (plan.blocked) {
      const programs = (plan.running ?? []).map(programName).join(', ');
      parts.push(h('p', { class: 'blocked', role: 'alert' }, t(`cleanup.blocked.${plan.blocked}`, { programs })));
    }

    const go = h('button', {
      type: 'button',
      class: 'primary',
      disabled: Boolean(plan.blocked),
      onclick: async () => {
        go.disabled = true;
        try {
          const job = await api.startJob(plan.id);
          unwatch?.();
          unwatch = null;
          follow(job.id);
        } catch (e) {
          go.disabled = false;
          if (['plan_expired', 'plan_stale', 'close-programs'].includes(e.code)) preview();
          else alert(t('error.generic', { message: e.message }));
        }
      },
    }, plan.simulate ? t('cleanup.simulateButton') : t(`action.${plan.kind}.confirm`));
    const again = plan.blocked === 'close-programs'
      ? h('button', { type: 'button', onclick: preview }, t('cleanup.checkAgain'))
      : null;
    const cancel = close(t('cleanup.cancel'));
    body.replaceChildren(...parts, buttons(go, again, cancel));
    // Not the button that cleans: pressing Enter twice must not run a
    // cleanup nobody has read.
    (again ?? cancel).focus();
    // A preview shows a simulation or a real cleanup: if the mode changes
    // meanwhile (in another tab), show the preview afresh. Only a change
    // counts, so a late update can't make previews repeat.
    let seen = Boolean(store.state.status?.simulate);
    unwatch = store.subscribe((state) => {
      const now = Boolean(state.status?.simulate);
      if (now === seen) return;
      seen = now;
      if (now !== Boolean(plan.simulate)) preview();
    });
  }

  // follow shows a confirmed cleanup until it ends.
  function follow(jobId) {
    let live = null;
    const render = (state) => {
      const j = state.jobs[jobId];
      if (!j) return;
      if (j.state === 'queued' || j.state === 'running') {
        live ??= running(j);
        update(live, j, state.jobProgress[jobId], state.jobLog[jobId]);
      } else {
        live = null;
        unsubscribe?.();
        unsubscribe = null;
        done(j);
      }
    };
    unsubscribe = store.subscribe(render);
    render(store.state);
  }

  // running draws the progress of a cleanup once and returns what update
  // changes, so buttons aren't rebuilt under the pointer.
  function running(j) {
    const live = {
      bar: bar(0, 'progress'),
      percent: h('span', { class: 'big' }),
      facts: h('p', { class: 'muted' }),
      current: h('div', { class: 'scan-path muted' }),
      log: h('pre', { class: 'log', hidden: true }),
    };
    const stop = !j.stoppable
      ? h('p', { class: 'note warn' }, t('cleanup.cantStop'))
      : h('button', { type: 'button', onclick: () => api.cancelJob(j.id).catch(() => {}) }, t('cleanup.stop'));
    body.replaceChildren(
      h('p', {}, t(j.simulated ? 'cleanup.simulating' : 'cleanup.running')),
      h('div', { class: 'progress-row' }, live.bar, live.percent),
      live.facts, live.current, live.log,
      buttons(stop, close(t('cleanup.hide'))),
    );
    return live;
  }

  function update(live, j, p, log) {
    let fraction = null;
    if (p && p.percent >= 0) fraction = p.percent / 100;
    else if (p && j.estimate > 0) fraction = Math.min(0.99, p.bytes / j.estimate);
    setBar(live.bar, fraction ?? 0);
    live.percent.textContent = fraction == null ? '' : `${Math.floor(fraction * 100)}%`;
    live.facts.textContent = j.state === 'queued' ? t('cleanup.queued')
      : p?.files ? t('cleanup.progress', { files: n(p.files, 'file'), bytes: bytes(p.bytes) }) : '';
    live.current.textContent = p?.current ?? '';
    if (log?.length) {
      live.log.hidden = false;
      live.log.textContent = log.slice(-6).join('\n');
    }
  }

  function done(j) {
    const o = j.outcome ?? {};
    const lines = [h('p', { class: `result result-${j.state}` }, result(j, o))];
    if (o.restartNeeded) lines.push(h('p', { class: 'note warn' }, t('cleanup.restart')));
    if (j.kind === 'component-cleanup' && !j.simulated && j.state === 'succeeded') lines.push(h('p', { class: 'muted' }, t('cleanup.scanAgain')));
    if (!j.simulated && j.state !== 'failed') lines.push(h('p', { class: 'muted' }, t('cleanup.measured')));
    body.replaceChildren(...lines,
      buttons(h('a', { class: 'button', href: '#/activity', onclick: () => dlg.close() }, t('cleanup.toActivity')), close()));
    dlg.querySelector('button')?.focus();
  }
}

function buttons(...items) {
  return h('div', { class: 'dialog-buttons' }, items);
}

function summary(plan) {
  switch (plan.kind) {
    case 'delete':
      return t('action.delete.summary', { files: n(plan.files, 'file'), bytes: bytes(plan.bytes) });
    case 'recycle-bin':
      return t('action.recycle-bin.summary', { items: n(plan.items ?? 0, 'item'), bytes: bytes(plan.bytes), drive: plan.drive.replace(/\\$/, '') });
    case 'delivery-optimization':
      return t('action.delivery-optimization.summary', { bytes: bytes(plan.bytes) });
    default:
      return t(`action.${plan.kind}.summary`);
  }
}

// locations lists what a deletion will go through, with what the dry run
// found in each.
function locations(list) {
  const items = list.slice(0, 30).map((l) => {
    const facts = [];
    if (l.state === 'missing') facts.push(t('cleanup.loc.missing'));
    else if (l.state === 'refused') facts.push(t(`cleanup.reason.${l.reason}`));
    else facts.push(t('cleanup.loc.files', { files: n(l.files, 'file'), bytes: bytes(l.bytes) }));
    if (l.kept) facts.push(t('cleanup.loc.kept', { count: n(l.kept, 'item') }));
    const samples = (l.samples ?? []).map(baseName).join(', ');
    return h('li', {},
      h('div', { class: 'location-path' }, l.path),
      h('div', { class: 'location-facts muted' }, facts.join(' · ')),
      samples ? h('div', { class: 'location-facts muted' }, t('cleanup.loc.samples', { names: samples })) : null,
    );
  });
  if (list.length > 30) items.push(h('li', { class: 'muted' }, t('findings.more', { count: count(list.length - 30) })));
  return h('details', { open: list.length <= 5 },
    h('summary', {}, t('cleanup.where', { count: count(list.length) })),
    h('ul', { class: 'locations' }, items));
}

// left lists the finding's locations the cleanup leaves alone, and why.
function left(list) {
  return h('details', {},
    h('summary', {}, t('cleanup.left', { count: count(list.length) })),
    h('ul', { class: 'locations' }, list.slice(0, 30).map((l) =>
      h('li', {},
        h('div', { class: 'location-path' }, l.path),
        h('div', { class: 'location-facts muted' }, `${bytes(l.bytes)} · ${t(`cleanup.left.${l.reason}`)}`),
      ))));
}

function result(j, o) {
  const vars = { freed: bytes(Math.max(0, j.freed)), files: n(o.files ?? 0, 'file'), bytes: bytes(o.bytes ?? 0),
    estimate: bytes(j.estimate), skipped: n(o.skipped ?? 0, 'file'), error: o.error ?? j.error ?? '' };
  // Only the deleter counts files; the Recycle Bin and Windows' tools don't.
  const kind = j.kind === 'delete' ? '' : j.kind === 'recycle-bin' ? '.recycle' : '.tool';
  if (j.simulated) return t(`cleanup.result.simulated${kind}`, vars);
  if (j.state === 'succeeded') return t(`cleanup.result.succeeded${kind}`, vars);
  return t(`cleanup.result.${j.state}`, vars);
}
