import { api } from '../api.js';
import { bar, h } from '../dom.js';
import { baseName, bytes, count, date, dirName, percent } from '../format.js';
import { t } from '../i18n.js';
import { store } from '../store.js';

// The explorer walks the result of the latest finished scan: a folder's
// sub-folders by size, the largest files in it, and file types overall.
export function mount(root, params) {
  const scan = store.state.scan;
  if (!scan || scan.state !== 'done') {
    root.append(
      h('h1', {}, t('nav.explorer')),
      h('section', { class: 'card message' },
        h('p', {}, t('explorer.noScan')),
        h('a', { class: 'button primary', href: '#/' }, t('explorer.toOverview')),
      ),
    );
    return null;
  }

  const path = params.get('path') || scan.roots[0];
  const main = h('section', { class: 'card' }, h('p', { class: 'muted' }, '…'));
  const side = h('aside', { class: 'side' });
  root.append(h('h1', {}, t('nav.explorer')), h('div', { class: 'explorer' }, main, side));

  let gone = false;
  Promise.all([api.tree(scan.id, path), api.files(scan.id, path, 15), api.types(scan.id, 12)]).then(
    ([node, files, types]) => {
      if (gone) return;
      renderFolder(main, node);
      side.replaceChildren(renderFiles(files), renderTypes(types));
    },
    (e) => {
      if (!gone) main.replaceChildren(h('p', {}, t('error.generic', { message: e.message })));
    },
  );
  return () => {
    gone = true;
  };
}

function explorerLink(path) {
  return `#/explorer?path=${encodeURIComponent(path)}`;
}

function crumbs(path) {
  // `C:\Users\Demo` → C:\ › Users › Demo, each a link to its folder.
  const parts = path.replace(/\\$/, '').split('\\');
  const out = [];
  let acc = '';
  parts.forEach((part, i) => {
    acc = i === 0 ? `${part}\\` : `${acc}${i > 1 ? '\\' : ''}${part}`;
    if (i > 0) out.push(h('span', { class: 'sep', 'aria-hidden': 'true' }, '›'));
    out.push(i === parts.length - 1 ? h('span', { class: 'crumb current' }, i === 0 ? acc : part) : h('a', { class: 'crumb', href: explorerLink(acc) }, i === 0 ? acc : part));
  });
  return h('nav', { class: 'crumbs', 'aria-label': 'Folder' }, out);
}

function renderFolder(card, node) {
  const whole = node.allocated || 1;
  const head = h('div', { class: 'row head' },
    h('span', {}, t('explorer.col.name')),
    h('span', {}, t('explorer.col.size')),
    h('span', { class: 'num' }, t('explorer.col.share')),
    h('span', { class: 'num' }, t('explorer.col.files')),
    h('span', { class: 'num' }, t('explorer.col.changed')),
  );
  const rows = [head];
  if (node.ownFiles > 0) {
    rows.push(h('div', { class: 'row own' },
      h('span', { class: 'name files-icon' }, t('explorer.ownFiles')),
      h('span', { class: 'sizecell' }, bar(node.ownAllocated / whole), bytes(node.ownAllocated)),
      h('span', { class: 'num' }, percent(node.ownAllocated, node.allocated)),
      h('span', { class: 'num' }, count(node.ownFiles)),
      h('span', { class: 'num' }, ''),
    ));
  }
  for (const c of node.children ?? []) {
    const badge = c.link ? t('explorer.link') : c.denied ? t('explorer.denied') : null;
    const cells = [
      h('span', { class: `name folder-icon${c.link ? ' link' : ''}` }, c.name, badge && h('span', { class: 'badge' }, badge)),
      h('span', { class: 'sizecell' }, bar(c.allocated / whole), bytes(c.allocated)),
      h('span', { class: 'num' }, percent(c.allocated, node.allocated)),
      h('span', { class: 'num' }, count(c.files)),
      h('span', { class: 'num' }, date(c.newest)),
    ];
    rows.push(c.link || !c.hasChildren && c.files === 0
      ? h('div', { class: 'row' }, cells)
      : h('a', { class: 'row', href: explorerLink(c.path) }, cells));
  }
  if (node.moreChildren) rows.push(h('div', { class: 'row muted' }, t('explorer.more', { count: count(node.moreChildren) })));
  if (!node.children?.length && !node.ownFiles) rows.push(h('p', { class: 'muted' }, t('explorer.empty')));

  card.replaceChildren(
    crumbs(node.path),
    h('div', { class: 'folder-total' },
      h('strong', {}, bytes(node.allocated)),
      h('span', { class: 'muted' }, t('explorer.files', { count: count(node.files) })),
    ),
    h('div', { class: 'table', role: 'table' }, rows),
  );
}

function renderFiles(files) {
  const card = h('section', { class: 'card' }, h('h2', {}, t('explorer.largest')));
  if (!files.length) {
    card.append(h('p', { class: 'muted' }, t('explorer.largest.none')));
    return card;
  }
  card.append(h('ol', { class: 'file-list' }, files.map((f) =>
    h('li', {},
      h('span', { class: 'file-name', title: f.path }, baseName(f.path)),
      h('span', { class: 'size' }, bytes(f.allocated)),
      h('span', { class: 'file-dir muted', title: f.path }, dirName(f.path)),
    ))));
  return card;
}

function renderTypes(types) {
  const top = types[0]?.allocated || 1;
  return h('section', { class: 'card' },
    h('h2', {}, t('explorer.types')),
    h('ul', { class: 'type-list' }, types.map((x) =>
      h('li', {},
        h('span', { class: 'ext' }, x.ext || t('explorer.noExt')),
        bar(x.allocated / top),
        h('span', { class: 'size' }, bytes(x.allocated)),
        h('span', { class: 'muted num' }, count(x.files)),
      ))));
}
