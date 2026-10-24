// h creates an element. Strings and numbers become text nodes, so values from
// the server (file names, paths) can never turn into markup.
export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props ?? {})) {
    if (value == null || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

// bar draws a horizontal bar filled to fraction (0–1).
export function bar(fraction, className = '') {
  const fill = h('span', { class: 'fill' });
  fill.style.width = `${Math.max(0, Math.min(1, fraction || 0)) * 100}%`;
  return h('span', { class: `bar ${className}`.trim() }, fill);
}

export function setBar(barEl, fraction) {
  barEl.firstChild.style.width = `${Math.max(0, Math.min(1, fraction || 0)) * 100}%`;
}
