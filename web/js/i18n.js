// Every text the page shows comes from i18n/<language>.json, so adding a
// language means adding one file.

let strings = {};

export async function loadStrings(lang) {
  const res = await fetch(`/i18n/${lang}.json`, { cache: 'no-cache' });
  strings = await res.json();
}

// t returns the text for key, with {name} placeholders filled from vars.
export function t(key, vars = {}) {
  const s = strings[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (m, name) => (name in vars ? String(vars[name]) : m));
}
