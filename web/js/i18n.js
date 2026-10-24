// Every text the page shows comes from i18n/<language>.json (the page) and
// i18n/rules.<language>.json (the findings), so adding a language means
// adding two files.

let strings = {};

export async function loadStrings(lang) {
  const files = [`/i18n/${lang}.json`, `/i18n/rules.${lang}.json`];
  const parts = await Promise.all(files.map((f) => fetch(f, { cache: 'no-cache' }).then((r) => r.json())));
  strings = Object.assign({}, ...parts);
}

// t returns the text for key, with {name} placeholders filled from vars.
export function t(key, vars = {}) {
  const s = strings[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (m, name) => (name in vars ? String(vars[name]) : m));
}
