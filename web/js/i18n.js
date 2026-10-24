// Every text the page shows comes from i18n/<language>.json (the page) and
// i18n/rules.<language>.json (the findings), so adding a language means
// adding two files.

let strings = {};

export async function loadStrings(lang) {
  const files = [`/i18n/${lang}.json`, `/i18n/rules.${lang}.json`];
  const parts = await Promise.all(files.map((f) => fetch(f, { cache: 'no-cache' }).then((r) => r.json())));
  strings = Object.assign({}, ...parts);
}

const plurals = new Intl.PluralRules('en');
const numbers = new Intl.NumberFormat('en');

// n returns a count with its noun, like "1 file" or "9,000 files", from the
// texts unit.<unit>.one and unit.<unit>.other.
export function n(value, unit) {
  return t(`unit.${unit}.${plurals.select(value) === 'one' ? 'one' : 'other'}`, { count: numbers.format(value) });
}

// has reports whether there is a text for key.
export function has(key) {
  return key in strings;
}

// t returns the text for key, with {name} placeholders filled from vars.
export function t(key, vars = {}) {
  const s = strings[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (m, name) => (name in vars ? String(vars[name]) : m));
}
