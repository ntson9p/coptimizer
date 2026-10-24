// Sizes use binary units, as Windows Explorer does: 1 GB = 1024³ bytes.
const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];

export function bytes(n) {
  if (!Number.isFinite(n)) return '–';
  let v = n;
  let i = 0;
  while (Math.abs(v) >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  const digits = i === 0 || v >= 100 ? 0 : v >= 10 ? 1 : 2;
  return `${v.toFixed(digits)} ${UNITS[i]}`;
}

const numberFormat = new Intl.NumberFormat('en');

export function count(n) {
  return numberFormat.format(n);
}

export function percent(part, whole) {
  if (!whole) return '–';
  const p = (100 * part) / whole;
  return p > 0 && p < 0.1 ? '<0.1%' : `${p.toFixed(1)}%`;
}

export function duration(ms) {
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}

export function date(iso) {
  if (!iso) return '–';
  return new Date(iso).toLocaleDateString('en', { year: 'numeric', month: 'short', day: 'numeric' });
}

export function dateTime(iso) {
  if (!iso) return '–';
  return new Date(iso).toLocaleString('en', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// baseName and dirName split a Windows path.
export function baseName(path) {
  return path.slice(path.lastIndexOf('\\') + 1);
}

export function dirName(path) {
  return path.slice(0, path.lastIndexOf('\\') + 1);
}
