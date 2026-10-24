// Talks to the COptimizer server. The launch link carries a one-time code in
// the URL fragment; it is traded for a session token that lives only in this
// tab (sessionStorage) and goes with every request.

const TOKEN_KEY = 'coptimizer.token';
let token = null;
try {
  token = sessionStorage.getItem(TOKEN_KEY);
} catch {
  // Storage can be unavailable; the token then lives until the tab reloads.
}

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// startSession signs in with the code from the link, if there is one, and
// reports whether the page has a session.
export async function startSession() {
  const match = /[#&]code=([0-9a-f]+)/i.exec(location.hash);
  if (match) {
    history.replaceState(null, '', `${location.pathname}#/`);
    const res = await call('POST', '/api/session', { code: match[1] }, false);
    setToken(res.token);
  }
  return token != null;
}

function setToken(value) {
  token = value;
  try {
    if (value) sessionStorage.setItem(TOKEN_KEY, value);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // See above.
  }
}

export function authHeaders() {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function call(method, path, body, auth = true) {
  const headers = { Accept: 'application/json', ...(auth ? authHeaders() : {}) };
  const init = { method, headers, cache: 'no-store' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  let data = null;
  try {
    data = await res.json();
  } catch {
    // Not JSON: handled below.
  }
  if (!res.ok) {
    if (res.status === 401) setToken(null);
    const err = data?.error ?? {};
    throw new ApiError(res.status, err.code ?? `http_${res.status}`, err.message ?? res.statusText);
  }
  return data;
}

const q = encodeURIComponent;

export const api = {
  status: () => call('GET', '/api/status'),
  drives: () => call('GET', '/api/drives'),
  startScan: (drives) => call('POST', '/api/scans', { drives }),
  cancelScan: (id) => call('DELETE', `/api/scans/${q(id)}`),
  tree: (id, path) => call('GET', `/api/scans/${q(id)}/tree?path=${q(path)}`),
  files: (id, path, limit) => call('GET', `/api/scans/${q(id)}/files?path=${q(path)}&limit=${limit}`),
  types: (id, limit) => call('GET', `/api/scans/${q(id)}/types?limit=${limit}`),
  findings: (id) => call('GET', `/api/scans/${q(id)}/findings`),
  system: () => call('GET', '/api/system'),
  runProbe: (name) => call('POST', `/api/system/${q(name)}`),
  // Cleanups: the page names only a finding; the server works out the rest.
  plan: (ruleId) => call('POST', '/api/plans', { ruleId }),
  startJob: (planId) => call('POST', '/api/jobs', { planId }),
  jobs: () => call('GET', '/api/jobs'),
  job: (id) => call('GET', `/api/jobs/${q(id)}`),
  cancelJob: (id) => call('DELETE', `/api/jobs/${q(id)}`),
  history: (limit) => call('GET', `/api/history?limit=${limit}`),
  setConfig: (patch) => call('PUT', '/api/config', patch),
  shutdown: () => call('POST', '/api/shutdown'),
};
