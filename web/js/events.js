import { authHeaders } from './api.js';

// connectEvents reads the server's event stream and calls onEvent(type, data)
// for each event, and onState with 'connecting', 'live', 'reconnecting' or
// 'unauthorized'. It uses fetch rather than EventSource because EventSource
// can't send the session token. After a drop it reconnects, asking for the
// events it missed.
export function connectEvents(onEvent, onState) {
  let lastId = null;
  let retry = 1000;
  let stopped = false;
  let abort = null;

  async function run() {
    while (!stopped) {
      onState(lastId === null ? 'connecting' : 'reconnecting');
      abort = new AbortController();
      let watchdog = null;
      const resetWatchdog = () => {
        clearTimeout(watchdog);
        watchdog = setTimeout(() => abort.abort(), 45000); // the server sends a heartbeat every 15 s
      };
      try {
        const headers = { Accept: 'text/event-stream', ...authHeaders() };
        if (lastId !== null) headers['Last-Event-ID'] = lastId;
        resetWatchdog();
        const res = await fetch('/api/events', { headers, cache: 'no-store', signal: abort.signal });
        if (res.status === 401) {
          onState('unauthorized');
          return;
        }
        if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
        onState('live');
        retry = 1000;
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          resetWatchdog();
          buf += value;
          let end;
          while ((end = buf.indexOf('\n\n')) >= 0) {
            const ev = parseEvent(buf.slice(0, end));
            buf = buf.slice(end + 2);
            if (ev.id !== undefined) lastId = ev.id;
            if (ev.type) onEvent(ev.type, ev.data ? JSON.parse(ev.data) : null);
          }
        }
      } catch {
        // Network trouble or the watchdog: reconnect below.
      } finally {
        clearTimeout(watchdog);
      }
      if (stopped) return;
      onState('reconnecting');
      await new Promise((resolve) => setTimeout(resolve, retry));
      retry = Math.min(retry * 2, 15000);
    }
  }

  run();
  return () => {
    stopped = true;
    abort?.abort();
  };
}

function parseEvent(raw) {
  const ev = {};
  for (const line of raw.split('\n')) {
    if (line === '' || line.startsWith(':')) continue;
    const colon = line.indexOf(':');
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') ev.type = value;
    else if (field === 'id') ev.id = value;
    else if (field === 'data') ev.data = ev.data === undefined ? value : `${ev.data}\n${value}`;
  }
  return ev;
}
