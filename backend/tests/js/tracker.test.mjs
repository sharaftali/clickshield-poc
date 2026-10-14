// Task 024: the tracker in a minimal fake browser. Run from backend/: node --test tests/js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import vm from 'node:vm';

const SOURCE = readFileSync(new URL('../../app/static/clickshield-tracker.js', import.meta.url), 'utf8');
const tick = () => new Promise((resolve) => setTimeout(resolve, 5));

function browser({ url = 'https://shop.example.test/landing', dataset = {}, webdriver = false, fetchOk = true } = {}) {
  const listeners = {};
  const on = (target) => (type, fn) => { (listeners[target + type] ||= []).push(fn); };
  const fire = (target, type, event = {}) => (listeners[target + type] || []).forEach((fn) => fn(event));
  const writes = [];
  const storage = (name) => {
    const data = new Map();
    return {
      getItem: (k) => (data.has(k) ? data.get(k) : null),
      setItem: (k, v) => { writes.push(name + ':' + k); data.set(k, String(v)); },
    };
  };
  const location = new URL(url);
  const sent = [];
  const beacons = [];
  const history = {
    pushState(_s, _t, path) { location.href = new URL(path, location.href).href; },
    replaceState(_s, _t, path) { location.href = new URL(path, location.href).href; },
  };
  const document = {
    currentScript: { src: 'https://api.clickshield.test/track.js', dataset: { siteId: 'site_token_1234', ...dataset } },
    referrer: '', title: 'Shop', visibilityState: 'visible', documentElement: { scrollHeight: 2000 },
    addEventListener: on('doc:'), querySelector: () => null,
  };
  const window = {
    location, history, document, innerWidth: 1280, innerHeight: 800, scrollY: 0,
    screen: { width: 1920, height: 1080 },
    navigator: {
      userAgent: 'Mozilla/5.0 Chrome/129', language: 'en-US', languages: ['en-US'], webdriver, maxTouchPoints: 0,
      sendBeacon: (endpoint, blob) => { beacons.push({ endpoint, blob }); return true; },
    },
    localStorage: storage('local'), sessionStorage: storage('session'),
    crypto: globalThis.crypto, addEventListener: on('win:'),
    fetch: (endpoint, init) => {
      sent.push({ endpoint, init, events: JSON.parse(init.body).events });
      return fetchOk ? Promise.resolve({ status: 200 }) : Promise.reject(new Error('offline'));
    },
  };
  const context = vm.createContext({
    window, document, URL, URLSearchParams, Blob, Intl, Uint8Array, WeakSet, JSON, Date, Math, Array,
    // Unref'd timers: retry back-off loops must not keep the test process alive.
    setTimeout: (fn, ms) => { const t = setTimeout(fn, ms); t.unref?.(); return t; },
    clearTimeout, console,
  });
  vm.runInContext(SOURCE, context);
  const types = () => sent.flatMap((r) => r.events.map((e) => e.event_type));
  return { window, document, sent, beacons, writes, fire, types, cs: window.ClickShield };
}

async function beaconEvents(b) {
  const texts = await Promise.all(b.beacons.map((x) => x.blob.text()));
  return texts.flatMap((text) => JSON.parse(text).events);
}

test('paid landing: session_start, ad_landing, page_view with attribution, no global config', async () => {
  const b = browser({ url: 'https://shop.example.test/landing?gclid=G1&utm_source=google&adgroupid=77&keyword=plumber&matchtype=e&wbraid=W9' });
  b.cs.flush(); await tick();
  assert.deepEqual(b.types().slice(0, 3), ['session_start', 'ad_landing', 'page_view']);
  const first = b.sent[0].events[0];
  assert.equal(b.sent[0].endpoint, 'https://api.clickshield.test/api/v1/track');
  assert.equal(b.sent[0].init.headers['Content-Type'], 'text/plain');
  assert.equal(first.site_token, 'site_token_1234');
  assert.equal(first.gclid, 'G1');
  assert.equal(first.wbraid, 'W9');
  assert.equal(first.adgroup_id, '77');
  assert.equal(first.keyword, 'plumber');
  assert.equal(first.matchtype, 'e');
  assert.match(first.visitor_token, /^v_[0-9a-f-]{36}$/);
  assert.equal(first.payload.automation.webdriver, false);
});

test('organic visit has no ad_landing', async () => {
  const b = browser();
  b.cs.flush(); await tick();
  assert.deepEqual(b.types(), ['session_start', 'page_view']);
});

test('SPA navigation sends a page_view with the new URL', async () => {
  const b = browser();
  b.window.history.pushState({}, '', '/products/42');
  await tick(); b.cs.flush(); await tick();
  const views = b.sent.flatMap((r) => r.events).filter((e) => e.event_type === 'page_view');
  assert.equal(views.at(-1).page_url, 'https://shop.example.test/products/42');
});

test('all 11 event types of spec §11 can be produced', async () => {
  const b = browser({ url: 'https://shop.example.test/?gclid=G' });
  const link = (href, host) => ({ closest: () => ({ getAttribute: () => href, host, href }), tagName: 'A' });
  b.fire('doc:', 'click', { target: { closest: () => null, tagName: 'BUTTON' } });
  b.fire('doc:', 'click', { target: link('tel:+15550100', '') });
  b.fire('doc:', 'click', { target: link('https://other.test/x', 'other.test') });
  b.window.scrollY = 1200; b.fire('win:', 'scroll');
  const form = { id: 'quote', getAttribute: () => null };
  b.fire('doc:', 'focusin', { target: { form } });
  b.fire('doc:', 'focusin', { target: { form } });
  b.fire('doc:', 'submit', { target: form });
  b.cs.trackConversion({ value: 1 });
  b.document.visibilityState = 'hidden'; b.fire('doc:', 'visibilitychange');
  await tick();
  const events = [...b.sent.flatMap((r) => r.events), ...(await beaconEvents(b))];
  const all = new Set(events.map((e) => e.event_type));
  for (const t of ['ad_landing', 'page_view', 'scroll', 'click', 'form_start', 'form_submit', 'phone_click',
                   'outbound_click', 'session_start', 'session_end', 'conversion']) {
    assert.ok(all.has(t), `missing ${t}`);
  }
  assert.equal(events.filter((e) => e.event_type === 'form_start').length, 1, 'form_start once per form');
});

test('session_end goes out with sendBeacon on pagehide, with engaged time', async () => {
  const b = browser();
  b.fire('win:', 'pagehide');
  assert.equal(b.beacons.length, 1);
  assert.equal(b.beacons[0].blob.type, 'text/plain');
  const end = (await beaconEvents(b)).find((e) => e.event_type === 'session_end');
  assert.ok(end && typeof end.payload.engaged_ms === 'number');
});

test('require consent: no request and no storage write until consent(true)', async () => {
  const b = browser({ dataset: { requireConsent: 'true' } });
  b.cs.track('click'); b.cs.flush(); b.fire('win:', 'pagehide'); await tick();
  assert.equal(b.sent.length, 0);
  assert.equal(b.beacons.length, 0);
  assert.deepEqual(b.writes, []);
  b.cs.consent(true); await tick();
  assert.ok(b.sent.length >= 1);
  assert.ok(b.writes.some((w) => w.startsWith('local:cs_visitor')));
});

test('offline: the queue never grows above its cap', async () => {
  const b = browser({ fetchOk: false });
  for (let i = 0; i < 250; i++) b.cs.track('click', { i });
  await tick();
  assert.ok(b.cs.queueSize() <= 100, `queue ${b.cs.queueSize()}`);
});

test('webdriver flag is reported', async () => {
  const b = browser({ webdriver: true });
  b.cs.flush(); await tick();
  assert.equal(b.sent[0].events[0].payload.automation.webdriver, true);
});

test('script stays under 6 KB gzipped', () => {
  const size = gzipSync(Buffer.from(SOURCE)).length;
  assert.ok(size < 6144, `gzipped ${size} bytes`);
});
