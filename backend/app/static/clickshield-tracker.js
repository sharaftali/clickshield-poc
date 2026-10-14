/*! Click Shield tracker v2 (spec §8–§11, §19–§20; task 024).
 *  <script async src="https://<api>/track.js" data-site-id="<token>"></script>
 *  Optional: data-endpoint, data-require-consent="true", data-consent-mode="google".
 *  API: ClickShield.consent(true|false), ClickShield.track(type, payload), ClickShield.trackConversion(payload)
 *  No canvas / audio fingerprinting: only coarse, aggregated browser traits (§19).
 */
(function (w, d) {
  'use strict';
  if (w.ClickShield && w.ClickShield.__v2) return;

  var script = d.currentScript || d.querySelector('script[data-site-id]');
  var data = (script && script.dataset) || {};
  var legacy = w.ClickShieldConfig || {};
  var siteId = data.siteId || legacy.siteToken || '';
  if (!siteId) { (w.console || {}).warn && console.warn('[ClickShield] data-site-id is required'); return; }
  var origin = '';
  try { origin = new URL(script.src, w.location.href).origin; } catch (e) { /* inline */ }
  var endpoint = data.endpoint || legacy.trackingUrl || (origin + '/api/v1/track');
  var needConsent = data.requireConsent === 'true' || legacy.requireConsent === true;

  var SESSION_IDLE_MS = 30 * 60 * 1000, MAX_QUEUE = 100, BATCH = 10, FLUSH_MS = 3000;
  var K = { visitor: 'cs_visitor', session: 'cs_session', seen: 'cs_seen', attr: 'cs_attr' };
  var ATTR = ['gclid', 'gbraid', 'wbraid', 'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'campaignid', 'campaign_id', 'utm_id', 'adgroupid', 'keyword', 'matchtype'];

  var consented = !needConsent, queue = [], timer = null, backoff = 0, retryAt = 0;
  var memory = {}, visibleSince = Date.now(), engagedMs = 0, lastUrl = null, ended = false;

  function uuid() {
    var c = w.crypto;
    if (c && c.randomUUID) return c.randomUUID();
    var b = new Uint8Array(16);
    if (c && c.getRandomValues) c.getRandomValues(b); else for (var i = 0; i < 16; i++) b[i] = Math.random() * 256;
    b[6] = (b[6] & 15) | 64; b[8] = (b[8] & 63) | 128;
    var h = Array.prototype.map.call(b, function (x) { return (x + 256).toString(16).slice(1); }).join('');
    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
  }

  // No storage at all before consent (§9): values live in memory only.
  function store(kind) {
    if (!consented) return null;
    try { return kind === 'local' ? w.localStorage : w.sessionStorage; } catch (e) { return null; }
  }
  function get(kind, key) { var s = store(kind); try { return s ? s.getItem(key) : memory[key] || null; } catch (e) { return memory[key] || null; } }
  function set(kind, key, value) { memory[key] = value; var s = store(kind); try { if (s) s.setItem(key, value); } catch (e) { /* full / blocked */ } }

  function visitorId() {
    var v = get('local', K.visitor);
    if (!v) { v = 'v_' + uuid(); set('local', K.visitor, v); }
    return v;
  }

  // A session ends after 30 minutes without activity; the next activity starts a new one.
  function session() {
    var now = Date.now(), id = get('session', K.session), seen = +get('session', K.seen) || 0, fresh = false;
    if (!id || now - seen > SESSION_IDLE_MS) { id = 's_' + uuid(); fresh = true; set('session', K.session, id); }
    set('session', K.seen, String(now));
    return { id: id, fresh: fresh };
  }

  function attribution(fresh) {
    var saved = get('session', K.attr), params, out = {}, found = false;
    if (saved && !fresh) { try { return JSON.parse(saved); } catch (e) { /* re-read */ } }
    params = new URLSearchParams(w.location.search);
    ATTR.forEach(function (name) { var value = params.get(name); if (value) { out[name] = value.slice(0, 255); found = true; } });
    if (found || fresh) set('session', K.attr, JSON.stringify(out));
    return out;
  }

  function isPaid(a) {
    return !!(a.gclid || a.gbraid || a.wbraid || a.campaignid || a.campaign_id || a.utm_id ||
      (a.utm_source || '').toLowerCase().indexOf('google') !== -1);
  }

  function context() {
    var n = w.navigator || {}, sc = w.screen || {}, tz = null;
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || null; } catch (e) { /* old browser */ }
    var ua = n.userAgent || '';
    return {
      tz: tz,
      payload: {
        client_language: n.language || null, client_timezone: tz,
        screen_width: sc.width || null, screen_height: sc.height || null,
        viewport_width: w.innerWidth || null, viewport_height: w.innerHeight || null,
        touch_points: n.maxTouchPoints || 0,
        // Aggregated automation indicators (§20), booleans only.
        automation: {
          webdriver: n.webdriver === true,
          headless: /HeadlessChrome|PhantomJS|Puppeteer|Playwright/i.test(ua),
          no_languages: !!n.languages && n.languages.length === 0,
          tiny_viewport: (w.innerWidth || 1000) < 100 || (w.innerHeight || 1000) < 100
        }
      }
    };
  }

  var current = session(), attr = attribution(current.fresh), ctx = context();

  function event(type, payload) {
    var s = session();
    if (s.fresh && s.id !== current.id) { current = s; attr = attribution(true); startSession(); }
    var payloadOut = {}, k;
    for (k in ctx.payload) payloadOut[k] = ctx.payload[k];
    for (k in (payload || {})) payloadOut[k] = payload[k];
    return {
      site_token: siteId, visitor_token: visitorId(), session_token: current.id, event_type: type,
      page_url: w.location.href, timestamp: new Date().toISOString(),
      gclid: attr.gclid || null, gbraid: attr.gbraid || null, wbraid: attr.wbraid || null,
      campaign_id: attr.campaignid || attr.campaign_id || attr.utm_id || null,
      adgroup_id: attr.adgroupid || null, keyword: attr.keyword || null, matchtype: attr.matchtype || null,
      utm_source: attr.utm_source || null, utm_medium: attr.utm_medium || null, utm_campaign: attr.utm_campaign || null,
      utm_term: attr.utm_term || null, utm_content: attr.utm_content || null,
      language: (w.navigator && w.navigator.language) || null, timezone: ctx.tz,
      referrer: d.referrer || null, payload: payloadOut
    };
  }

  function push(type, payload) {
    queue.push(event(type, payload));
    while (queue.length > MAX_QUEUE) queue.shift(); // offline: keep the newest, never grow forever
    if (queue.length >= BATCH) flush(); else if (!timer) timer = setTimeout(flush, FLUSH_MS);
  }

  function flush(useBeacon) {
    clearTimeout(timer); timer = null;
    if (!consented || !queue.length) return;
    if (!useBeacon && Date.now() < retryAt) { timer = setTimeout(flush, retryAt - Date.now()); return; }
    var batch = queue.splice(0, 50), body = JSON.stringify({ events: batch });
    // text/plain: a CORS-safelisted type, so no preflight and sendBeacon works (§8 "send securely").
    if (useBeacon && w.navigator.sendBeacon && w.navigator.sendBeacon(endpoint, new Blob([body], { type: 'text/plain' }))) return;
    w.fetch(endpoint, { method: 'POST', body: body, keepalive: true, mode: 'cors', credentials: 'omit',
      headers: { 'Content-Type': 'text/plain' } })
      .then(function (r) {
        if (r.status === 429 || r.status >= 500) throw new Error('retry');
        backoff = 0; retryAt = 0;
        if (queue.length) flush();
      })
      .catch(function () {
        queue = batch.concat(queue).slice(-MAX_QUEUE);
        backoff = Math.min(60000, (backoff || 1000) * 2); retryAt = Date.now() + backoff;
        timer = setTimeout(flush, backoff);
      });
  }

  function startSession() {
    ended = false;
    push('session_start');
    if (isPaid(attr)) push('ad_landing', { landing_path: w.location.pathname });
  }

  function pageView() {
    if (w.location.href === lastUrl) return;
    lastUrl = w.location.href;
    push('page_view', { page_title: d.title });
  }

  function endSession() {
    if (ended) return;
    ended = true;
    if (d.visibilityState === 'visible') engagedMs += Date.now() - visibleSince;
    push('session_end', { engaged_ms: engagedMs });
    flush(true);
  }

  // ---- SPA navigation (§8) ----
  ['pushState', 'replaceState'].forEach(function (name) {
    var original = w.history[name];
    if (typeof original !== 'function') return;
    w.history[name] = function () { var result = original.apply(this, arguments); setTimeout(pageView, 0); return result; };
  });
  w.addEventListener('popstate', function () { setTimeout(pageView, 0); });

  // ---- interactions ----
  d.addEventListener('click', function (e) {
    var t = e.target, link = t && t.closest ? t.closest('a[href]') : null, href = link ? link.getAttribute('href') || '' : '';
    if (/^tel:/i.test(href)) { push('phone_click', { target: 'A' }); return; }
    if (link && link.host && link.host !== w.location.host && /^https?:/i.test(link.href)) {
      push('outbound_click', { host: link.host }); return;
    }
    push('click', { x: e.clientX, y: e.clientY, target: t && t.tagName ? t.tagName : 'UNKNOWN' });
  }, { capture: true, passive: true });

  var marks = [25, 50, 75, 100], reached = {};
  w.addEventListener('scroll', function () {
    var el = d.documentElement, height = el.scrollHeight - w.innerHeight;
    var depth = height > 0 ? Math.min(100, (w.scrollY / height) * 100) : 100;
    marks.forEach(function (m) { if (depth >= m && !reached[m]) { reached[m] = true; push('scroll', { depth: m }); } });
  }, { passive: true });

  var startedForms = typeof WeakSet === 'function' ? new WeakSet() : { has: function () { return false; }, add: function () {} };
  d.addEventListener('focusin', function (e) {
    var form = e.target && e.target.form;
    if (form && !startedForms.has(form)) { startedForms.add(form); push('form_start', { form: form.id || form.name || null }); }
  });
  d.addEventListener('submit', function (e) {
    var form = e.target;
    push('form_submit', { form: (form && (form.id || form.getAttribute('name'))) || null });
    flush(true);
  }, true);

  d.addEventListener('visibilitychange', function () {
    if (d.visibilityState === 'hidden') { engagedMs += Date.now() - visibleSince; endSession(); }
    else { visibleSince = Date.now(); ended = false; }
  });
  w.addEventListener('pagehide', endSession);

  // ---- consent (§9) ----
  function consent(granted) {
    consented = !!granted;
    if (!consented) { queue = []; return; }
    var k; for (k in memory) set(/^cs_visitor/.test(k) ? 'local' : 'session', k, memory[k]);
    flush();
  }
  if (needConsent && data.consentMode === 'google') {
    var granted = function (args) { return args && args[0] === 'consent' && args[2] && args[2].analytics_storage === 'granted'; };
    var layer = w.dataLayer = w.dataLayer || [];
    if (layer.some && layer.some(granted)) consented = true;
    var original = layer.push;
    layer.push = function () { var r = original.apply(layer, arguments); if (granted(arguments[0])) consent(true); return r; };
  }

  var api = {
    __v2: true,
    consent: consent,
    track: function (type, payload) { push(type, payload); },
    trackConversion: function (payload) { push('conversion', payload); flush(); },
    flush: function () { flush(); },
    queueSize: function () { return queue.length; }
  };
  w.ClickShield = api;
  w.ClickShieldTracker = api; // v1 name

  if (current.fresh) startSession();
  pageView();
})(window, document);
