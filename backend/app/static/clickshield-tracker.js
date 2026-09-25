(function () {
  'use strict';

  const defaults = {
    siteToken: '',
    trackingUrl: 'http://localhost:8000/api/v1/track',
    sessionStorageKey: 'clickshield_session',
    visitorStorageKey: 'clickshield_visitor',
    maxQueueSize: 10,
    flushIntervalMs: 3000,
  };

  function getConfig() {
    const userConfig = window.ClickShieldConfig || {};
    return { ...defaults, ...userConfig };
  }

  function generateToken(prefix) {
    return prefix + '_' + Math.random().toString(36).slice(2) + Date.now().toString(36);
  }

  function getOrCreateStorageValue(storage, key, createValue) {
    const existing = storage.getItem(key);
    if (existing) return existing;
    const value = createValue();
    storage.setItem(key, value);
    return value;
  }

  function buildClientContext() {
    const timezone = window.Intl && typeof window.Intl.DateTimeFormat === 'function'
      ? window.Intl.DateTimeFormat().resolvedOptions().timeZone || null
      : null;

    return {
      client_language: navigator.language || null,
      client_timezone: timezone,
      screen_width: window.screen && typeof window.screen.width === 'number' ? window.screen.width : null,
      screen_height: window.screen && typeof window.screen.height === 'number' ? window.screen.height : null,
      viewport_width: typeof window.innerWidth === 'number' ? window.innerWidth : null,
      viewport_height: typeof window.innerHeight === 'number' ? window.innerHeight : null,
      touch_points: typeof navigator.maxTouchPoints === 'number' ? navigator.maxTouchPoints : 0,
    };
  }

  function buildEvent(eventType, payload, customMeta) {
    const config = getConfig();
    const params = new URLSearchParams(window.location.search);
    const clientContext = buildClientContext();

    return {
      site_token: config.siteToken,
      visitor_token: getOrCreateStorageValue(
        window.localStorage,
        config.visitorStorageKey,
        () => generateToken('v')
      ),
      session_token: getOrCreateStorageValue(
        window.sessionStorage,
        config.sessionStorageKey,
        () => generateToken('s')
      ),
      event_type: eventType,
      page_url: window.location.href,
      timestamp: new Date().toISOString(),
      gclid: params.get('gclid') || customMeta?.gclid || null,
      campaign_id: params.get('campaign_id') || params.get('campaignid') || params.get('utm_id') || customMeta?.campaign_id || null,
      utm_source: params.get('utm_source') || customMeta?.utm_source || null,
      utm_medium: params.get('utm_medium') || customMeta?.utm_medium || null,
      utm_campaign: params.get('utm_campaign') || customMeta?.utm_campaign || null,
      utm_term: params.get('utm_term') || customMeta?.utm_term || null,
      utm_content: params.get('utm_content') || customMeta?.utm_content || null,
      language: customMeta?.language || clientContext.client_language,
      timezone: customMeta?.timezone || clientContext.client_timezone,
      referrer: document.referrer || customMeta?.referrer || null,
      payload: { ...clientContext, ...(payload || {}) },
    };
  }

  function queueFlushQueue(queue) {
    if (!queue.length) return;

    const config = getConfig();
    const body = { events: queue.splice(0, queue.length) };

    fetch(config.trackingUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      keepalive: true,
      mode: 'cors',
    }).catch(function () {
      // keep queue intact if network fails; same message may be retried later
      queue.unshift(...body.events);
    });
  }

  function registerTracker() {
    const queue = [];
    const config = getConfig();

    if (!config.siteToken) {
      console.warn('[ClickShield] siteToken is required. Set window.ClickShieldConfig = { siteToken: "..." };');
      return;
    }

    const send = function (eventType, payload, customMeta) {
      queue.push(buildEvent(eventType, payload, customMeta));
      if (queue.length >= config.maxQueueSize) {
        queueFlushQueue(queue);
      }
    };

    const flush = function () {
      queueFlushQueue(queue);
    };

    const tracker = {
      send,
      flush,
      trackPageView: function (meta) {
        send('page_view', { page_title: document.title }, meta);
      },
      trackClick: function (meta) {
        send('click', { x: meta?.x, y: meta?.y, target: meta?.target || document.title }, meta);
      },
      trackScroll: function (depth, meta) {
        send('scroll', { depth: depth }, meta);
      },
      trackConversion: function (payload, meta) {
        send('conversion', payload || {}, meta);
      },
    };

    window.ClickShieldTracker = tracker;

    tracker.trackPageView();

    document.addEventListener('click', function (event) {
      const target = event.target;
      const meta = {
        x: event.clientX,
        y: event.clientY,
        target: target && target.tagName ? target.tagName : 'UNKNOWN',
      };
      tracker.trackClick(meta);
    }, { passive: true, capture: true });

    let scrollDepth = 0;
    function handleScroll() {
      const documentHeight = document.documentElement.scrollHeight - window.innerHeight;
      const currentDepth = documentHeight > 0 ? (window.scrollY / documentHeight) * 100 : 0;
      const boundedDepth = Math.min(100, Math.max(0, currentDepth));
      if (boundedDepth >= 50 && boundedDepth > scrollDepth) {
        scrollDepth = boundedDepth;
        tracker.trackScroll(boundedDepth);
      }
    }

    window.addEventListener('scroll', handleScroll, { passive: true });
    window.addEventListener('beforeunload', flush);
    setInterval(flush, config.flushIntervalMs);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', registerTracker, { once: true });
  } else {
    registerTracker();
  }
})();
