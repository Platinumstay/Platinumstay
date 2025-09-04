// /srv/platinumstay/sw.js
const CACHE = "platinumstay-v10";
const START_URL = "/login?source=pwa";
const PRECACHE = [
  START_URL,
  "/static/css/main.css",
  "/static/js/main.js",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
  "/static/manifest.json"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(PRECACHE))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  // Network-first for HTML, cache-first for others
  if (req.headers.get("accept")?.includes("text/html")) {
    event.respondWith(
      fetch(req).then((res) => {
        const clone = res.clone();
        caches.open(CACHE).then((c) => c.put(req, clone));
        return res;
      }).catch(() => caches.match(req, { ignoreSearch: true }) || caches.match(START_URL))
    );
  } else {
    event.respondWith(
      caches.match(req).then((hit) => hit || fetch(req).then((res) => {
        const clone = res.clone();
        caches.open(CACHE).then((c) => c.put(req, clone));
        return res;
      }))
    );
  }
});
