
const CACHE = "platinumstay-v1";
const ASSETS = [
  "/", "/login",
  "/static/css/site.css",
  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css",
  "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(k => (k === CACHE ? null : caches.delete(k))))
    )
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  event.respondWith(
    caches.match(req).then((res) =>
      res ||
      fetch(req).then((netRes) => {
        if (netRes.ok && req.url.startsWith(self.location.origin)) {
          const copy = netRes.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return netRes;
      }).catch(() => caches.match("/login"))
    )
  );
});
