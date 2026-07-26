// service-worker.js — permet a l'app de s'installer comme une PWA.
// Version minimale : met en cache la page d'accueil pour un chargement rapide.

const CACHE = "anti-arnaque-v1";
const A_METTRE_EN_CACHE = ["/", "/static/manifest.json"];

// Installation : on pre-charge l'essentiel
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(A_METTRE_EN_CACHE)));
  self.skipWaiting();
});

// Activation : on nettoie les vieux caches
self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((cles) =>
      Promise.all(cles.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    )
  );
});

// Requetes : on tente le reseau d'abord, avec le cache en secours.
// IMPORTANT : les analyses (/analyser) passent TOUJOURS par le reseau,
// car elles doivent etre fraiches (jamais servies depuis le cache).
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith("/analyser")) {
    return; // on laisse passer vers le reseau, pas de cache
  }
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});
