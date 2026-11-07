/* CloudVault Service Worker - Offline Resilience & Low-Bandwidth Acceleration */
const CACHE_NAME = 'cloudvault-v1';
const PRECACHE_ASSETS = [
  '/manifest.webmanifest',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
  '/static/icons/icon.svg',
  '/offline',
  '/about',
  '/loading'
];

// Install: Pre-cache essential offline shell assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(PRECACHE_ASSETS).catch((err) => {
        console.warn('Pre-cache asset warning:', err);
      });
    }).then(() => self.skipWaiting())
  );
});

// Activate: Clean up obsolete caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch: Strategy adapted for weak/rural connections
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Skip mutating requests (POST, DELETE, PUT) and authentication endpoints from caching
  if (req.method !== 'GET' || url.pathname.startsWith('/logout') || url.pathname.startsWith('/upload')) {
    return;
  }

  // 1. Navigation requests (HTML pages)
  if (req.mode === 'navigate') {
    event.respondWith(
      // Network with 3.5s timeout fallback to avoid hanging on spotty 2G connections
      Promise.race([
        fetch(req).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const resClone = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
          }
          return networkResponse;
        }),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Network timeout on slow connection')), 3500)
        )
      ]).catch(async () => {
        const cached = await caches.match(req);
        if (cached) return cached;
        const offlinePage = await caches.match('/offline');
        if (offlinePage) return offlinePage;
        return caches.match('/loading');
      })
    );
    return;
  }

  // 2. Static assets & CDN fonts/icons: Cache First with background refresh
  if (
    url.pathname.startsWith('/static/') ||
    url.hostname.includes('fonts.googleapis.com') ||
    url.hostname.includes('fonts.gstatic.com') ||
    url.hostname.includes('cdnjs.cloudflare.com') ||
    url.hostname.includes('cdn.tailwindcss.com')
  ) {
    event.respondWith(
      caches.match(req).then((cachedResponse) => {
        if (cachedResponse) {
          // Revalidate in background for up-to-date styles
          fetch(req).then((networkResponse) => {
            if (networkResponse && networkResponse.status === 200) {
              caches.open(CACHE_NAME).then((cache) => cache.put(req, networkResponse));
            }
          }).catch(() => {});
          return cachedResponse;
        }

        return fetch(req).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const resClone = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
          }
          return networkResponse;
        }).catch(() => {
          // Fallback gracefully without breaking layout
          return new Response('', { status: 408, statusText: 'Offline' });
        });
      })
    );
    return;
  }

  // 3. Document streaming and API calls: Network first with graceful offline error
  event.respondWith(
    fetch(req).catch(async () => {
      const cached = await caches.match(req);
      if (cached) return cached;
      return new Response(JSON.stringify({ error: 'Network unavailable. Working in offline mode.' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    })
  );
});
