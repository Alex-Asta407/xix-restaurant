// Service Worker for XIX Restaurant - Mobile Optimized
const CACHE_NAME = 'xix-restaurant-v2';

// Install event - minimal caching
self.addEventListener('install', (event) => {
  console.log('Service Worker installing...');
  self.skipWaiting(); // Force activation
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('Service Worker activating...');
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => {
      return self.clients.claim(); // Take control of all pages
    })
  );
});

// Fetch event - minimal interference for mobile compatibility
self.addEventListener('fetch', (event) => {
  // Only handle navigation requests for offline fallback
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => {
        return caches.match('/offline.html');
      })
    );
  }
  // For all other requests (API calls, form submissions, static assets), 
  // let them pass through normally without caching interference
});