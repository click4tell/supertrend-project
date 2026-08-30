/* sw.js — سرویس‌ورکر ساده برای کش آفلاین نسخه PWA فروشگاه MQL5 Expert */
var CACHE_NAME = 'mql5expert-pwa-v3';
var CORE_ASSETS = [
  './', './index.html', './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable.png'
];

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      return cache.addAll(CORE_ASSETS);
    }).catch(function () { /* اگر فایلی در دسترس نبود نادیده بگیر */ })
  );
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.filter(function (k) { return k !== CACHE_NAME; })
            .map(function (k) { return caches.delete(k); })
      );
    })
  );
  self.clients.claim();
});

/* استراتژی: کش اول، سپس شبکه — درخواست‌های Worker همیشه از شبکه */
self.addEventListener('fetch', function (event) {
  var url = new URL(event.request.url);

  // درخواست‌های API و POST را کش نمی‌کنیم
  if (event.request.method === 'POST' || url.hostname.includes('workers.dev')) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then(function (cached) {
      if (cached) return cached;
      return fetch(event.request).then(function (response) {
        if (response && response.status === 200 && response.type === 'basic') {
          var clone = response.clone();
          caches.open(CACHE_NAME).then(function (cache) { cache.put(event.request, clone); });
        }
        return response;
      }).catch(function () {
        return caches.match('./index.html');
      });
    })
  );
});
