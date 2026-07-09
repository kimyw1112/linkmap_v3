/* ════════════════════════════════════════════════════════════
   LinkMap — Service Worker  v4.0  (2026-06-21)

   전략: 네트워크 우선(Network First) + 오프라인 폴백
   ─ 파일이 바뀌면 항상 최신 버전을 먼저 받아옴
   ─ 오프라인이거나 네트워크 실패 시에만 캐시 사용
   ─ 쿼리스트링은 무시하고 경로만으로 캐시 매칭
   ─ 캐시 버전 올리면 이전 캐시 자동 파기
════════════════════════════════════════════════════════════ */
const CACHE_NAME = 'linkmap-v8';
const ASSETS = [
  './',
  './index.html',
  './app.html',
  './app.js',
  './style.css',
  './icon-192.png',
  './icon-512.png',
  './manifest.json',
];

/* ── 설치: 정적 파일 사전 캐시 ─── */
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME)
      .then(c => c.addAll(ASSETS))
      .then(() => self.skipWaiting())   // 즉시 활성화
  );
});

/* ── 활성화: 이전 캐시 완전 파기 ─── */
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())  // 열린 탭 즉시 제어
  );
});

/* ── Fetch: 네트워크 우선, 실패 시 캐시 ─── */
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

  // 같은 출처(GitHub Pages) 요청만 처리
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;

  e.respondWith(
    fetch(e.request)
      .then(networkRes => {
        // 네트워크 성공 → 캐시 갱신 후 반환
        if (networkRes && networkRes.status === 200) {
          const clone = networkRes.clone();
          caches.open(CACHE_NAME).then(c => {
            // 쿼리스트링 없는 URL로 캐시 저장 (캐시 키 통일)
            const cacheUrl = new URL(e.request.url);
            cacheUrl.search = '';
            c.put(new Request(cacheUrl.toString()), clone);
          });
        }
        return networkRes;
      })
      .catch(() => {
        // 네트워크 실패(오프라인) → 캐시에서 반환
        const cacheUrl = new URL(e.request.url);
        cacheUrl.search = '';
        return caches.match(new Request(cacheUrl.toString()), { ignoreSearch: true });
      })
  );
});

/* ── Push 이벤트 수신 ─── */
self.addEventListener('push', e => {
  let data = { title: '🔔 LinkMap 알림', body: '연락이 필요한 인맥이 있습니다.' };
  try { if (e.data) data = e.data.json(); } catch {}
  e.waitUntil(
    self.registration.showNotification(data.title, {
      body:    data.body,
      icon:    './icon-192.png',
      badge:   './icon-192.png',
      tag:     'linkmap-alert',
      vibrate: [200, 100, 200],
      data:    { url: './app.html' },
      actions: [
        { action: 'open',    title: '앱 열기' },
        { action: 'dismiss', title: '닫기'   },
      ],
    })
  );
});

/* ── 알림 클릭 처리 ─── */
self.addEventListener('notificationclick', e => {
  e.notification.close();
  if (e.action === 'dismiss') return;
  const url = (e.notification.data && e.notification.data.url) || './app.html';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const client of list) {
        if (client.url.includes('app.html') && 'focus' in client) return client.focus();
      }
      return clients.openWindow(url);
    })
  );
});

/* ── 백그라운드 동기화 ─── */
self.addEventListener('sync', e => {
  if (e.tag === 'check-alerts') e.waitUntil(Promise.resolve());
});
