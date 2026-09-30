// Tiny in-process TTL cache for expensive, read-mostly aggregate queries
// (dashboard/analytics). Keeps repeated refreshes and multiple open tabs
// from re-scanning the request log every few seconds.
const store = new Map();

export function cached(key, ttlMs, compute) {
  const now = Date.now();
  const hit = store.get(key);
  if (hit && hit.exp > now) return hit.value;
  const value = compute();
  store.set(key, { value, exp: now + ttlMs });
  if (store.size > 300) {
    for (const [k, v] of store) if (v.exp <= now) store.delete(k);
    if (store.size > 300) store.clear();
  }
  return value;
}

export function clearCache() {
  store.clear();
}
