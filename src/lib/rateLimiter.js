// In-memory sliding-window rate limiter.
//
// PRODUCTION NOTE: replace the `store` Map below with Redis (e.g. ioredis)
// for distributed rate limiting across multiple app instances — the
// interface (`incrementAndCheck`) is designed to map directly onto a
// Redis INCR + EXPIRE / sorted-set implementation, so callers never change.

const store = new Map(); // key -> [timestamps]

function prune(list, windowMs, now) {
  while (list.length && now - list[0] > windowMs) list.shift();
  return list;
}

/**
 * Returns { allowed, remaining, retryAfterSeconds }
 */
export function incrementAndCheck(key, limit, windowMs) {
  if (!limit || limit <= 0) return { allowed: true, remaining: Infinity, retryAfterSeconds: 0 };
  const now = Date.now();
  let list = store.get(key);
  if (!list) {
    list = [];
    store.set(key, list);
  }
  prune(list, windowMs, now);
  if (list.length >= limit) {
    const retryAfterSeconds = Math.ceil((windowMs - (now - list[0])) / 1000);
    return { allowed: false, remaining: 0, retryAfterSeconds: Math.max(retryAfterSeconds, 1) };
  }
  list.push(now);
  return { allowed: true, remaining: limit - list.length, retryAfterSeconds: 0 };
}

// Periodic cleanup so the map doesn't grow unbounded on long-running processes
setInterval(() => {
  const now = Date.now();
  for (const [key, list] of store.entries()) {
    prune(list, 24 * 60 * 60 * 1000, now);
    if (list.length === 0) store.delete(key);
  }
}, 10 * 60 * 1000).unref();
