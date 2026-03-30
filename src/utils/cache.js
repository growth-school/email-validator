/** Simple LRU cache with per-entry TTL. Max 1000 entries; evicts oldest insertion order. */
class LRUCache {
  constructor(maxEntries = 1000) {
    this.maxEntries = maxEntries;
    /** @type {Map<string, { value: unknown, expiresAt: number }>} */
    this.store = new Map();
    /** @type {Map<string, number>} last SMTP attempt per MX host (ms) */
    this.smtpLastByMx = new Map();
  }

  has(key) {
    const e = this.store.get(key);
    if (!e) return false;
    if (Date.now() > e.expiresAt) {
      this.store.delete(key);
      return false;
    }
    return true;
  }

  get(key) {
    const e = this.store.get(key);
    if (!e) return undefined;
    if (Date.now() > e.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    this.store.delete(key);
    this.store.set(key, e);
    return e.value;
  }

  set(key, value, ttlMs) {
    const expiresAt = Date.now() + ttlMs;
    if (this.store.has(key)) this.store.delete(key);
    this.store.set(key, { value, expiresAt });
    while (this.store.size > this.maxEntries) {
      const first = this.store.keys().next().value;
      this.store.delete(first);
    }
  }

  delete(key) {
    return this.store.delete(key);
  }

  /**
   * Enforce minimum gap between SMTP attempts to the same MX host.
   * @param {string} mxHost normalized hostname
   * @param {number} minGapMs default 10000
   * @returns {number} ms to wait (0 if ok to proceed)
   */
  smtpThrottleWait(mxHost, minGapMs = 10_000) {
    const last = this.smtpLastByMx.get(mxHost);
    const now = Date.now();
    if (last == null) return 0;
    const elapsed = now - last;
    return elapsed >= minGapMs ? 0 : minGapMs - elapsed;
  }

  recordSmtpAttempt(mxHost) {
    this.smtpLastByMx.set(mxHost, Date.now());
    while (this.smtpLastByMx.size > this.maxEntries) {
      const oldest = this.smtpLastByMx.keys().next().value;
      this.smtpLastByMx.delete(oldest);
    }
  }

  clear() {
    this.store.clear();
    this.smtpLastByMx.clear();
  }
}

module.exports = { LRUCache: LRUCache, cache: new LRUCache(1000) };
