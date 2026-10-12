// One global Durable Object (op.js reaches it with idFromName("ledger")) that
// keeps the counters every upload and key attempt has to agree on: rate
// limits, bytes per session / IP per day, the pause switch, and the storage
// pool behind the hard stop. Each check-and-write below is one synchronous
// block of SQL, so concurrent requests can't both slip under a limit.
//
// The pool = both buckets' stored bytes (listed at most every POOL_TTL_MS)
// + the reservations of uploads that a listing hasn't counted yet (in flight,
// or finished after the last listing started).
//
// It also keeps the event queue that voidbot (and optool events) reads through
// the admin route: key entries, links, uploads, the pause switch, and files that
// appeared in or left the void-media bucket (found by the pool listing, so
// within POOL_TTL_MS of the copy; the bot's polls keep that listing running).

import { DurableObject } from "cloudflare:workers";

const POOL_TTL_MS = 10 * 60 * 1000;
// the bucket's lifecycle rule aborts unfinished multipart uploads after a day
const STALE_UPLOAD_MS = 2 * 24 * 3600 * 1000;
// event queue: kept this long, and never more than this many rows
const EVENT_KEEP_MS = 14 * 24 * 3600 * 1000;
const EVENT_MAX_ROWS = 20000;
const EVENT_PAGE_MAX = 1000;

export class Ledger extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.refreshing = null;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS hits (scope TEXT, who TEXT, slot INTEGER, n INTEGER, PRIMARY KEY (scope, who, slot));
      CREATE TABLE IF NOT EXISTS daily (day TEXT, who TEXT, bytes INTEGER, PRIMARY KEY (day, who));
      CREATE TABLE IF NOT EXISTS uploads (upload_id TEXT PRIMARY KEY, key TEXT, sid TEXT, ip TEXT, day TEXT,
        size INTEGER, created INTEGER, done INTEGER);
      CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT);
      CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER, kind TEXT, data TEXT);
      CREATE TABLE IF NOT EXISTS media (key TEXT PRIMARY KEY, size INTEGER);
    `);
  }

  // ----- small helpers -----
  get(k) {
    return this.sql.exec("SELECT v FROM state WHERE k = ?", k).toArray()[0]?.v ?? null;
  }

  set(k, v) {
    this.sql.exec("INSERT INTO state (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v", k, String(v));
  }

  dailyBytes(day, who) {
    return this.sql.exec("SELECT bytes FROM daily WHERE day = ? AND who = ?", day, who).toArray()[0]?.bytes ?? 0;
  }

  addDaily(day, who, bytes) {
    this.sql.exec(
      "INSERT INTO daily (day, who, bytes) VALUES (?, ?, ?) ON CONFLICT (day, who) DO UPDATE SET bytes = MAX(0, bytes + excluded.bytes)",
      day, who, bytes,
    );
  }

  reserved() {
    return this.sql.exec("SELECT COALESCE(SUM(size), 0) AS s FROM uploads").one().s;
  }

  // ----- rate limits: fixed windows -----
  // {ok} and counts the attempt, or {ok: false, retry: seconds} without counting it
  hit(scope, who, max, windowSec) {
    const now = Math.floor(Date.now() / 1000);
    const slot = Math.floor(now / windowSec);
    this.sql.exec("DELETE FROM hits WHERE scope = ? AND slot < ?", scope, slot);
    const n = this.sql.exec("SELECT n FROM hits WHERE scope = ? AND who = ? AND slot = ?", scope, who, slot).toArray()[0]?.n ?? 0;
    if (n >= max) return { ok: false, retry: (slot + 1) * windowSec - now };
    this.sql.exec(
      "INSERT INTO hits (scope, who, slot, n) VALUES (?, ?, ?, 1) ON CONFLICT (scope, who, slot) DO UPDATE SET n = n + 1",
      scope, who, slot,
    );
    return { ok: true };
  }

  // ----- pause switch -----
  isPaused() {
    return this.get("paused") === "1";
  }

  setPaused(on, by = "") {
    if (this.isPaused() !== on) this.log(on ? "pause" : "resume", { by });
    this.set("paused", on ? "1" : "0");
    return this.isPaused();
  }

  // ----- storage pool -----
  async refreshPool(force = false) {
    const at = Number(this.get("pool_at") ?? 0);
    if (!force && Date.now() - at < POOL_TTL_MS) return;
    if (!this.refreshing) {
      this.refreshing = (async () => {
        const started = Date.now();
        const media = await listBucket(this.env.MEDIA);
        const incoming = await listBucket(this.env.INCOMING);
        let stored = 0;
        for (const size of media.values()) stored += size;
        for (const size of incoming.values()) stored += size;
        this.set("stored", stored);
        this.diffMedia(media);
        this.set("pool_at", started);
        // finished before this listing began = counted in `stored` now
        this.sql.exec("DELETE FROM uploads WHERE done IS NOT NULL AND done < ?", started);
        this.sql.exec("DELETE FROM uploads WHERE done IS NULL AND created < ?", started - STALE_UPLOAD_MS);
        const twoDaysAgo = new Date(started - 2 * 86400 * 1000).toISOString().slice(0, 10);
        this.sql.exec("DELETE FROM daily WHERE day < ?", twoDaysAgo);
      })().finally(() => {
        this.refreshing = null;
      });
    }
    await this.refreshing;
  }

  poolUsed() {
    return Number(this.get("stored") ?? 0) + this.reserved();
  }

  // What an operator has left: {paused, dayLeft, poolLeft, used, budget}
  async status({ sid, ip, day, dayCap, budget }) {
    await this.refreshPool();
    const used = this.poolUsed();
    const dayUsed = Math.max(this.dailyBytes(day, "s:" + sid), this.dailyBytes(day, "i:" + ip));
    return {
      paused: this.isPaused(),
      dayLeft: Math.max(0, dayCap - dayUsed),
      poolLeft: Math.max(0, budget - used),
      used,
      budget,
    };
  }

  // Claims `size` bytes for a new upload, or says which limit stops it
  async reserve({ uploadId, key, sid, ip, day, size, dayCap, budget }) {
    await this.refreshPool();
    // from here on: no awaits, so the checks and the insert can't interleave
    if (this.isPaused()) return { ok: false, error: "paused" };
    const dayUsed = Math.max(this.dailyBytes(day, "s:" + sid), this.dailyBytes(day, "i:" + ip));
    if (dayUsed + size > dayCap) return { ok: false, error: "day", left: Math.max(0, dayCap - dayUsed) };
    const used = this.poolUsed();
    if (used + size > budget) return { ok: false, error: "pool", left: Math.max(0, budget - used) };
    this.sql.exec(
      "INSERT INTO uploads (upload_id, key, sid, ip, day, size, created, done) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
      uploadId, key, sid, ip, day, size, Date.now(),
    );
    this.addDaily(day, "s:" + sid, size);
    this.addDaily(day, "i:" + ip, size);
    return { ok: true };
  }

  lookup(uploadId) {
    return this.sql.exec("SELECT * FROM uploads WHERE upload_id = ?", uploadId).toArray()[0] ?? null;
  }

  // Finished: the reservation stays until a listing has counted the file
  complete(uploadId) {
    this.sql.exec("UPDATE uploads SET done = ? WHERE upload_id = ?", Date.now(), uploadId);
  }

  // Aborted or rejected: give the bytes back to the pool and the daily allowance
  release(uploadId) {
    const row = this.lookup(uploadId);
    if (!row) return;
    this.sql.exec("DELETE FROM uploads WHERE upload_id = ?", uploadId);
    this.addDaily(row.day, "s:" + row.sid, -row.size);
    this.addDaily(row.day, "i:" + row.ip, -row.size);
  }

  // ----- event queue -----
  log(kind, data = {}) {
    const now = Date.now();
    const { id } = this.sql.exec(
      "INSERT INTO events (at, kind, data) VALUES (?, ?, ?) RETURNING id", now, kind, JSON.stringify(data),
    ).one();
    this.sql.exec("DELETE FROM events WHERE at < ? OR id <= ?", now - EVENT_KEEP_MS, id - EVENT_MAX_ROWS);
    return id;
  }

  // {events: [{id, at, kind, ...data}], last, more}: the ones after `after`
  // (oldest first), or with `tail` the newest `tail` ones. `last` is the cursor
  // for the next call; a cursor older than the queue just starts at its oldest row,
  // one newer than the queue (it was emptied) starts over from the beginning.
  async events({ after = 0, limit = 200, tail = 0 } = {}) {
    await this.refreshPool();
    const n = Math.max(1, Math.min(EVENT_PAGE_MAX, Number(tail) || Number(limit) || 200));
    const top = this.sql.exec("SELECT COALESCE(MAX(id), 0) AS id FROM events").one().id;
    let from = Math.max(0, Number(after) || 0);
    if (from > top) from = 0;
    const rows = tail
      ? this.sql.exec("SELECT * FROM events ORDER BY id DESC LIMIT ?", n).toArray().reverse()
      : this.sql.exec("SELECT * FROM events WHERE id > ? ORDER BY id LIMIT ?", from, n + 1).toArray();
    const more = !tail && rows.length > n;
    if (more) rows.pop();
    return {
      events: rows.map((r) => ({ id: r.id, at: r.at, kind: r.kind, ...JSON.parse(r.data) })),
      last: rows.length ? rows[rows.length - 1].id : tail ? top : from,
      more,
      paused: this.isPaused(),
      used: this.poolUsed(),
    };
  }

  // Compares a fresh void-media listing with the last one: media-add / media-rm
  // events. The first listing after a deploy only fills the table (no events).
  diffMedia(listing) {
    const known = new Map(this.sql.exec("SELECT key, size FROM media").toArray().map((r) => [r.key, r.size]));
    const seeded = this.get("media_seeded") === "1";
    for (const [key, size] of listing) {
      if (known.get(key) === size) continue;
      this.sql.exec("INSERT INTO media (key, size) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET size = excluded.size", key, size);
      if (seeded) this.log("media-add", { key, size, replaced: known.has(key) });
    }
    for (const [key, size] of known) {
      if (listing.has(key)) continue;
      this.sql.exec("DELETE FROM media WHERE key = ?", key);
      if (seeded) this.log("media-rm", { key, size });
    }
    this.set("media_seeded", "1");
  }

  // optool status
  async summary() {
    await this.refreshPool(true);
    const inFlight = this.sql.exec("SELECT COUNT(*) AS n FROM uploads WHERE done IS NULL").one().n;
    return { paused: this.isPaused(), stored: Number(this.get("stored")), reserved: this.reserved(), inFlight };
  }
}

// key -> size of every object in a bucket
async function listBucket(bucket) {
  const objects = new Map();
  let cursor;
  do {
    const page = await bucket.list({ cursor, limit: 1000 });
    for (const obj of page.objects) objects.set(obj.key, obj.size);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return objects;
}
