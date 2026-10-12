// Operator + link-submission routes under /_op/ (called from index.js).
//
// Operators get in with a channel key (one short public passphrase per Discord
// channel / platform, OP_KEYS = {channel: {hash, label}} holds only SHA-256
// hashes; tools/optool makes them). A key sets the void_op cookie (and
// void_auth, so an operator can always play media) and is logged with the
// visitor's IP / network / browser, so an abused channel can be traced and
// revoked on its own: the cookie is checked against OP_KEYS on every request.
//
// Uploads are R2 multipart uploads into the separate bucket void-incoming,
// which nothing here ever serves back: the owner reviews it with rclone.
// Links (anyone with void_auth) are small JSON files in the same bucket.
// Limits and the hard stop live in the Ledger Durable Object (ledger.js), and
// so does the event queue (note() below) that voidbot posts to IRC.

import { SITE_ORIGINS, AUTH_COOKIE, authorized, getCookie, sameString } from "./auth.js";
import { ALLOWED, SNIFF_BYTES, TEXT_MAX, contentMatches, extensionOf } from "./filetypes.js";

const OP_COOKIE = "void_op";
const COOKIE_MAX_AGE = 30 * 24 * 3600; // same as void_auth (void_auth.lua)
const PART_SIZE = 50 * 1024 * 1024; // the zone takes request bodies up to 100 MB
const MAX_PARTS = 10000;
const GB = 1e9;
// R2 custom metadata is capped at 2,048 bytes in total
const META_MAX = 2000;

// caps from wrangler.toml [vars], with fallbacks
function caps(env) {
  return {
    file: Number(env.OP_MAX_FILE_GB ?? 100) * GB,
    day: Number(env.OP_DAY_GB ?? 200) * GB,
    budget: Number(env.STORAGE_BUDGET_GB ?? 1950) * GB,
    keyTries: Number(env.OP_KEY_TRIES ?? 10), // per IP per 10 minutes
    keyTriesAll: Number(env.OP_KEY_TRIES_ALL ?? 300), // everyone, per 10 minutes
    linksIp: Number(env.OP_LINKS_PER_IP_DAY ?? 30),
    linksAll: Number(env.OP_LINKS_PER_DAY ?? 500),
  };
}

const ledger = (env) => env.LEDGER.get(env.LEDGER.idFromName("ledger"));
const today = () => new Date().toISOString().slice(0, 10);

// Adds an event to the Ledger's queue (read by voidbot / optool events through
// admin); a failed write is logged and never fails the request itself
async function note(env, kind, data) {
  try {
    await ledger(env).log(kind, data);
  } catch (err) {
    console.log(JSON.stringify({ event: "op-note-error", kind, message: String(err) }));
  }
}

// the visitor fields an event carries (who() has more, kept in the bucket logs)
const brief = (v) => ({ ip: v.ip, country: v.country, city: v.city, isp: v.isp, ua: v.ua.slice(0, 160) });

export async function handleOp(request, env, url) {
  const route = url.pathname.slice("/_op/".length);
  const origin = request.headers.get("origin");

  // optool (owner only): bearer token, no browser involved
  if (route === "admin") return admin(request, env);

  if (request.method === "OPTIONS") {
    if (!SITE_ORIGINS.has(origin)) return reply(request, 403, { error: "origin" });
    return new Response(null, {
      status: 204,
      headers: {
        ...corsHeaders(origin),
        "access-control-allow-methods": "GET, POST, PUT",
        "access-control-allow-headers": "content-type, x-op",
        "access-control-max-age": "86400",
      },
    });
  }
  // Only the site's own pages: the Origin and the custom header (which forces a
  // CORS preflight) stop other sites from riding the cookies, on top of SameSite
  if (!SITE_ORIGINS.has(origin) || request.headers.get("x-op") !== "1") {
    return reply(request, 403, { error: "origin" });
  }

  const routes = {
    "GET me": me,
    "POST login": login,
    "POST logout": logout,
    "POST link": submitLink,
    "POST upload/start": uploadStart,
    "PUT upload/part": uploadPart,
    "POST upload/complete": uploadComplete,
    "POST upload/abort": uploadAbort,
  };
  const handler = routes[`${request.method} ${route}`];
  if (!handler) return reply(request, 404, { error: "route" });
  try {
    return await handler(request, env, url);
  } catch (err) {
    if (err instanceof BadRequest) return reply(request, 400, { error: "bad", message: err.message });
    console.log(JSON.stringify({ event: "op-error", route, message: String(err?.stack || err) }));
    return reply(request, 500, { error: "server" });
  }
}

class BadRequest extends Error {}

async function readJson(request) {
  try {
    const body = await request.json();
    if (body && typeof body === "object") return body;
  } catch {}
  throw new BadRequest("expected a JSON object");
}

// ===== cookies =====

async function hmac(env, text) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(env.OP_COOKIE_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return base64url(new Uint8Array(sig));
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

let keysCache = { raw: null, parsed: {} };
function opKeys(env) {
  const raw = env.OP_KEYS || "{}";
  if (keysCache.raw !== raw) {
    let parsed = {};
    try {
      parsed = JSON.parse(raw);
    } catch {
      console.log(JSON.stringify({ event: "op-keys-invalid" }));
    }
    keysCache = { raw, parsed };
  }
  return keysCache.parsed;
}

// {channel, label, sid} for a valid void_op cookie whose channel still exists, else null
async function readOp(request, env) {
  if (!env.OP_COOKIE_SECRET) return null;
  const value = getCookie(request, OP_COOKIE);
  const m = value && /^([a-z0-9-]{1,40})\.([0-9a-f]{16})\.(\d{1,12})\.([\w-]{43})$/.exec(value);
  if (!m) return null;
  const [, channel, sid, exp, sig] = m;
  if (Number(exp) * 1000 < Date.now()) return null;
  if (!sameString(sig, await hmac(env, `${channel}.${sid}.${exp}`))) return null;
  const entry = opKeys(env)[channel];
  if (!entry) return null; // revoked
  return { channel, label: entry.label || channel, sid };
}

function cookieHeaders(env, channel, sid, exp, sig) {
  const headers = [
    `${OP_COOKIE}=${channel}.${sid}.${exp}.${sig}; Path=/_op/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Strict`,
  ];
  // the same cookie /void/login sets (void_auth.lua), so its logout clears this one too
  if (env.VOID_AUTH_TOKEN) {
    headers.push(
      `${AUTH_COOKIE}=${env.VOID_AUTH_TOKEN}; Domain=gloat.ing; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Strict`,
    );
  }
  return headers;
}

// ===== who is asking (logged with every key entry, link and upload) =====

function who(request) {
  const cf = request.cf || {};
  return {
    ip: request.headers.get("cf-connecting-ip") || "unknown",
    country: cf.country || "",
    region: cf.region || "",
    city: cf.city || "",
    asn: cf.asn ? String(cf.asn) : "",
    isp: cf.asOrganization || "",
    ua: (request.headers.get("user-agent") || "").slice(0, 300),
    lang: (request.headers.get("accept-language") || "").slice(0, 100),
  };
}

// Loose typing: "Ember Quad  strafe" = "ember-quad-strafe"
export function normalizeKey(key) {
  return (String(key).toLowerCase().match(/[a-z0-9]+/g) || []).join("-");
}

async function sha256hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(bytes) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ===== routes =====

async function status(request, env, op) {
  const c = caps(env);
  const auth = !!op || (await authorized(request, env));
  const body = {
    auth,
    op: !!op,
    channel: op ? op.label : null,
    allowed: Object.keys(ALLOWED),
    limits: { file: c.file, day: c.day, text: TEXT_MAX, part: PART_SIZE },
  };
  const book = ledger(env);
  if (op) {
    const s = await book.status({ sid: op.sid, ip: who(request).ip, day: today(), dayCap: c.day, budget: c.budget });
    Object.assign(body, { paused: s.paused, left: { day: s.dayLeft, pool: s.poolLeft }, pool: { used: s.used, budget: s.budget } });
  } else {
    body.paused = await book.isPaused();
  }
  return body;
}

async function me(request, env) {
  return reply(request, 200, await status(request, env, await readOp(request, env)));
}

async function login(request, env) {
  const body = await readJson(request);
  const c = caps(env);
  const visitor = who(request);
  const book = ledger(env);

  const perIp = await book.hit("key-ip", visitor.ip, c.keyTries, 600);
  if (!perIp.ok) return reply(request, 429, { error: "slow", retry: perIp.retry });
  const all = await book.hit("key-all", "*", c.keyTriesAll, 600);
  if (!all.ok) return reply(request, 429, { error: "slow", retry: all.retry });

  const hash = await sha256hex(normalizeKey(body.key ?? ""));
  let channel = null;
  for (const [name, entry] of Object.entries(opKeys(env))) {
    if (entry && typeof entry.hash === "string" && sameString(entry.hash, hash)) channel = name;
  }
  if (!channel || !env.OP_COOKIE_SECRET) {
    console.log(JSON.stringify({ event: "op-key-fail", ...visitor }));
    await note(env, "key-fail", brief(visitor));
    return reply(request, 401, { error: "key" });
  }

  const sid = randomHex(8);
  const exp = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
  const sig = await hmac(env, `${channel}.${sid}.${exp}`);
  const at = new Date().toISOString();
  await env.INCOMING.put(
    `_log/sessions/${today()}/${channel}-${sid}.json`,
    JSON.stringify({ at, channel, sid, ...visitor }, null, 1),
    { httpMetadata: { contentType: "application/json" } },
  );
  console.log(JSON.stringify({ event: "op-key-ok", channel, sid, ...visitor }));
  await note(env, "key-ok", { channel, sid, ...brief(visitor) });

  const op = { channel, label: opKeys(env)[channel].label || channel, sid };
  const res = reply(request, 200, await status(request, env, op));
  for (const cookie of cookieHeaders(env, channel, sid, exp, sig)) res.headers.append("set-cookie", cookie);
  return res;
}

async function logout(request) {
  const res = reply(request, 200, { ok: true });
  res.headers.append("set-cookie", `${OP_COOKIE}=; Path=/_op/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`);
  return res;
}

const clip = (v, max) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max) : "");

async function submitLink(request, env) {
  const op = await readOp(request, env);
  if (!op && !(await authorized(request, env))) return reply(request, 401, { error: "auth" });
  const body = await readJson(request);
  const c = caps(env);
  const visitor = who(request);
  const book = ledger(env);

  let link;
  try {
    link = new URL(String(body.url ?? "").trim());
  } catch {
    return reply(request, 400, { error: "url" });
  }
  if (!["http:", "https:"].includes(link.protocol) || link.href.length > 2000) {
    return reply(request, 400, { error: "url" });
  }
  if (await book.isPaused()) return reply(request, 503, { error: "paused" });

  const perIp = await book.hit("link-ip", visitor.ip, c.linksIp, 86400);
  if (!perIp.ok) return reply(request, 429, { error: "slow", retry: perIp.retry });
  const all = await book.hit("link-all", "*", c.linksAll, 86400);
  if (!all.ok) return reply(request, 429, { error: "slow", retry: all.retry });

  const record = {
    at: new Date().toISOString(),
    url: link.href,
    title: clip(body.title, 200),
    sender: clip(body.sender, 64),
    comment: clip(body.comment, 2000),
    credit: body.credit === true,
    channel: op?.channel ?? null,
    sid: op?.sid ?? null,
    ...visitor,
  };
  await env.INCOMING.put(`_links/${today()}/${Date.now()}-${randomHex(4)}.json`, JSON.stringify(record, null, 1), {
    httpMetadata: { contentType: "application/json" },
  });
  await note(env, "link", {
    url: record.url, title: record.title, sender: record.sender, comment: record.comment.slice(0, 300),
    credit: record.credit, channel: record.channel, sid: record.sid, ...brief(visitor),
  });
  return reply(request, 200, { ok: true });
}

// File and folder names: no control characters or slashes, no leading dots, Unicode kept
function cleanName(name, max = 180) {
  let s = String(name ?? "").normalize("NFC").replace(/[\u0000-\u001f\u007f]/g, "").replace(/[\/\\]/g, "_").trim();
  s = s.replace(/^\.+/, "").trim();
  if (s.length > max) {
    const ext = extensionOf(s);
    s = ext && ext.length < 12 ? s.slice(0, max - ext.length - 1) + "." + ext : s.slice(0, max);
  }
  return s;
}

function cleanPath(path) {
  const parts = String(path ?? "")
    .split(/[\/\\]+/)
    .map((p) => cleanName(p, 80))
    .filter((p) => p && p !== "." && p !== "..");
  return parts.slice(0, 6).join("/").slice(0, 300);
}

function partCount(size) {
  return Math.ceil(size / PART_SIZE);
}

// R2 metadata values are strings, 2 KB in total: trim the long fields until they fit
function fitMetadata(meta) {
  const size = () => Object.entries(meta).reduce((n, [k, v]) => n + k.length + new TextEncoder().encode(v).length, 0);
  for (const field of ["ua", "comment", "lang", "isp", "name"]) {
    while (size() > META_MAX && meta[field]) meta[field] = meta[field].slice(0, Math.floor(meta[field].length * 0.7));
  }
  return meta;
}

async function uploadStart(request, env) {
  const op = await readOp(request, env);
  if (!op) return reply(request, 401, { error: "op" });
  const body = await readJson(request);
  const c = caps(env);
  const visitor = who(request);

  const name = cleanName(body.name);
  const ext = extensionOf(name);
  if (!name) throw new BadRequest("missing name");
  const size = Number(body.size);
  const refused = async (statusCode, error, extra) => {
    await note(env, "upload-refused", { error, name, size, channel: op.channel, sid: op.sid, ip: visitor.ip, country: visitor.country });
    return reply(request, statusCode, { error, ...extra });
  };
  if (!ALLOWED[ext]) return refused(415, "type", { ext });
  if (!Number.isSafeInteger(size) || size < 1) throw new BadRequest("bad size");
  const max = ALLOWED[ext] === "text" ? TEXT_MAX : c.file;
  if (size > max || partCount(size) > MAX_PARTS) return refused(413, "size", { max });

  const path = cleanPath(body.path);
  const dir = `${op.channel}/${today()}/${op.sid}/${path ? path + "/" : ""}`;
  let key = dir + name;
  if (await env.INCOMING.head(key)) key = `${dir}${Date.now().toString(36)}-${name}`;

  const customMetadata = fitMetadata({
    name: String(body.name ?? "").slice(0, 300),
    sender: clip(body.sender, 64),
    comment: clip(body.comment, 500),
    credit: body.credit === true ? "1" : "0",
    channel: op.channel,
    sid: op.sid,
    size: String(size),
    ...visitor,
  });
  const upload = await env.INCOMING.createMultipartUpload(key, {
    httpMetadata: { contentType: "application/octet-stream" },
    customMetadata,
  });
  const claim = await ledger(env).reserve({
    uploadId: upload.uploadId, key, sid: op.sid, ip: visitor.ip, day: today(), size, dayCap: c.day, budget: c.budget,
  });
  if (!claim.ok) {
    await upload.abort().catch(() => {});
    const statusCode = { paused: 503, day: 429, pool: 507 }[claim.error] ?? 429;
    return refused(statusCode, claim.error, { left: claim.left });
  }
  return reply(request, 200, { key, uploadId: upload.uploadId, partSize: PART_SIZE });
}

// The upload must be in flight and belong to this operator session
async function ownedUpload(env, op, key, uploadId) {
  if (typeof key !== "string" || typeof uploadId !== "string") return null;
  const row = await ledger(env).lookup(uploadId);
  return row && row.key === key && row.sid === op.sid && row.done === null ? row : null;
}

async function uploadPart(request, env, url) {
  const op = await readOp(request, env);
  if (!op) return reply(request, 401, { error: "op" });
  const key = url.searchParams.get("key");
  const uploadId = url.searchParams.get("uploadId");
  const n = Number(url.searchParams.get("n"));
  const row = await ownedUpload(env, op, key, uploadId);
  if (!row) return reply(request, 404, { error: "upload" });

  // every part is PART_SIZE except the last (R2 needs equal parts), so the
  // finished file can only be the size that was reserved
  const count = partCount(row.size);
  if (!Number.isInteger(n) || n < 1 || n > count) throw new BadRequest("bad part number");
  const expected = n < count ? PART_SIZE : row.size - (count - 1) * PART_SIZE;
  if (Number(request.headers.get("content-length")) !== expected || !request.body) {
    throw new BadRequest(`part ${n} must be ${expected} bytes`);
  }
  const part = await env.INCOMING.resumeMultipartUpload(key, uploadId).uploadPart(n, request.body);
  return reply(request, 200, { partNumber: part.partNumber, etag: part.etag });
}

async function uploadComplete(request, env) {
  const op = await readOp(request, env);
  if (!op) return reply(request, 401, { error: "op" });
  const body = await readJson(request);
  const row = await ownedUpload(env, op, body.key, body.uploadId);
  if (!row) return reply(request, 404, { error: "upload" });

  const count = partCount(row.size);
  const parts = Array.isArray(body.parts) ? body.parts : [];
  const numbers = parts.map((p) => p?.partNumber).sort((a, b) => a - b);
  if (parts.length !== count || numbers.some((v, i) => v !== i + 1) || parts.some((p) => typeof p.etag !== "string")) {
    throw new BadRequest("parts don't cover the file");
  }
  const book = ledger(env);
  const obj = await env.INCOMING.resumeMultipartUpload(row.key, row.upload_id)
    .complete(parts.map((p) => ({ partNumber: p.partNumber, etag: p.etag })));

  const reject = async (error) => {
    await env.INCOMING.delete(row.key);
    await book.release(row.upload_id);
    console.log(JSON.stringify({ event: "op-upload-rejected", error, key: row.key, channel: op.channel, sid: op.sid }));
    await note(env, "upload-rejected", { error, key: row.key, size: row.size, channel: op.channel, sid: op.sid });
    return reply(request, 422, { error });
  };
  if (obj.size !== row.size) return reject("size");

  const head = await env.INCOMING.get(row.key, { range: { offset: 0, length: Math.min(SNIFF_BYTES, row.size) } });
  const first = new Uint8Array(await head.arrayBuffer());
  if (!contentMatches(extensionOf(row.key), first)) return reject("content");

  await book.complete(row.upload_id);
  console.log(JSON.stringify({ event: "op-upload", key: row.key, size: row.size, channel: op.channel, sid: op.sid }));
  const meta = head.customMetadata || {};
  await note(env, "upload", {
    key: row.key, size: row.size, channel: op.channel, sid: op.sid,
    sender: meta.sender || "", credit: meta.credit === "1", comment: meta.comment || "", country: meta.country || "",
  });
  return reply(request, 200, { ok: true, size: obj.size });
}

async function uploadAbort(request, env) {
  const op = await readOp(request, env);
  if (!op) return reply(request, 401, { error: "op" });
  const body = await readJson(request);
  const row = await ownedUpload(env, op, body.key, body.uploadId);
  if (!row) return reply(request, 404, { error: "upload" });
  await env.INCOMING.resumeMultipartUpload(row.key, row.upload_id).abort().catch(() => {});
  await ledger(env).release(row.upload_id);
  return reply(request, 200, { ok: true });
}

// ===== optool + voidbot: pause / resume / status / events =====
// {action: "events", after: <last id seen>, limit} or {action: "events", tail: n};
// pause/resume take an optional `by` (who flipped it, shown in the event);
// pending = the uploads waiting for review (voidbot !pending)

async function admin(request, env) {
  const auth = request.headers.get("authorization") || "";
  if (request.method !== "POST" || !env.OP_ADMIN_TOKEN || !sameString(auth, `Bearer ${env.OP_ADMIN_TOKEN}`)) {
    return reply(request, 403, { error: "admin" });
  }
  const body = await readJson(request).catch(() => ({}));
  const book = ledger(env);
  const by = clip(body.by, 64) || "admin";
  if (body.action === "events") {
    const page = await book.events({ after: body.after, limit: body.limit, tail: body.tail });
    return reply(request, 200, { ...page, budget: caps(env).budget });
  }
  if (body.action === "pending") return reply(request, 200, await pending(env));
  // dotfiles/sync.py watch: a secret found in the public dotfiles repo (voidbot posts it to #ops + highlights)
  if (body.action === "alert") {
    await note(env, "alert", { text: clip(body.text, 400), by });
    return reply(request, 200, { ok: true });
  }
  if (body.action === "pause") await book.setPaused(true, by);
  else if (body.action === "resume") await book.setPaused(false, by);
  else if (body.action !== "status") return reply(request, 400, { error: "action" });
  const c = caps(env);
  return reply(request, 200, { ...(await book.summary()), budget: c.budget, channels: Object.keys(opKeys(env)) });
}

// {files, bytes, newest: [{key, size, at}] (10 newest first)} of everything
// uploaded and not yet reviewed (the bucket minus its _log/ and _links/ folders)
async function pending(env) {
  const rows = [];
  let cursor;
  do {
    const page = await env.INCOMING.list({ cursor, limit: 1000 });
    for (const obj of page.objects) {
      if (!obj.key.startsWith("_log/") && !obj.key.startsWith("_links/")) {
        rows.push({ key: obj.key, size: obj.size, at: obj.uploaded.getTime() });
      }
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  rows.sort((a, b) => b.at - a.at);
  return { files: rows.length, bytes: rows.reduce((n, r) => n + r.size, 0), newest: rows.slice(0, 10) };
}

// ===== responses =====

function corsHeaders(origin) {
  return SITE_ORIGINS.has(origin)
    ? { "access-control-allow-origin": origin, "access-control-allow-credentials": "true", vary: "Origin" }
    : { vary: "Origin" };
}

function reply(request, status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...corsHeaders(request.headers.get("origin")),
    },
  });
}
