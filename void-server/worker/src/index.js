// void-media: serves the R2 bucket at media.gloat.ing to visitors logged in
// through /void/login (void_auth cookie, Domain=gloat.ing). Keys under
// PUBLIC_PREFIX skip the check (things guests see, e.g. the bg video).
// Supports Range (seeking = 206) and conditional requests (304).
// Paths ending in "/" are directory pages (src/listing.js), open to everyone.

import { isFolder, listing } from "./listing.js";
import { authorized } from "./auth.js";
import { handleOp } from "./op.js";

export { Ledger } from "./ledger.js";

const PUBLIC_PREFIX = "public/";
const LOGIN_URL = "https://gloat.ing/void/login";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // operator + link submission routes (op.js); "_op/" is never a key in the bucket
    if (url.pathname.startsWith("/_op/")) return handleOp(request, env, url);

    const method = request.method;
    if (method !== "GET" && method !== "HEAD") {
      return text(405, "Method Not Allowed", { Allow: "GET, HEAD" });
    }

    let key;
    try {
      key = decodeURIComponent(url.pathname.slice(1));
    } catch {
      return text(400, "Bad Request");
    }

    const authed = await authorized(request, env);
    if (key === "" || key.endsWith("/")) {
      return (await listing(request, env, key, url, authed)) ?? text(404, "Not Found");
    }

    const isPublic = key.startsWith(PUBLIC_PREFIX);
    if (!isPublic && !authed) {
      // a person opening a file from a listing page gets the login page;
      // <video>/<audio>/fetch requests get the 403
      const navigating = request.headers.get("sec-fetch-dest") === "document";
      return navigating ? Response.redirect(LOGIN_URL, 302) : text(403, "Forbidden");
    }

    if (method === "HEAD") {
      const head = await env.MEDIA.head(key);
      if (!head) return notFound(env, key, url);
      const headers = objectHeaders(head, isPublic);
      headers.set("content-length", String(head.size));
      return new Response(null, { headers });
    }

    // Seeking: ask R2 for the range directly (one round trip to the bucket) and
    // work out the Content-Range from the size it returns. Only a range R2
    // rejects (past the end) costs a head() for the size first.
    const wanted = parseRange(request.headers.get("range"));
    let obj;
    try {
      obj = await env.MEDIA.get(key, { onlyIf: request.headers, ...(wanted && { range: toR2Range(wanted) }) });
    } catch (err) {
      if (!wanted) throw err;
      const head = await env.MEDIA.head(key);
      if (!head) return text(404, "Not Found");
      const clamped = resolveRange(wanted, head.size);
      if (!clamped) return unsatisfiable(head.size);
      obj = await env.MEDIA.get(key, { onlyIf: request.headers, range: clamped });
    }
    if (obj === null) return notFound(env, key, url);

    const headers = objectHeaders(obj, isPublic);
    // The site's download buttons: a cross-origin <a download> is ignored by
    // browsers, so "?download" makes the response itself a download
    if (url.searchParams.has("download")) {
      headers.set("content-disposition", `attachment; filename*=UTF-8''${encodeRFC5987(key.split("/").pop())}`);
    }

    // An onlyIf precondition failed: R2 returns the metadata without a body
    if (!("body" in obj)) {
      const revalidating =
        request.headers.has("if-none-match") || request.headers.has("if-modified-since");
      return new Response(null, { status: revalidating ? 304 : 412, headers });
    }

    if (wanted) {
      const range = resolveRange(wanted, obj.size);
      if (!range) {
        // R2 answered a range past the end instead of rejecting it
        await obj.body.cancel();
        return unsatisfiable(obj.size);
      }
      const { offset, length } = range;
      headers.set("content-range", `bytes ${offset}-${offset + length - 1}/${obj.size}`);
      return new Response(obj.body, { status: 206, headers });
    }
    return new Response(obj.body, { headers });
  },
};

// A folder opened without the trailing slash ("/q3") is sent to "/q3/"
async function notFound(env, key, url) {
  if (await isFolder(env, key + "/")) {
    return new Response(null, { status: 302, headers: { location: url.pathname + "/", "cache-control": "no-store" } });
  }
  return text(404, "Not Found");
}

function objectHeaders(obj, isPublic) {
  const headers = new Headers();
  obj.writeHttpMetadata(headers); // content-type, cache-control, ... set at upload
  headers.set("etag", obj.httpEtag);
  headers.set("last-modified", obj.uploaded.toUTCString());
  headers.set("accept-ranges", "bytes");
  headers.set("x-content-type-options", "nosniff");
  if (!headers.has("cache-control")) {
    headers.set("cache-control", `${isPublic ? "public" : "private"}, max-age=86400`);
  }
  // public files are open anyway: any page may fetch() them (the site reads public/stats/ this way)
  if (isPublic) headers.set("access-control-allow-origin", "*");
  return headers;
}

// "bytes=start-end" / "bytes=start-" / "bytes=-suffix". Anything else (no
// header, multiple ranges, garbage) returns null = serve the whole object.
function parseRange(header) {
  const m = header && /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m || (m[1] === "" && m[2] === "")) return null;
  if (m[1] === "") return { suffix: Number(m[2]) };
  const start = Number(m[1]);
  const end = m[2] === "" ? Infinity : Number(m[2]);
  return end < start ? null : { start, end };
}

// The parsed range as an R2Range, before the object size is known
function toR2Range(wanted) {
  if ("suffix" in wanted) return { suffix: wanted.suffix };
  if (wanted.end === Infinity) return { offset: wanted.start };
  return { offset: wanted.start, length: wanted.end - wanted.start + 1 };
}

// Clamp to the object size: {offset, length}, or null if unsatisfiable
function resolveRange(wanted, size) {
  if ("suffix" in wanted) {
    const length = Math.min(wanted.suffix, size);
    return length > 0 ? { offset: size - length, length } : null;
  }
  if (wanted.start >= size) return null;
  return { offset: wanted.start, length: Math.min(wanted.end, size - 1) - wanted.start + 1 };
}

// filename* value: percent-encode everything outside RFC 5987's attr-char
function encodeRFC5987(name) {
  return encodeURIComponent(name).replace(/['()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

function unsatisfiable(size) {
  return text(416, "Range Not Satisfiable", { "Content-Range": `bytes */${size}` });
}

function text(status, body, extra = {}) {
  return new Response(body, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", ...extra },
  });
}
