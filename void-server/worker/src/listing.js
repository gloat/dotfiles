import { SITE_ORIGINS } from "./auth.js";

// Directory pages for media.gloat.ing. The markup copies nginx's fancyindex
// module (h1 "Directory:" + table#list), so the Nginx-Fancyindex theme
// (search, theme toggle, breadcrumbs, pagination, README.md rendering) works
// unchanged. The theme files live in the bucket under THEME (public, no login).
// "?json" returns the same listing as JSON for the site's panels (CORS for
// gloat.ing, with an "auth" flag so guests see what's locked). Listings are
// public: only the files themselves need the login cookie.

const THEME = "/public/_theme/";
const HIDDEN = new Set(["HEADER.md", "FOOTER.md"]); // fancyindex_ignore on the VPS
const MAX_PAGES = 50; // list() returns up to 1,000 keys per call
const TIME_ZONE = "America/Chicago"; // the VPS's zone (fancyindex_localtime on)
// bucket list() calls are billed as Class A operations, so each folder's list
// is cached per data center: a new upload shows up within LIST_TTL seconds
const LIST_TTL = 60;

const collator = new Intl.Collator("en", { numeric: true, sensitivity: "base" });
const dateParts = new Intl.DateTimeFormat("en-US", {
  timeZone: TIME_ZONE,
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
});

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'", // README.md fetch
  "worker-src 'none'", // the theme registers a service worker that only exists on gloat.ing
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

// The listing for `prefix` ("" = bucket root, else ends in "/"), or null if
// nothing is stored under it. `authed` = the visitor has the login cookie.
export async function listing(request, env, prefix, url, authed) {
  const { folders, files } = await cachedList(env.MEDIA, prefix, url.origin);
  const found = !prefix || folders.length > 0 || files.length > 0;

  if (url.searchParams.has("json")) {
    sortEntries(folders, "N", false);
    sortEntries(files, "N", false);
    const body = {
      auth: authed,
      folders: folders.map((f) => f.name),
      files: files.map((f) => ({ name: f.name, size: f.size, date: f.date.toISOString() })),
    };
    return json(found ? 200 : 404, body, request);
  }
  if (!found) return null;

  const column = url.searchParams.get("C") || "N";
  const descending = url.searchParams.get("O") === "D";
  sortEntries(folders, "N", descending);
  sortEntries(files, column, descending);

  const rows = [];
  if (prefix) rows.push(row("../", "Parent directory/", "-", "-"));
  for (const f of folders) rows.push(row(encodeURIComponent(f.name) + "/", f.name + "/", "-", "-"));
  for (const f of files) rows.push(row(encodeURIComponent(f.name), f.name, formatSize(f.size), formatDate(f.date)));

  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": CSP,
    "x-content-type-options": "nosniff",
    "referrer-policy": "same-origin",
  });
  return new Response(request.method === "HEAD" ? null : page(prefix, rows), { headers });
}

function json(status, body, request) {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
    "cache-control": "private, no-store", // "auth" differs per visitor
    "x-content-type-options": "nosniff",
    vary: "Origin",
  });
  // The site's fetch() sends the cookie (credentials: "include"), so CORS has to
  // name the exact origin; "*" is not allowed together with credentials
  const origin = request.headers.get("origin");
  if (SITE_ORIGINS.has(origin)) {
    headers.set("access-control-allow-origin", origin);
    headers.set("access-control-allow-credentials", "true");
  }
  return new Response(request.method === "HEAD" ? null : JSON.stringify(body), { status, headers });
}

// True if any key starts with `prefix` (used to redirect "/q3" to "/q3/")
export async function isFolder(env, prefix) {
  const page = await env.MEDIA.list({ prefix, limit: 1 });
  return page.objects.length > 0 || page.delimitedPrefixes.length > 0;
}

async function cachedList(bucket, prefix, origin) {
  const cache = caches.default;
  const cacheKey = new Request(`${origin}/__list/${encodeURIComponent(prefix)}`);
  const hit = await cache.match(cacheKey);
  const data = hit ? await hit.json() : await listAll(bucket, prefix);
  if (!hit) {
    const stored = new Response(JSON.stringify(data), {
      headers: { "content-type": "application/json", "cache-control": `max-age=${LIST_TTL}` },
    });
    await cache.put(cacheKey, stored);
  }
  // dates come back from the cache as strings
  for (const f of data.files) f.date = new Date(f.date);
  return data;
}

// The file's own modification time when the uploader kept it (rclone stores it as the "mtime"
// metadata: Unix seconds, or RFC 3339 from some versions), else the upload time
function fileDate(obj) {
  const m = obj.customMetadata?.mtime;
  const t = m ? (/^\d+(\.\d+)?$/.test(m) ? parseFloat(m) * 1000 : Date.parse(m)) : NaN;
  return Number.isFinite(t) ? new Date(t) : obj.uploaded;
}

async function listAll(bucket, prefix) {
  const folders = [];
  const files = [];
  let cursor;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await bucket.list({ prefix, delimiter: "/", cursor, include: ["customMetadata"] });
    for (const p of page.delimitedPrefixes) {
      folders.push({ name: p.slice(prefix.length, -1) });
    }
    for (const obj of page.objects) {
      const name = obj.key.slice(prefix.length);
      // "" = a zero-byte folder marker ("q3/") some tools create
      if (name && !HIDDEN.has(name)) files.push({ name, size: obj.size, date: fileDate(obj) });
    }
    if (!page.truncated) break;
    cursor = page.cursor;
  }
  return { folders, files };
}

// fancyindex's ?C=N|S|M (name, size, date) & O=A|D; folders stay on top
function sortEntries(list, column, descending) {
  const byName = (a, b) => collator.compare(a.name, b.name);
  const compare =
    column === "S" ? (a, b) => a.size - b.size || byName(a, b)
    : column === "M" ? (a, b) => a.date - b.date || byName(a, b)
    : byName;
  list.sort(descending ? (a, b) => compare(b, a) : compare);
}

function row(href, name, size, date) {
  return (
    `<tr><td colspan="2" class="link"><a href="${escapeHtml(href)}" title="${escapeHtml(name)}">` +
    `${escapeHtml(name)}</a></td><td class="size">${size}</td><td class="date">${date}</td></tr>`
  );
}

// fancyindex_exact_size off: "487.0 MiB"
function formatSize(bytes) {
  const units = ["KiB", "MiB", "GiB", "TiB"];
  if (bytes < 1024) return `${bytes} B`;
  let value = bytes;
  let unit = -1;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

// "2026-Oct-04 14:02", like fancyindex
function formatDate(date) {
  const p = Object.fromEntries(dateParts.formatToParts(date).map((x) => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}`;
}

function sortHeader(label, column) {
  return (
    `<a href="?C=${column}&amp;O=A">${label}</a>&nbsp;` +
    `<a href="?C=${column}&amp;O=D">&nbsp;&darr;&nbsp;</a>`
  );
}

function page(prefix, rows) {
  const path = escapeHtml("/" + prefix);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow, noai, noimageai">
<meta name="color-scheme" content="light dark">
<title>${path}</title>
<link rel="icon" href="${THEME}favicon.png">
<link rel="stylesheet" href="${THEME}styles.css">
</head>
<body class="theme-light">
<h1>Directory:
${path}</h1>
<table id="list"><thead><tr><th colspan="2">${sortHeader("File Name", "N")}</th><th>${sortHeader("File Size", "S")}</th><th>${sortHeader("Date", "M")}</th></tr></thead>
<tbody>${rows.join("\n")}
</tbody></table><div id="raw_include_README_md"></div>
<footer></footer>
<script src="${THEME}addNginxFancyIndexForm.js" defer></script>
<script src="${THEME}showdown.min.js" defer></script>
<script src="${THEME}purify.min.js" defer></script>
<script src="${THEME}readme.js" defer></script>
</body>
</html>
`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}
