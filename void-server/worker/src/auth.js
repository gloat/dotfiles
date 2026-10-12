// Cookie helpers shared by the media routes (index.js), the listings and the
// operator routes (op.js).

export const SITE_ORIGINS = new Set(["https://gloat.ing", "https://www.gloat.ing"]);
export const AUTH_COOKIE = "void_auth";

export function getCookie(request, name) {
  const cookies = request.headers.get("cookie");
  if (!cookies) return null;
  for (const part of cookies.split(";")) {
    const eq = part.indexOf("=");
    if (eq >= 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

// The visitor has the login cookie from /void/login (or from an operator key, see op.js)
export async function authorized(request, env) {
  const expected = env.VOID_AUTH_TOKEN;
  if (!expected) return false; // secret not set: deny everything
  const cookie = getCookie(request, AUTH_COOKIE);
  return cookie !== null && sameString(cookie, expected);
}

export function sameString(a, b) {
  const enc = new TextEncoder();
  const x = enc.encode(a);
  const y = enc.encode(b);
  return x.byteLength === y.byteLength && crypto.subtle.timingSafeEqual(x, y);
}
