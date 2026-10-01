/*
  Aiden's Browser proxy (a Cloudflare Worker)

  Websites like Wikipedia send headers that say "don't show me
  inside an iframe". This Worker fetches the page for us, deletes
  those headers, and sends the page back so the iframe can show it.

  Routes:
    POST /login               { username, password }  ->  { token, username, role }
    ANY  /p/<token>/<address> fetches <address> through the proxy

  Admin routes (need "Authorization: Bearer <token>" from an admin account):
    GET  /admin/users         every account and whether it's disabled
    POST /admin/password      { username, password, reason }  change a password
    POST /admin/disable       { username, disabled, reason }  turn a login off/on

  Accounts live in the USERS KV database as "user:<name>" -> {
    role:      "user" | "admin"
    salt, hash               the password, hashed (never the real password)
    disabled:  true when an admin turned the login off
    reason:    what the admin typed; shown to the user when they try to log in
    previous:  { salt, hash } of the password before an admin changed it,
               so typing the old password shows the reason
    changedAt: when an admin last changed this account; older logins stop working
  }
  Create accounts with "npm run user" (scripts/user.mjs).
  There's no sign-up page on purpose: only people you add can log in.

  Secret (set with "npx wrangler secret put SECRET"):
    SECRET    a long random string used to sign tokens
*/

/* How long a login lasts */
const TOKEN_HOURS = 12;
const TOKEN_MS = TOKEN_HOURS * 60 * 60 * 1000;

/*
  Password hashing settings. scripts/user.mjs must use the same ones.
  PBKDF2 runs the hash 100,000 times so guessing passwords is slow.
  (100,000 is the most Cloudflare Workers allow.)
*/
const HASH_ITERATIONS = 100000;

/* Usernames: 3-20 letters, numbers, _ or - (also keeps tokens URL-safe) */
const USERNAME_PATTERN = /^[a-z0-9_-]{3,20}$/;

/* Reasons are shown on the login screen, so keep them short */
const MAX_REASON_LENGTH = 200;

/* Lets the GitHub Pages site call /login and /admin */
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

/* Headers we remove from every page */
const BLOCKING_HEADERS = [
  "x-frame-options",                     // "don't put me in an iframe"
  "content-security-policy",             // can also say that (frame-ancestors)
  "content-security-policy-report-only",
  "cross-origin-embedder-policy",        // would block the page's own images
  "set-cookie",                          // every site shares our one domain
  "strict-transport-security",
  "content-encoding",                    // fetch() already unzipped the body
  "content-length"                       // wrong once we change the page
];


export default {

  async fetch(request, env) {

    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    if (url.pathname === "/login" && request.method === "POST") {
      return login(request, env);
    }

    if (url.pathname.startsWith("/admin/")) {
      return admin(request, env, url);
    }

    if (url.pathname.startsWith("/p/")) {
      return proxy(request, env, url);
    }

    return new Response("Aiden's Browser proxy is running.", { headers: CORS });

  }

};


/* =========================
   LOGIN
========================= */

/* Made-up account, so a wrong username takes as long as a wrong password */
const NOBODY = { salt: "AAAAAAAAAAAAAAAAAAAAAA", hash: "" };


async function login(request, env) {

  const body = await readJson(request);

  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");

  const account =
    (USERNAME_PATTERN.test(username) && await getAccount(env, username)) || NOBODY;

  /*
    Hash what they typed with the account's salt and compare.
    We never store or compare the real password.
  */

  const typedHash = await hashPassword(password, account.salt);

  const rightPassword =
    Boolean(account.hash) && sameText(typedHash, account.hash);

  /* The password an admin replaced: tell them why it stopped working */
  const oldPassword =
    !rightPassword && Boolean(account.previous) &&
    sameText(await hashPassword(password, account.previous.salt), account.previous.hash);


  if (!env.SECRET || (!rightPassword && !oldPassword)) {
    return json({ error: CONTACT }, 401);
  }

  if (account.disabled || oldPassword) {
    return json({ error: CONTACT, reason: account.reason || "" }, 403);
  }

  /*
    The token is "<username>.<expiry time>.<signature>".
    Only someone who knows SECRET can make a valid
    signature, so tokens can't be faked or extended.
  */

  const expires = String(Date.now() + TOKEN_MS);
  const signed = username + "." + expires;

  return json({
    token: signed + "." + await sign(signed, env.SECRET),
    username,
    role: account.role || "user"
  });

}


async function getAccount(env, username) {

  return env.USERS.get("user:" + username, "json");

}


async function saveAccount(env, username, account) {

  await env.USERS.put("user:" + username, JSON.stringify(account));

}


async function readJson(request) {

  try {
    return await request.json();
  } catch {
    return {};  // Not JSON, so the checks that use it fail
  }

}


async function hashPassword(password, salt) {

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromBase64Url(salt), iterations: HASH_ITERATIONS },
    key,
    256
  );

  return toBase64Url(bits);

}


async function sign(text, secret) {

  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return toBase64Url(await crypto.subtle.sign("HMAC", key, encoder.encode(text)));

}


/*
  Checks the token and returns { username, account }, or null.
  The account is read fresh every time, so removing or disabling
  someone, or changing their password, logs them out right away.
*/

async function checkToken(token, env) {

  const [username, expires, signature] = token.split(".");

  if (!username || !expires || !signature || !env.SECRET) return null;

  if (Number(expires) < Date.now()) return null;

  if (!sameText(signature, await sign(username + "." + expires, env.SECRET))) return null;

  const account = await getAccount(env, username);

  if (!account || account.disabled) return null;

  /* Logged in before an admin changed this account? Not anymore. */
  const issuedAt = Number(expires) - TOKEN_MS;

  if (account.changedAt && issuedAt < account.changedAt) return null;

  return { username, account };

}


/* Compares secrets without leaking (through timing) how much matched */

function sameText(a, b) {

  const encoder = new TextEncoder();
  const bytesA = encoder.encode(a);
  const bytesB = encoder.encode(b);

  return bytesA.length === bytesB.length && crypto.subtle.timingSafeEqual(bytesA, bytesB);

}


/* Base64 that is safe to put in a URL */

function toBase64Url(buffer) {

  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

}


function fromBase64Url(text) {

  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));

  return Uint8Array.from(binary, char => char.charCodeAt(0));

}


/* =========================
   ADMIN PANEL
========================= */

async function admin(request, env, url) {

  const token = (request.headers.get("Authorization") || "").replace(/^Bearer /, "");

  const me = await checkToken(token, env);

  if (!me || me.account.role !== "admin") {
    return json({ error: CONTACT }, 403);
  }


  /* Every account, without the password hashes */

  if (url.pathname === "/admin/users" && request.method === "GET") {

    const users = [];
    let cursor;

    do {

      const page = await env.USERS.list({ prefix: "user:", cursor });

      for (const key of page.keys) {

        const account = await env.USERS.get(key.name, "json");

        users.push({
          username: key.name.slice("user:".length),
          role: account.role || "user",
          disabled: Boolean(account.disabled),
          reason: account.reason || ""
        });

      }

      cursor = page.list_complete ? undefined : page.cursor;

    } while (cursor);

    return json({ users });

  }


  if (request.method !== "POST") {
    return json({ error: "Unknown admin action" }, 404);
  }


  const body = await readJson(request);

  const username = String(body.username || "").trim().toLowerCase();
  const reason = String(body.reason || "").trim().slice(0, MAX_REASON_LENGTH);

  const account = USERNAME_PATTERN.test(username) && await getAccount(env, username);

  if (!account) {
    return json({ error: "No account called " + username }, 404);
  }


  /* Change a password (typing the old one then shows the reason) */

  if (url.pathname === "/admin/password") {

    const password = String(body.password || "");

    if (!password) {
      return json({ error: "Type a new password" }, 400);
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));

    account.previous = { salt: account.salt, hash: account.hash };
    account.salt = toBase64Url(salt);
    account.hash = await hashPassword(password, account.salt);
    account.reason = reason;
    account.changedAt = Date.now();

    await saveAccount(env, username, account);

    return json({ ok: true });

  }


  /* Turn a login off (with a reason) or back on */

  if (url.pathname === "/admin/disable") {

    const disabled = Boolean(body.disabled);

    /* Don't let the admin lock themselves out */
    if (disabled && username === me.username) {
      return json({ error: "You can't disable your own account" }, 400);
    }

    account.disabled = disabled;
    account.reason = disabled ? reason : "";
    account.changedAt = Date.now();

    await saveAccount(env, username, account);

    return json({ ok: true });

  }


  return json({ error: "Unknown admin action" }, 404);

}


/* =========================
   PROXY
========================= */

async function proxy(request, env, url) {

  /*
    The address is "/p/<token>/https://site.com/page".
    The ?query part comes separately, so a search form
    on the page can add its own ?q=... and still work.
  */

  const rest = url.pathname.slice("/p/".length);
  const slash = rest.indexOf("/");
  const token = slash === -1 ? rest : rest.slice(0, slash);

  if (!(await checkToken(token, env))) {
    return errorPage(401, "Your login ran out. Log in again to keep browsing.", true);
  }

  /* Some tools squash "https://" into "https:/", so put it back */
  const address =
    rest.slice(slash + 1).replace(/^(https?):\/*/i, "$1://") + url.search;

  let target;

  try {
    target = new URL(address);
  } catch {
    return errorPage(400, "That isn't a valid web address.");
  }

  if (!/^https?:$/.test(target.protocol) || target.hostname === url.hostname) {
    return errorPage(400, "That address can't be opened through the proxy.");
  }


  /* Pass along only harmless headers (no cookies) */

  const headers = new Headers();

  for (const name of ["accept", "accept-language", "content-type", "user-agent"]) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }


  let response;

  try {
    response = await fetch(target, {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      redirect: "follow"
    });
  } catch {
    return errorPage(502, "Couldn't reach " + target.hostname + ".");
  }


  const outHeaders = new Headers(response.headers);

  for (const name of BLOCKING_HEADERS) {
    outHeaders.delete(name);
  }

  const result = new Response(response.body, {
    status: response.status,
    headers: outHeaders
  });


  /* Images, PDFs, etc. go straight through */

  const type = outHeaders.get("content-type") || "";

  if (!type.includes("text/html")) {
    return result;
  }

  /* After redirects, this is where we really ended up */
  const pageUrl = response.url || target.href;

  return rewritePage(result, pageUrl, url.origin + "/p/" + token + "/");

}


/* =========================
   REWRITING THE PAGE
========================= */

/*
  Links on the page point at the real site, so clicking
  one would leave the proxy (and show a blank iframe).
  We change every link to go through the proxy instead.

  Images, CSS, and scripts don't need the proxy: they're
  allowed to load from other sites, so a <base> tag
  pointing at the real site is enough for them.
*/

function rewritePage(response, pageUrl, proxyBase) {

  function toProxy(link) {

    link = link.trim();

    if (!link || link.startsWith("#")) return null;

    try {

      const absolute = new URL(link, pageUrl);

      if (!/^https?:$/.test(absolute.protocol)) return null;  // mailto:, javascript:, ...

      return proxyBase + absolute.href;

    } catch {
      return null;
    }

  }


  const rewriteLink = attribute => ({
    element(el) {

      const proxied = toProxy(el.getAttribute(attribute) || "");

      if (proxied) el.setAttribute(attribute, proxied);

      /* target="_top" would try to replace the whole browser page */
      if (/^_(top|parent)$/i.test(el.getAttribute("target") || "")) {
        el.setAttribute("target", "_self");
      }

    }
  });


  /* Add our <base> tag and helper script to the top of the page */

  let injected = false;

  const inject = {
    element(el) {

      if (injected) return;

      injected = true;

      el.prepend(
        `<base href="${escapeHtml(pageUrl)}">` + helperScript(pageUrl, proxyBase),
        { html: true }
      );

    }
  };


  return new HTMLRewriter()

    .on("head", inject)
    .on("body", inject)   // for pages with no <head>

    /* Only our <base> should count */
    .on("base", { element: el => el.remove() })

    .on("a[href]", rewriteLink("href"))
    .on("area[href]", rewriteLink("href"))
    .on("form[action]", rewriteLink("action"))

    .on("meta[http-equiv]", {
      element(el) {

        const kind = (el.getAttribute("http-equiv") || "").toLowerCase();

        /* Same blocking rules as the header, written in the page */
        if (kind.startsWith("content-security-policy")) {
          el.remove();
        }

        /* <meta http-equiv="refresh" content="0; url=..."> redirects */
        if (kind === "refresh") {

          const content = el.getAttribute("content") || "";
          const match = content.match(/^(\s*\d+\s*[;,]\s*url\s*=\s*)['"]?([^'"]+)['"]?\s*$/i);
          const proxied = match && toProxy(match[2]);

          if (proxied) el.setAttribute("content", match[1] + proxied);

        }

      }
    })

    .transform(response);

}


/*
  Runs inside every proxied page. It:
  - tells Aiden's Browser which page we're on (for the address bar and tab)
  - catches links and forms the page's own JavaScript made after loading
  - keeps "#section" links on the page
*/

function helperScript(pageUrl, proxyBase) {

  const data = JSON.stringify({ pageUrl, proxyBase }).replace(/</g, "\\u003c");

  return `<script>
(() => {
  const { pageUrl, proxyBase } = ${data};

  const proxied = link =>
    /^https?:/i.test(link) && !link.startsWith(proxyBase) ? proxyBase + link : link;

  addEventListener("DOMContentLoaded", () => {
    parent.postMessage({ type: "aiden-page", url: pageUrl, title: document.title }, "*");
  });

  document.addEventListener("click", event => {
    const link = event.target.closest && event.target.closest("a[href]");
    if (!link || typeof link.href !== "string") return;

    const raw = link.getAttribute("href");
    if (raw.startsWith("#")) {
      event.preventDefault();
      location.hash = raw;
      return;
    }

    if (/^_(top|parent)$/i.test(link.target)) link.target = "_self";
    link.href = proxied(link.href);
  }, true);

  document.addEventListener("submit", event => {
    const form = event.target;
    const action = form.getAttribute("action");
    if (action) form.setAttribute("action", proxied(new URL(action, document.baseURI).href));
  }, true);
})();
</script>`;

}


/* =========================
   HELPERS
========================= */

function json(data, status = 200) {

  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" }
  });

}


function escapeHtml(text) {

  return text
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

}


/* What every error page says */
const CONTACT = "Contact caterjake05@gmail.com";


/*
  A dark error page that matches the browser. Visitors only see
  CONTACT; the real reason is hidden in an HTML comment so you
  can still find it with F12.
*/

function errorPage(status, reason, loggedOut = false) {

  /* Tells Aiden's Browser to show the login screen again */
  const logout = loggedOut
    ? `<script>parent.postMessage({ type: "aiden-logout" }, "*");</script>`
    : "";

  return new Response(
    `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Error</title></head>
<body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
  background:#0d0d1a;color:#ddd;font-family:Arial,sans-serif;text-align:center;padding:20px">
  <!-- ${escapeHtml(reason)} -->
  <p style="font-size:18px">${CONTACT}</p>
  ${logout}
</body>
</html>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8" } }
  );

}
