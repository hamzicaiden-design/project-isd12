# Aiden's Browser

A mini web browser that runs inside a web page. It's built with plain HTML, CSS, and JavaScript, with no libraries. Websites load through a small proxy running on Cloudflare Workers (in the `proxy/` folder), so sites that normally refuse to show inside an iframe still work.

## Features

- 🔒 Username and password login with a neon glow design. Accounts are checked by the proxy, not the page.
- 👑 Admin panel (admin accounts only): change anyone's password or disable their login, with a reason that the person sees when they try to log in. Either change logs them out right away.
- 🌐 Address bar: type a website (like `wikipedia.org`) or search words (they go to Bing)
- 🔁 Pages load through the proxy, and clicking links keeps you inside the browser
- ← → ⟳ ⌂ Back, forward, reload, and home buttons, using my own history list
- 🏷️ The tab shows the title of the page you're on
- ↗ An "Open in new tab" button for sites that don't work well through the proxy

## How it fits together

```
index.html (GitHub Pages)  --->  proxy (Cloudflare Worker)  --->  the real website
     iframe shows the page  <---  removes blocking headers,  <---
                                  rewrites links
```

- `POST /login` checks the username and password and returns a token that lasts 12 hours.
- `/admin/users`, `/admin/password`, `/admin/disable` power the admin panel and only work with an admin account's token.
- `/p/<token>/<address>` fetches the address, removes the headers that block iframes, and rewrites the page's links so they go through the proxy too.

## How to run it

**Online:** GitHub Pages publishes the site automatically every time you push (see `.github/workflows/static.yml`). The proxy is published separately:

```
cd proxy
npm install
npx wrangler login                    # once
npx wrangler secret put SECRET        # any long random string
npx wrangler deploy
```

Make accounts (there is no sign-up page, so only people you add can log in):

```
npm run user -- add debug --admin     # admin account (gets the admin panel)
npm run user -- add friend            # normal account
npm run user -- list
npm run user -- remove friend         # also logs them out
```

Then put the Worker's address in the `PROXY` line near the top of the script in `index.html`.

**On your computer:** run the proxy with `cd proxy`, then `npm run dev`. Make test accounts with `npm run user -- add <name> --local`. Then double-click `index.html`. When it's opened from your computer, it automatically uses the local proxy.

## Limits

The proxy only rewrites links written in the page's HTML (plus links clicked later). Big sites such as YouTube, Google, and Discord build the page with lots of JavaScript and need logins/cookies, so they often break. Simple sites like Wikipedia, news sites, and docs work well.

## Things I learned

- **Why some sites show up blank:** Big sites like Google and YouTube send a header (`X-Frame-Options`, or `frame-ancestors` in `Content-Security-Policy`) that says "don't put me inside an iframe." It protects against *clickjacking*, where an attacker hides a real site under fake buttons. A web page can't turn that off, but a server in the middle (a *proxy*) can remove the header before the browser sees it.
- **Why the browser keeps its own history list:** The browser won't let my page read another website's history (the *same-origin policy*), so I save every page I visit in an array. The proxy adds a small script to each page that uses `postMessage` to tell my page which address it's on.
- **Why the login moved to the server:** A password checked in the browser can be read with F12. Now the proxy checks it and hands back a token signed with HMAC-SHA256, so nobody can fake one without knowing the secret.
- **Why passwords are hashed:** Accounts store a *salted PBKDF2 hash*, not the password. Even if someone saw the database, they would have to guess each password, and each guess takes 100,000 rounds of hashing.
