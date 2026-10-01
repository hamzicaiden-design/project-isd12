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

## Limits

The proxy only rewrites links written in the page's HTML (plus links clicked later). Big sites such as YouTube, Google, and Discord build the page with lots of JavaScript and need logins/cookies, so they often break. Simple sites like Wikipedia, news sites, and docs work well.

