# Aiden's Browser

A mini web browser that runs inside a web page. It's built with plain HTML, CSS, and JavaScript, with no libraries.

## Features

- 🔒 Password login screen with a neon glow design
- 🌐 Address bar: type a website (like `wikipedia.org`) or search words (they go to Google)
- ← → ⟳ ⌂ Back, forward, reload, and home buttons, using the browser's own history list
- 🏷️ The tab shows the name of the site you're on
- ↗ An "Open in new tab" button for sites that block being shown inside other pages

## How to run it

**Online:** GitHub Pages publishes the site automatically every time you push (see `.github/workflows/static.yml`).

**On your computer:** double-click `index.html` to open it in your browser.

## Things I learned

- **Why some sites show up blank:** Big sites like Google and YouTube send a header (`X-Frame-Options`) that says "don't put me inside an iframe." It protects against *clickjacking*, where an attacker hides a real site under fake buttons.
- **Why the browser keeps its own history list:** The browser won't let my page read another website's history (the *same-origin policy*), so I save every page I visit in an array.
- **Why the password isn't really secret:** The check runs in the browser, so anyone can read it with F12. A real login needs a server.
