# The app's UI: what to know before changing it

The window is a plain web page in Tauri's web view (WebKitGTK on Linux). No
framework, no build step, no bundler: what's in `src/` is what runs.

| File | What it is |
|---|---|
| `src/index.html` | The page: header, pairing panel (QR), phone screen panel with the app grid, files panel, notifications, settings dialog, pairing dialog, drop overlay, toast |
| `src/main.js` | All behaviour (ES module, ~470 lines) |
| `src/styles.css` | All styling, in the design language of [Streamline](https://github.com/whozdgt/streamline): CSS variables on `:root` are the dark **Midnight** theme, and `prefers-color-scheme: light` swaps in **Classic** |
| `src/assets/` | The icon: `olink.svg` (Midnight) and `olink-classic.svg` (Classic); the header's `<picture>` picks one with the theme |
| `src/fonts/` | Optional Inter font (falls back to the system UI font) |

Preview it in any browser without the app: serve `src/` (for example
`python3 -m http.server -d src`) and open `index.html#demo`, which fills the
page with sample data (connected phone, apps, transfers, a notification).
Without `#demo` it shows the "Connect your phone" state.

## Rules the page must keep

- **No inline scripts, no external resources.** The Content-Security-Policy
  (`src-tauri/tauri.conf.json`) allows scripts and styles only from the app
  itself, images from itself and `data:`. So: no `<script>` blocks or
  `onclick=` attributes, no CDNs, no web fonts from the internet, no
  remote images. Inline `style=` attributes are allowed.
- **Phone text is shown as text, never as HTML.** Notification text, app
  names, file names and the phone's name come from the phone (and partly
  from anyone who can message the phone). Use `textContent` / the `el()`
  helper, never `innerHTML`. The only `innerHTML` is the QR SVG, which the
  app generates itself.
- **The page never handles file paths.** "Send files…" and drag and drop
  are done by the app's Rust side; the page only asks for the picker.
- Keep the element ids that `main.js` looks up (or change both together).

## Talking to the app

`window.__TAURI__.core.invoke(name, args)` (wrapped as `invoke()` in
`main.js`) calls these commands:

| Command | Args | Does |
|---|---|---|
| `phone_state` | – | Current state as a list of events (below), on page load |
| `start_cast` | `{ app: null \| "com.package.name" }` | Show the phone screen, or one app |
| `pick_files_to_send` | `{ folders: bool }` | Open the file / folder picker and send what's picked |
| `cancel_transfer` | `{ id }` | Stop a transfer to the phone |
| `open_received_folder` | – | Open `~/Downloads/Olink` |
| `get_settings` / `set_settings` | `{ settings }` | `cast_quality` (`smooth`/`balanced`/`sharp`), `scroll_mode` (`swipe`/`scroll`), `desktop_notifications`, `share_clipboard`, `start_on_login` (booleans) |
| `answer_pairing` | `{ id, allow }` | Answer "Allow this phone to connect?" |
| `ui_log` | `{ msg }` | Write a line to the app's log |

Events arrive on the `"phone"` channel as `{ kind, ... }`:

| `kind` | Fields | Meaning |
|---|---|---|
| `qr` | `svg`, `addr` | Pairing QR code |
| `connected` / `disconnected` | `peer` | Phone connection |
| `battery` | `level`, `charging` | Phone battery |
| `casting` | `on` | Phone screen window open |
| `apps` | `apps: [{pkg, name, icon, recent}]` | Apps that can be shown alone; `icon` is a checked `data:image/…` URL or empty |
| `notification` | `app`, `title`, `text` | A phone notification |
| `transfer` | `id`, `outgoing`, `state`, `files`, `bytes`, `done` | File transfer; `state` is `waiting`, `sending`, `receiving`, `done` or `failed` |
| `pair_request` / `pair_request_done` | `id`, `name`, `model`, `addr` / `id`, `allowed` | Pairing question (answer within 20 s) |
| `error` | `msg` | Something to tell the user |
| `fatal` | `msg` | The phone connection can't run (shown as a banner) |

## Window and sizes

Default 960×640, minimum 720×480. The window only exists while it's open
(closing it ends its process; the app keeps running in the tray), so the
page always starts fresh and rebuilds itself from `phone_state`.
