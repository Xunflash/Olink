# Fonts

The UI is styled for **Inter** (a modern, legible variable sans-serif), with a
`system-ui` fallback so it still looks current if the font file is missing.

To bundle Inter:

1. Download the variable WOFF2 from https://rsms.me/inter/ (SIL Open Font
   License, free to redistribute).
2. Drop the file here as:

   - `Inter-roman.var.woff2`  (required)
   - `Inter-italic.var.woff2` (optional — add an italic `@font-face` if you use it)

The `@font-face` in `../styles.css` already points at `Inter-roman.var.woff2`.

Alternatives, if you prefer: **IBM Plex Sans** (pairs with IBM Plex Mono for the
transfer log) or simply leaning on the `system-ui` stack for a zero-bundle build.
