# EPUB Server

A single-file, dependency-free Python script that serves an `.epub` file as a
local website, so you can read it in any browser. It can also host PDFs: a
single `.pdf`, or a whole folder of them.

## Features

- **PDF hosting** — point it at a `.pdf` for an in-browser viewer page, or at a
  folder of PDFs (searched recursively) for a library page listing every file
  with its size, a viewer, and a download link. PDFs are streamed straight from
  disk with HTTP Range support, so large files open quickly and the browser
  can jump to any page without downloading the whole thing first. The folder is
  rescanned on every page load, so PDFs you add while the server is running
  appear on reload. See [Hosting PDFs](#hosting-pdfs).

- **Zero dependencies** — standard library only, works anywhere Python 3
  runs, including Termux on Android.
- **No unzip step** — reads straight from the `.epub` zip, or from a folder
  you've already extracted.
- **Correct Unicode, always** — accented characters, CJK, emoji, and curly
  quotes decode correctly no matter what encoding the original files
  declared, including CSS `@charset` and legacy non-UTF-8 encodings.
- **Finds the book even if `container.xml` is wrong** — if `META-INF/container.xml` is missing, broken, or points at a file that doesn't exist, it searches for an `.opf` package file itself (shallowest first, with a warning); if there is none, it serves every `.html`, `.htm` and `.xhtml` file it finds, sorted by name (numbers in order, so `page2` comes before `page10`), with the file or folder name as the title and a contents list built from each page's own title. Only if there are no such pages either does it report that this is not a valid EPUB.
- **Handles messy real-world zips** — percent-encoded filenames, filenames
  with a different Unicode normalization than the metadata expects (NFC vs
  NFD, common from macOS), and legacy CP437-mangled filenames.
- **Renders XHTML the way the author intended** — well-formed chapters are
  served as real XHTML (`application/xhtml+xml`), not forced through the
  browser's HTML parser. That matters because HTML parsing treats a
  self-closing tag like `<a id="page_12"/>` as an *open* tag, which turns the
  rest of the chapter into one giant link. Named entities (`&nbsp;`,
  `&mdash;`, ...) work under any doctype. Sloppy, non-well-formed chapters
  automatically fall back to the forgiving HTML parser instead of showing an
  XML error page.
- **Root-absolute links work** — references like `href="/styles/main.css"`
  or `src="/OEBPS/images/a.png"` are resolved against the book (the epub root
  first, then the package folder) instead of 404ing.
- **Won't be fooled by embedded examples** — a literal `<body>`, `<title>`,
  or `<h1>` shown as example markup inside a comment, CDATA section, or a
  `<script>`/`<style>` block (common in programming and web-dev books) is
  correctly skipped over when finding the chapter's real tag.
- **Real table of contents** — parses an EPUB3 `nav.xhtml` or EPUB2
  `toc.ncx` into a proper nested list, with a sensible fallback if neither
  is present or parseable.
- **Cover image** shown on the index page, from either EPUB3 or EPUB2
  metadata.
- **Multiple authors** and **right-to-left languages** (Arabic, Hebrew,
  etc.) are handled correctly.
- **De-obfuscates embedded fonts** (the standard IDPF and Adobe schemes),
  so books with custom typefaces actually render them.
- **Detects genuine DRM** and reports it clearly instead of crashing or
  serving garbage. This tool never attempts to circumvent real content
  protection.
- **In-page reading nav bar** — contents / prev / next / chapter title /
  position — injected into each chapter.

- **Safe by default with untrusted books** — a book is untrusted input, so
  every response carries a Content-Security-Policy that blocks scripts,
  remote resources, forms and framing, plus `nosniff`, a same-origin-only referrer policy and
  same-origin resource headers. Use `--allow-scripts` / `--allow-remote` only
  for books you trust (each prints a startup warning). See [Security](#security).
- **Fast and cached** — chapters are rendered once and kept in a size-bounded
  cache; responses carry `ETag`s so reloads get `304 Not Modified`. Large
  media is streamed from the zip with HTTP Range support instead of being
  loaded into memory (in-memory files are capped at 32 MB). Chapter titles
  for the fallback contents list (books with no table of contents) are read
  on first use, not at startup; the first visit to the index page reads each
  chapter once, then the titles are remembered.
- **Loud, not silent** — problems such as an unreadable `encryption.xml` or a
  broken table of contents print a warning on stderr instead of being ignored.

- **Compatibility checks, in plain words** — instead of a traceback, you get a
  clear message (and the book still opens where it can) for: a Python older
  than 3.7; a file that isn't a readable zip (with a hint if it is really a
  Kindle/MOBI, CHM, FB2, DjVu or archive file); password-protected or
  unsupported-compression zip entries (shown as `415 Cannot be shown`);
  missing or wrong `mimetype` file; unknown or missing EPUB version;
  fixed-layout books; reading-order items that are images/SVG rather than
  HTML; invalid `--port` values; and listen addresses this machine can't use.
  IPv6 addresses such as `--host ::1` are supported. Non-ASCII titles never
  crash a console that can't display them.

- **Browser heads-up** — if your browser looks too old (older than Chrome/Edge
  84, Firefox 78, Safari/iOS 14, Opera 70, Samsung Internet 14; any Internet
  Explorer or pre-2020 Edge), or isn't one it recognises, the contents page
  shows a yellow note that things may not work but you can keep going.
  PDF pages also warn phones and tablets, which often can't show a PDF inside
  a page, and point to "Open in new tab" / "Download". The warning only
  advises: pages are always served in full. Scripts and tools such as `curl`,
  and requests with no User-Agent, are never warned. The browser is guessed
  from its User-Agent, which can be wrong; the page is marked `Vary:
  User-Agent`, and chapters themselves are never changed.

## Requirements

- Python 3.7 or later.
- Nothing else — no `pip install` needed.

## Usage

```
python epub_server.py path/to/book.epub
```

This starts a local server and opens your browser to it automatically.

### Options

| Option         | Default       | Description                                              |
|----------------|---------------|-----------------------------------------------------------|
| `path`         | *(required)*  | An `.epub` or `.pdf` file, or a folder: either already-extracted epub contents or a folder of PDFs to host |
| `--only-me`    | *(default)*   | Only this device can open it                              |
| `--share`      | off           | Any device on the same Wi-Fi/network can open it (no password: trusted networks only) |
| `--port PORT`  | `8000`        | Port to serve on (1-65535)                                |
| `--host ADDRESS` | `127.0.0.1` | Advanced: the exact address to listen on, instead of `--only-me`/`--share` |
| `--no-browser` | off           | Don't automatically open a browser tab                    |
| `--verbose`    | off           | Log every request (failed requests are always logged)     |
| `--config FILE` | see below    | Read default settings from this file (see [Settings file](#settings-file-run-it-with-no-arguments)) |
| `--no-config`  | off           | Ignore any settings file this time                        |
| `--init-config` |              | Write a commented settings file and exit                  |
| `--allow-scripts` | off        | Let JavaScript inside the book run (blocked by default)   |
| `--allow-remote`  | off        | Let the book load images/styles/etc. from `https://` sites (blocked by default) |

### Settings file (run it with no arguments)

Put your usual choices in a settings file and the script uses them by itself:
`python3 epub_server.py` (or `uv run epub_server.py`) with nothing typed will
open the book you want, shared the way you want.

1. Create a commented starter file:
   ```
   python3 epub_server.py --init-config
   ```
   It is written to `~/.config/epub_server/config.ini` (on Windows,
   `%APPDATA%\epub_server\config.ini`) and never overwrites an existing file.
   Use `--init-config --config my.ini` to write it somewhere else.
2. Edit it. For example:
   ```ini
   [server]
   auto_apply_custom_settings = yes   ; apply this file automatically
   access = share                     ; or: only-me
   port = 9000
   open_browser = no
   path = ~/Books/my-book.epub        ; served when no path is typed
   ```
3. Run `python3 epub_server.py`. It prints `using settings from ... (auto-applied)`.

Every command-line option has a setting:

| Setting | Values | Same as |
|---|---|---|
| `auto_apply_custom_settings` | yes / no (also spelled `auto_apply_settings`) | whether a file found automatically is used at all (see below) |
| `access` | `only-me` or `share` | `--only-me` / `--share` |
| `host` | an address, e.g. `127.0.0.1` | `--host` (use `access` *or* `host`, not both) |
| `port` | 1-65535 | `--port` |
| `open_browser` | yes / no | `--no-browser` when `no` |
| `verbose` | yes / no | `--verbose` |
| `allow_scripts` | yes / no | `--allow-scripts` |
| `allow_remote` | yes / no | `--allow-remote` |
| `path` | a book, PDF or folder | the `path` argument |

`--config`, `--no-config`, `--init-config` and `--help` are about the file
itself, so they have no setting.

**Which file, and when it applies**

- **Automatic file.** Without `--config`, the script looks for `epub_server.ini`
  next to `epub_server.py`, then the per-user file above (the first one that
  exists). It is applied only if it is valid **and** has
  `auto_apply_custom_settings = yes`. If it is missing, it is skipped. If it is
  corrupted (bad value, unknown setting, not text...), it is skipped with a
  one-line `ignoring settings file ...` notice and the server runs on the
  built-in defaults. If it is valid but doesn't ask to be applied, it is left
  alone silently.
- **A file you name.** `--config FILE` is always applied, whether or not it
  has `auto_apply_custom_settings`, and a problem in it is an error, since you
  asked for that file specifically.
- **Never the current folder.** The folder you run from is not searched, so a
  stray file in a downloaded folder can't change how the server behaves.
- `--no-config` ignores every settings file for that run.
- **Order of priority:** command-line options, then the settings file, then the
  built-in defaults. `--share`, `--only-me` or `--host` on the command line
  replaces the file's `access`/`host`; a path typed on the command line
  replaces the file's `path`.
- Setting names ignore case and `-` vs `_`. A command-line flag can switch
  things on but not off, so for one run without a file's `allow_scripts = yes`
  use `--no-config`.
- Turning on `allow_scripts`, `allow_remote` or `access = share` in the file
  prints the same safety warnings as the matching command-line options.
- A relative `path` is relative to the settings file's folder; `~` is your home.

### Examples

Serve a book and open it in your browser:
```
python epub_server.py my-book.epub
```

Use a different port:
```
python epub_server.py my-book.epub --port 9000
```

Run headless (e.g. on a server, or Termux with no browser) and open the
printed URL yourself:
```
python epub_server.py my-book.epub --no-browser
```

Serve a folder you've already extracted an epub into:
```
python epub_server.py ./my-extracted-book/
```

Allow other devices on your network to connect (e.g. read on your phone
while it runs on your laptop) — only do this on networks you trust:
```
python epub_server.py my-book.epub --share
```

When you use `--share` (or `--host 0.0.0.0`), the terminal prints the links to use:
`serving at http://localhost:8000/ on this device` and one
`on your network, open http://192.168.x.x:8000/` line per local address
(`0.0.0.0` itself is not an address you can visit). In Termux, open those
links in the phone's browser, or from another device on the same Wi-Fi.

Stop the server with `Ctrl+C`.

### Hosting PDFs

Serve one PDF:
```
python epub_server.py paper.pdf
```

Serve every PDF under a folder (subfolders included; hidden files and folders
are skipped):
```
python epub_server.py ./my-pdfs/
```

Share a PDF library with other devices on your network (only on networks you
trust — anyone who can reach the port can read every PDF in the folder):
```
python epub_server.py ./my-pdfs/ --share --no-browser
```

How the path is interpreted:

- A file is treated as a PDF if it ends in `.pdf` or starts with the `%PDF-`
  signature, so a PDF without an extension still works.
- Inside a folder, only files ending in `.pdf` are listed (extensionless PDFs
  are only recognised when you pass them as the path itself).
- A folder is treated as an extracted epub if it contains
  `META-INF/container.xml`; otherwise, if it contains any PDFs, it's treated as
  a PDF library.

Pages: `/` is the library (or the viewer, when you pointed at one file),
`/view/<id>` is a viewer, `/pdf/<id>` is the raw PDF shown inline, and
`/dl/<id>` forces a download. The `<id>` is derived from the file's path
inside the library, and only files found by the scan can be requested — a URL
can't be used to reach anything else on disk.

The viewer uses your browser's built-in PDF support. Some mobile browsers
(Android Chrome, for example) don't show PDFs inline; there, use the "Open in
new tab" or "Download" links in the viewer's top bar.

### Troubleshooting

- **A book looks unstyled or has missing images/fonts** — watch the terminal.
  Every failed request is printed (e.g. `404 GET /book/OEBPS/styles/x.css`),
  and names the page that asked for it, e.g.
  `404 GET /book/OEBPS/x.css  (requested by /book/OEBPS/c1.xhtml)`, which
  usually points straight at the broken reference inside the book. Use
  `--verbose` to see every request.
- **"Address already in use"** — another copy (or another program) is on that
  port. Pick a different one with `--port`.

## Security

- Scripts, remote content, `<form>` submission and framing are blocked by the
  CSP unless you opt in with `--allow-scripts` / `--allow-remote`. With
  `--allow-scripts` the other restrictions stay in force.
- When bound to a loopback address (the default), requests whose `Host`
  header isn't `localhost`/`127.0.0.1`/`::1` get `403`, which defeats DNS
  rebinding attacks from web pages in your browser. Binding to `0.0.0.0` or
  another address turns this check off and prints a warning: anyone who can
  reach the port can read the book or PDFs.
- XML with `<!ENTITY>` declarations is refused (entity-expansion bombs);
  parsing of titles/bodies uses linear-time scanners, so hostile files
  can't stall the server; table-of-contents nesting is capped.
- DRM detection can't be sidestepped with alternate Unicode/zip spellings of
  a protected file's name.
- Extracted folders never serve dotfiles or dot-folders (`.git`, `.env`, ...),
  and nothing outside the book's folder is reachable.
- PDF libraries skip symlinks that point outside the folder and anything that
  isn't a regular file; only files found by a scan can be requested.
- Internal errors return a generic `500`; details go to the terminal only.
  Logged paths have control characters neutralised. Idle connections time out.

## Tests

```
python -m unittest discover -s tests -v
```

Standard library only; the suite starts real servers on free local ports.

## How it works

1. Reads the epub's `META-INF/container.xml` to find the OPF package file,
   whatever it's actually named.
2. Parses the OPF for metadata (title, authors, language, identifier), the
   manifest, and the spine (reading order).
3. Looks for a table of contents: an EPUB3 nav document (identified by
   `properties="nav"` in the manifest), then an EPUB2 `toc.ncx`. If
   neither exists, or parsing fails, it falls back to scanning each
   chapter for a `<title>`/`<h1>` — skipping past comments, CDATA
   sections, and script/style blocks so example markup in a technical
   book isn't mistaken for the real heading.
4. Checks for `META-INF/encryption.xml`. Fonts obfuscated with the standard
   IDPF or Adobe schemes are de-obfuscated on the fly and served normally.
   Anything else listed there is treated as genuine DRM: those pages
   return a clear "DRM-protected" message instead of content.
5. Serves each chapter with a small reading nav bar injected right after the
   chapter's real `<body>` tag (again skipping past any comments, CDATA, or
   script/style blocks that might contain tag-looking example text). Named
   HTML entities are first rewritten as numeric references; if the result
   parses as well-formed XHTML it's sent as `application/xhtml+xml`,
   otherwise as `text/html`. The book's CSS, images, and fonts are served as
   their own files so original styling works.

## What it can't do

- **Real DRM** (Adobe ADEPT, Readium LCP, etc.) — affected pages show a
  clear message instead of content. This is by design: the tool does not
  attempt to decrypt or otherwise bypass actual content protection.
- **Fixed-layout / comic-style EPUBs** — these will load, but the injected
  nav bar isn't specially adapted for precisely-positioned fixed-layout
  pages, so it may overlap content on some of them.
- **Mix EPUBs and PDFs in one library** — a run serves either one EPUB or
  PDFs, not both. Folder mode only picks up PDFs.
- **PDF extras** — no text search, thumbnails, or reading-progress tracking;
  the viewer is whatever your browser provides. Password-protected PDFs are
  served as-is, and your browser's viewer will prompt for the password.
- It's read-only — nothing is ever extracted or written to disk; the epub
  (or PDF) is served directly from the file or folder you pointed it at.
