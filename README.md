# EPUB Server

A single-file, dependency-free Python script that serves an `.epub` file as a
local website, so you can read it in any browser.

## Features

- **Zero dependencies** — standard library only, works anywhere Python 3
  runs, including Termux on Android.
- **No unzip step** — reads straight from the `.epub` zip, or from a folder
  you've already extracted.
- **Correct Unicode, always** — accented characters, CJK, emoji, and curly
  quotes decode correctly no matter what encoding the original files
  declared, including CSS `@charset` and legacy non-UTF-8 encodings.
- **Handles messy real-world zips** — percent-encoded filenames, filenames
  with a different Unicode normalization than the metadata expects (NFC vs
  NFD, common from macOS), and legacy CP437-mangled filenames.
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
| `epub`         | *(required)*  | Path to an `.epub` file, or a folder of already-extracted contents |
| `--port PORT`  | `8000`        | Port to serve on                                          |
| `--host HOST`  | `127.0.0.1`   | Host/interface to bind to                                  |
| `--no-browser` | off           | Don't automatically open a browser tab                    |

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
python epub_server.py my-book.epub --host 0.0.0.0
```

Stop the server with `Ctrl+C`.

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
5. Serves each chapter as HTML with a small reading nav bar injected right
   after the chapter's real `<body>` tag (again skipping past any comments,
   CDATA, or script/style blocks that might contain tag-looking example
   text), and serves the book's CSS, images, and fonts as their own files
   so original styling works.

## What it can't do

- **Real DRM** (Adobe ADEPT, Readium LCP, etc.) — affected pages show a
  clear message instead of content. This is by design: the tool does not
  attempt to decrypt or otherwise bypass actual content protection.
- **Fixed-layout / comic-style EPUBs** — these will load, but the injected
  nav bar isn't specially adapted for precisely-positioned fixed-layout
  pages, so it may overlap content on some of them.
- It's read-only — nothing is ever extracted or written to disk; the epub
  is served directly out of the zip (or folder) you pointed it at.
