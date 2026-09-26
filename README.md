# EPUB Server

A single-file, dependency-free Python script that serves an `.epub` file as a local website, so you can read it in any browser.

## Features

- **Zero dependencies** — standard library only, works anywhere Python 3 runs, including Termux on Android.
- **No unzip step** — reads straight from the `.epub` zip, or from a folder you've already extracted.
- **Correct Unicode, always** — handles declared encodings, CSS `@charset`, and common fallbacks.
- **Handles messy real-world zips** — percent-encoded filenames, Unicode normalization differences, and legacy CP437-mangled names.
- **Real table of contents** — parses EPUB3 `nav.xhtml` or EPUB2 `toc.ncx`, with a per-chapter fallback.
- **Cover image**, multiple authors, right-to-left languages, and embedded fonts.
- **Detects genuine DRM** and reports it clearly without attempting to bypass content protection.
- **In-page reading nav bar** — contents, previous/next, chapter title, and position.

## Requirements

- Python 3.7 or later.
- Nothing else — no `pip install` needed.

## Usage

```bash
python epub_server.py path/to/book.epub
```

The server starts on port `8000` and opens your browser automatically.

### Options

| Option | Default | Description |
|---|---:|---|
| `epub` | required | EPUB file or extracted EPUB folder |
| `--port PORT` | `8000` | Port to serve on |
| `--host HOST` | `127.0.0.1` | Host/interface to bind to |
| `--no-browser` | off | Don't automatically open a browser tab |

### Examples

```bash
python epub_server.py my-book.epub --port 9000
python epub_server.py my-book.epub --no-browser
python epub_server.py ./my-extracted-book/
python epub_server.py my-book.epub --host 0.0.0.0
```

Stop the server with `Ctrl+C`.

## How it works

The script reads `META-INF/container.xml`, locates and parses the OPF package, builds the reading order and table of contents, then serves resources directly from the EPUB zip or extracted directory. XHTML and CSS are decoded and served with explicit UTF-8 charsets. Standard IDPF and Adobe font obfuscation is reversed on the fly; other encryption is reported as DRM.

## Limitations

- Real DRM such as Adobe ADEPT or Readium LCP is not decrypted.
- Fixed-layout/comic EPUBs load, but the injected navigation bar may overlap precisely positioned content.
- The server is read-only: it does not extract or write EPUB contents to disk.
