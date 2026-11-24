#!/usr/bin/env python3
"""Serve an EPUB as a local website so you can read it in a browser.

Stdlib only - no pip installs needed, works anywhere Python does (including
Termux). Reads the epub's own container.xml to find the OPF file, whatever
it's actually named, and always serves text with an explicit UTF-8 charset
so accented characters, curly quotes, CJK, emoji, etc. don't turn into
mojibake, no matter what encoding the original files were authored in.

Aims to support "all kinds" of epub in the wild, not just tidy ones:
  - EPUB2 (toc.ncx) and EPUB3 (nav.xhtml) table of contents, nested, with a
    heuristic per-chapter fallback when neither is present or parseable.
  - Cover image, on the index page, from either EPUB3 or EPUB2 metadata.
  - Multiple authors, right-to-left languages.
  - Percent-encoded / oddly-normalized / legacy-CP437 filenames inside the
    zip, which real-world epubs from a variety of tools do use.
  - Embedded fonts obfuscated with the standard IDPF or Adobe schemes are
    de-obfuscated on the fly, so custom typefaces actually render.
  - Genuine DRM (anything else listed in encryption.xml) is detected and
    reported clearly instead of being served as garbage or crashing - this
    tool does not attempt to circumvent real content-protection schemes.

Works on a raw .epub file, or a folder you already extracted one into.

It can also host PDFs: point it at a single .pdf, or at a folder of PDFs (searched
recursively) and it serves a library page plus an in-browser viewer. PDFs are
streamed straight from disk with HTTP Range support, so big files open quickly
and the browser can jump around in them without downloading everything first.

Usage:
    python epub_server.py book.epub
    python epub_server.py book.epub --port 9000
    python epub_server.py ./already-extracted-folder
    python epub_server.py paper.pdf
    python epub_server.py ./folder-of-pdfs
"""

import sys

if sys.version_info < (3, 7):  # checked before anything newer than 3.6 is imported or used
    sys.exit(
        'error: epub_server.py needs Python 3.7 or newer '
        f'(this is {sys.version_info[0]}.{sys.version_info[1]}). Install a newer Python and run '
        'it with that, e.g. "python3.11 epub_server.py book.epub".'
    )

import argparse
import configparser
import errno
import hashlib
import html
import html.entities as html_entities
import mimetypes
import os
import posixpath
import re
import stat
import tempfile
import threading
import traceback
import unicodedata
import webbrowser
import zipfile
import zlib
import bisect
import socket
from collections import OrderedDict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit
from xml.etree import ElementTree as ET

CONTAINER_NS = {'c': 'urn:oasis:names:tc:opendocument:xmlns:container'}
OPF_NS = {'opf': 'http://www.idpf.org/2007/opf'}
DC_NS = {'dc': 'http://purl.org/dc/elements/1.1/'}

XHTML_NS_URI = 'http://www.w3.org/1999/xhtml'
EPUB_OPS_NS_URI = 'http://www.idpf.org/2007/ops'
NCX_NS_URI = 'http://www.daisy.org/z3986/2005/ncx/'
XML_ENC_NS_URI = 'http://www.w3.org/2001/04/xmlenc#'

TAG_RE = re.compile(r'<[^<>]*>')
XML_DECL_RE = re.compile(r'^\s*<\?xml[^>]*\?>\s*')

# Everything below that looks through a chapter's markup is written to take time proportional
# to the chapter's size, whatever it contains. A pattern like `<!--.*?-->` is not: given a
# file with thousands of unterminated `<!--`, each one rescans the rest of the file, so a
# few hundred KB of hostile markup can freeze the (single-threaded-in-practice) server for
# minutes. So the openers are matched with patterns that cannot run past the next `<` or `>`,
# and the closers are looked for with one forward search that, on failure, ends the work.
_SKIP_START_RE = re.compile(r'<!--|<!\[CDATA\[|<(script|style)\b[^<>]*>', re.IGNORECASE)
_COMMENT_CDATA_START_RE = re.compile(r'<!--|<!\[CDATA\[')
_SKIP_END_RES = {
    '<!--': re.compile(r'-->'),
    '<![cdata[': re.compile(r'\]\]>'),
    'script': re.compile(r'</script\s*>', re.IGNORECASE),
    'style': re.compile(r'</style\s*>', re.IGNORECASE),
}
_OPEN_TAG_RES = {
    name: re.compile(rf'<{name}\b[^<>]*>', re.IGNORECASE) for name in ('title', 'h1', 'body')
}
_CLOSE_TAG_RES = {name: re.compile(rf'</{name}\s*>', re.IGNORECASE) for name in ('title', 'h1')}
# Only the start of a chapter is searched for its title.
TITLE_SCAN_CHARS = 256 * 1024

IDPF_FONT_ALG = 'http://www.idpf.org/2008/embedding'
ADOBE_FONT_ALG = 'http://ns.adobe.com/pdf/enc#RC'
FONT_OBFUSCATION_WINDOWS = {IDPF_FONT_ALG: 1040, ADOBE_FONT_ALG: 1024}
RTL_LANGUAGES = {'ar', 'he', 'fa', 'ur', 'yi', 'ps', 'sd', 'dv', 'ckb', 'syr'}

# Resource handling. Chapters, stylesheets and the book's metadata files are read fully into
# memory (and the cap below stops a hostile or corrupt entry from exhausting it); anything
# bigger than STREAM_THRESHOLD that isn't text - and all audio/video - is streamed in chunks
# instead, with Range support so media can seek.
MAX_INMEMORY_BYTES = 32 * 1024 * 1024
# A table of contents nested deeper than this is cut off there (real ones are 2-4 levels), so
# a hostile one can't exhaust the interpreter's recursion limit while it is parsed and drawn.
MAX_TOC_DEPTH = 32
STREAM_THRESHOLD = 4 * 1024 * 1024
STREAM_CHUNK = 64 * 1024
CHAPTER_CACHE_BYTES = 32 * 1024 * 1024
TEXT_DOC_EXTS = ('.xhtml', '.html', '.htm')
# Bump when the way chapters are processed changes, so browsers drop their cached copies.
ETAG_SALT = 'e2'


def build_csp(allow_scripts=False, allow_remote=False):
    """The Content-Security-Policy sent with every EPUB response.

    A book is untrusted content served from your own machine, so by default it may not run
    scripts and may only load things from the book itself (or inline `data:` URLs): no
    tracking pixels, remote fonts or stylesheets, no forms, no framing by other sites.
    --allow-scripts and --allow-remote relax that for a book you trust."""
    remote = ' https:' if allow_remote else ''
    scripts = ("'self' 'unsafe-inline' 'unsafe-eval'" + remote) if allow_scripts else "'none'"
    return '; '.join(
        [
            f"default-src 'self' data:{remote}",
            f"style-src 'self' 'unsafe-inline'{remote}",
            f'script-src {scripts}',
            "object-src 'self'",
            "base-uri 'self'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        ]
    )


LOOPBACK_NAMES = {'localhost', '127.0.0.1', '::1'}


def allowed_host_names(bind_host):
    """The Host header values to accept when listening on a loopback address, else None.

    A web page can point its own domain name at 127.0.0.1 ("DNS rebinding") and then read
    whatever is served here as if it were its own site. Browsers still send that page's
    domain in the Host header, so refusing anything that isn't a loopback name stops it."""
    if bind_host in LOOPBACK_NAMES or bind_host.startswith('127.'):
        return LOOPBACK_NAMES | {bind_host}
    return None


def host_header_name(value):
    """The host part of a Host header: no port, no brackets, lower case, no trailing dot."""
    value = value.strip().lower()
    if value.startswith('['):
        return value[1 : value.find(']')] if ']' in value else value
    return value.rsplit(':', 1)[0].rstrip('.') if value.count(':') == 1 else value.rstrip('.')


for ext, ctype in [
    ('.woff2', 'font/woff2'),
    ('.woff', 'font/woff'),
    ('.ttf', 'font/ttf'),
    ('.otf', 'font/otf'),
]:
    mimetypes.add_type(ctype, ext)


def warn(message):
    """Report something that went wrong but isn't fatal, instead of hiding it."""
    print(f'warning: {message}', file=sys.stderr)


class ResourceTooLargeError(Exception):
    def __init__(self, name, size, limit):
        super().__init__(f'{name} is {size} bytes, over the {limit}-byte in-memory limit')
        self.name, self.size, self.limit = name, size, limit


class UnsupportedContentError(Exception):
    """An entry this tool can't read (a password-protected zip entry, an unsupported
    compression method), as opposed to one that is missing or DRM-protected."""

    def __init__(self, name, reason):
        super().__init__(f'{name}: {reason}')
        self.name, self.reason = name, reason


def _check_size(name, size):
    if size > MAX_INMEMORY_BYTES:
        raise ResourceTooLargeError(name, size, MAX_INMEMORY_BYTES)


class ZipSource:
    """Reads epub content directly from the .epub zip - no extraction."""

    def __init__(self, path):
        self._zf = zipfile.ZipFile(path)
        self._lock = threading.Lock()
        # Indexes for _find_alt_name, built once so a request for a name that isn't there
        # costs a dictionary lookup rather than a pass over every entry in the book.
        self._by_nfc, self._by_cp437 = {}, {}
        for n in self._zf.namelist():
            self._by_nfc.setdefault(unicodedata.normalize('NFC', n), n)
            try:
                self._by_cp437.setdefault(n.encode('cp437'), n)
            except UnicodeEncodeError:
                pass

    def _resolve(self, name):
        """The ZipInfo for `name`, tolerating odd Unicode normalization / legacy encodings."""
        try:
            return self._zf.getinfo(name)
        except KeyError:
            alt = self._find_alt_name(name)
            if alt is None:
                raise
            return self._zf.getinfo(alt)

    def exists(self, name):
        with self._lock:
            try:
                self._resolve(name)
            except KeyError:
                return False
            return True

    @staticmethod
    def _unsupported(name, exc):
        """The error for an entry the zip library can't open, in plain words."""
        if isinstance(exc, NotImplementedError):
            return UnsupportedContentError(name, f'unsupported zip compression ({exc})')
        return UnsupportedContentError(name, 'password-protected zip entry')

    def read(self, name):
        """The whole entry as bytes (refuses entries bigger than MAX_INMEMORY_BYTES)."""
        with self._lock:
            info = self._resolve(name)
            _check_size(name, info.file_size)
            try:
                return self._zf.read(info)
            except (NotImplementedError, RuntimeError) as exc:  # RuntimeError: encrypted
                raise self._unsupported(name, exc) from exc

    def open(self, name):
        """Open an entry for streaming: (file object, size, validator).

        Nothing is loaded up front, so this is safe for very large entries. The
        validator changes whenever the entry's content does (used for ETags)."""
        with self._lock:
            info = self._resolve(name)
            try:
                f = self._zf.open(info)
            except (NotImplementedError, RuntimeError) as exc:
                raise self._unsupported(name, exc) from exc
        return f, info.file_size, f'{info.CRC:08x}-{info.file_size:x}'

    def canonical(self, name):
        """The name `name` is really stored under (reads tolerate Unicode-normalization and
        legacy-encoding spelling differences), or `name` itself if there is no such entry."""
        with self._lock:
            try:
                return self._resolve(name).filename
            except KeyError:
                return name

    def list_names(self):
        """Every file entry (not folders)."""
        with self._lock:
            return [n for n in self._zf.namelist() if not n.endswith('/')]

    def find_opf_names(self):
        """Every .opf entry, shallowest first (the fallback when container.xml is no help)."""
        with self._lock:
            names = [n for n in self._zf.namelist() if n.lower().endswith('.opf')]
        return sorted(names, key=lambda n: (n.count('/'), n.lower()))

    def _find_alt_name(self, name):
        alt = self._by_nfc.get(unicodedata.normalize('NFC', name))
        if alt is not None:
            return alt
        try:
            return self._by_cp437.get(name.encode('utf-8', 'surrogateescape'))
        except UnicodeEncodeError:
            return None


class DirSource:
    """Reads epub content from an already-extracted folder."""

    def __init__(self, path):
        self._root = Path(path).resolve()

    def _locate(self, name):
        """Find the regular file for `name` inside the root: (path, stat result)."""
        last_exc = None
        for candidate in self._candidates(name):
            # Hidden files and folders (.git, .env, ...) are never part of a book, and
            # '..' starts with a dot too: neither is ever served.
            if any(part.startswith('.') for part in candidate.split('/')):
                continue
            try:
                p = (self._root / candidate).resolve()
                if self._root != p and self._root not in p.parents:
                    continue  # path escaped the root - never follow it
                st = p.stat()
                if stat.S_ISREG(st.st_mode):
                    return p, st
            except (OSError, ValueError) as exc:  # ValueError: e.g. NUL byte in a crafted URL
                last_exc = exc
        raise FileNotFoundError(name) from last_exc

    def exists(self, name):
        try:
            self._locate(name)
        except FileNotFoundError:
            return False
        return True

    def read(self, name):
        """The whole file as bytes (refuses files bigger than MAX_INMEMORY_BYTES)."""
        p, st = self._locate(name)
        _check_size(name, st.st_size)
        try:
            return p.read_bytes()
        except OSError as exc:
            raise FileNotFoundError(name) from exc

    def open(self, name):
        """Open a file for streaming: (file object, size, validator)."""
        p, st = self._locate(name)
        try:
            f = open(p, 'rb')
        except OSError as exc:
            raise FileNotFoundError(name) from exc
        return f, st.st_size, f'{st.st_mtime_ns:x}-{st.st_size:x}'

    def list_names(self, limit=50000):
        """Every regular file inside the folder (hidden folders and files skipped)."""
        names = []
        for dirpath, dirnames, filenames in os.walk(self._root):
            dirnames[:] = [d for d in dirnames if not d.startswith('.')]
            for f in filenames:
                rel = Path(dirpath, f).relative_to(self._root).as_posix()
                if not f.startswith('.') and self.exists(rel):
                    names.append(rel)
            if len(names) > limit:
                break
        return names

    def find_opf_names(self, limit=20000):
        """Every .opf file in the folder (hidden folders skipped), shallowest first."""
        found, seen = [], 0
        for dirpath, dirnames, filenames in os.walk(self._root):
            dirnames[:] = [d for d in dirnames if not d.startswith('.')]
            for f in filenames:
                seen += 1
                if f.lower().endswith('.opf') and not f.startswith('.'):
                    rel = Path(dirpath, f).relative_to(self._root).as_posix()
                    if self.exists(rel):  # regular file inside the root, not a symlink escape
                        found.append(rel)
            if seen > limit:
                break
        return sorted(found, key=lambda n: (n.count('/'), n.lower()))

    @staticmethod
    def canonical(name):
        return name

    @staticmethod
    def _candidates(name):
        seen = set()
        for form in (name, unicodedata.normalize('NFC', name), unicodedata.normalize('NFD', name)):
            if form not in seen:
                seen.add(form)
                yield form


def open_source(path):
    path = Path(path)
    source = DirSource(path) if path.is_dir() else ZipSource(path)
    source.label = (
        path.name if path.is_dir() else path.stem
    )  # used as the title of a book with no OPF
    return source


def sniff_text(raw):
    """Decode text while honoring declared encodings, with safe fallbacks."""
    # The 'utf-16' codec reads the BOM to pick the byte order *and* consumes it; 'utf-16-le'/'-be'
    # would leave a U+FEFF at the start of the text, which stops the leading <?xml ...?>
    # declaration from being recognised and stripped (so the chapter fell back to HTML mode).
    for bom, enc in (
        (b'\xef\xbb\xbf', 'utf-8-sig'),
        (b'\xff\xfe', 'utf-16'),
        (b'\xfe\xff', 'utf-16'),
    ):
        if raw.startswith(bom):
            return raw.decode(enc, errors='replace')
    head = raw[:1024].decode('ascii', errors='ignore')
    m = (
        re.search(r'encoding=["\']([\w-]+)["\']', head, re.IGNORECASE)
        or re.search(r'@charset\s+["\']([\w-]+)["\']', head, re.IGNORECASE)
        or re.search(r'charset=["\']?([\w-]+)', head, re.IGNORECASE)
    )
    for enc in filter(None, [m.group(1) if m else None, 'utf-8']):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode('latin-1')


def resolve_href(href, base_dir):
    href = unquote(href).replace('\\', '/')
    path_part, _, frag = href.partition('#')
    if not path_part:
        return '', frag
    full = posixpath.join(base_dir, path_part) if base_dir else path_part
    return posixpath.normpath(full), frag


def is_rtl_language(lang):
    return bool(lang and lang.split('-')[0].strip().lower() in RTL_LANGUAGES)


def skipped_spans(text, comments_only=False):
    """(start, end) spans of the comments, CDATA sections and - unless `comments_only` -
    <script>/<style> blocks in `text`, in order. Something never closed runs to the end of
    the text, which is how a browser treats it. Time is linear in len(text)."""
    start_re = _COMMENT_CDATA_START_RE if comments_only else _SKIP_START_RE
    spans, pos = [], 0
    while True:
        m = start_re.search(text, pos)
        if m is None:
            return spans
        token = m.group(0)
        if token.startswith('<!--'):
            end_re = _SKIP_END_RES['<!--']
        elif token.startswith('<!['):  # CDATA
            end_re = _SKIP_END_RES['<![cdata[']
        elif token.endswith('/>'):  # <script src="x"/>: nothing between the tags to skip
            spans.append(m.span())
            pos = m.end()
            continue
        else:
            end_re = _SKIP_END_RES[m.group(1).lower()]
        end = end_re.search(text, m.end())
        if end is None:
            spans.append((m.start(), len(text)))
            return spans
        spans.append((m.start(), end.end()))
        pos = end.end()


def _inside(spans, pos):
    i = bisect.bisect_right(spans, (pos, float('inf'))) - 1
    return i >= 0 and pos < spans[i][1]


def first_real_tag(text, name, spans=None):
    """The match for the first opening <name ...> that isn't inside a comment, CDATA section
    or <script>/<style> block - or None."""
    spans = skipped_spans(text) if spans is None else spans
    pos = 0
    while True:
        m = _OPEN_TAG_RES[name].search(text, pos)
        if m is None:
            return None
        if not _inside(spans, m.start()):
            return m
        pos = m.end()


def first_real_element_text(text, name):
    """The markup between the first real <name> and its closing tag, or None."""
    spans = skipped_spans(text)
    m = first_real_tag(text, name, spans)
    if m is None or m.group(0).endswith('/>'):
        return None
    end = _CLOSE_TAG_RES[name].search(text, m.end())
    return text[m.end() : end.start()] if end else None


_ENTITY_DECL_SIGNATURES = tuple(
    '<!ENTITY'.encode(enc) for enc in ('ascii', 'utf-16-le', 'utf-16-be')
)


def _has_entity_declaration(data):
    if isinstance(data, str):
        return '<!ENTITY' in data
    return any(sig in data for sig in _ENTITY_DECL_SIGNATURES)


LOOSE_PAGE_EXTENSIONS = ('.html', '.htm', '.xhtml')


def natural_sort_key(name):
    """Sort by name with numbers in order: page2 before page10, case-insensitive."""
    return [int(t) if t.isdigit() else t for t in re.split(r'(\d+)', name.lower())] + [name]


def parse_xml(data):
    """ET.fromstring for files that come out of an untrusted book.

    Documents that declare their own entities are refused: that is the way to build a
    "billion laughs" file (a few hundred bytes that expand to gigabytes). Current versions
    of expat defend against it too, but this runs on whatever Python the user has. Real
    books don't declare entities - a DOCTYPE that merely points at the XHTML DTD is fine."""
    if _has_entity_declaration(data):
        raise ET.ParseError('entity declarations (<!ENTITY ...>) are not allowed')
    return ET.fromstring(data)


def _find_child(el, name, ns_uri):
    found = el.find(f'{{{ns_uri}}}{name}')
    return found if found is not None else el.find(name)


def _find_children(el, name, ns_uri):
    found = el.findall(f'{{{ns_uri}}}{name}')
    return found if found else el.findall(name)


def _find_descendants(el, name, ns_uri):
    found = el.findall(f'.//{{{ns_uri}}}{name}')
    return found if found else el.findall(f'.//{name}')


def _idpf_font_key(identifier):
    cleaned = ''.join(c for c in identifier if c not in ' \t\r\n')
    return hashlib.sha1(cleaned.encode('utf-8')).digest()


def _adobe_font_key(identifier):
    hex_digits = ''.join(c for c in identifier if c in '0123456789abcdefABCDEF')
    try:
        return bytes.fromhex(hex_digits[:32])
    except ValueError:
        return None


def deobfuscate_font(data, algorithm, identifier):
    window = FONT_OBFUSCATION_WINDOWS.get(algorithm)
    if window is None or not identifier:
        return data
    key = _idpf_font_key(identifier) if algorithm == IDPF_FONT_ALG else _adobe_font_key(identifier)
    if not key:
        return data
    out = bytearray(data)
    for i in range(min(window, len(data))):
        out[i] ^= key[i % len(key)]
    return bytes(out)


@dataclass
class ManifestItem:
    id: str
    href: str
    media_type: str
    properties: frozenset


@dataclass
class TocEntry:
    title: str
    path: str
    fragment: str
    children: list = field(default_factory=list)


class DrmProtectedError(Exception):
    def __init__(self, path, algorithm):
        super().__init__(f'{path} is DRM-protected (algorithm: {algorithm})')
        self.path, self.algorithm = path, algorithm


class Book:
    def __init__(self, source):
        self.source = source
        self.opf_dir, self.opf_path = self._find_opf()
        if self.opf_path is not None:  # a loose folder of pages was never meant to be an EPUB
            self._check_mimetype_entry()
        if self.opf_path is None:
            self._parse_loose_pages()
        else:
            self._parse_opf()
        obfuscated, drm = self._parse_encryption()
        # Keyed by canonical name, so asking for a protected file under a different (but
        # equivalent) Unicode spelling can't slip past the DRM check or skip de-obfuscation.
        self.obfuscated_fonts = {self._key(p): alg for p, alg in obfuscated.items()}
        self.drm_paths = {self._key(p): alg for p, alg in drm.items()}
        self.has_drm = bool(self.drm_paths)
        self.cover = self._resolve_cover()
        self._titles = {}  # chapter path -> title, filled in on demand by title_for()
        try:
            self.toc = self._build_toc()
        except Exception as exc:
            warn(
                f'could not read the table of contents ({type(exc).__name__}: {exc}); '
                'showing a plain chapter list instead'
            )
            self.toc = []

    def _find_opf(self):
        """Where the package (.opf) file is: (its folder, its path).

        container.xml is the proper source. If it is missing, unreadable, or points at a
        file that isn't there, look for an .opf file directly (and say so). If there is
        none at all, this isn't a usable book."""
        problem = None
        try:
            root = parse_xml(self.source.read('META-INF/container.xml'))
        except (KeyError, FileNotFoundError):
            problem = 'META-INF/container.xml is missing'
        except Exception as exc:  # unparseable, too large, entity declarations...
            problem = f'META-INF/container.xml is unusable ({printable(str(exc))})'
        else:
            for rootfile in root.findall('.//c:rootfile', CONTAINER_NS):
                href = rootfile.get('full-path')
                if not href:
                    continue
                full_path, _ = resolve_href(href, '')
                if self.source.exists(full_path):
                    return posixpath.dirname(full_path), full_path
            problem = 'META-INF/container.xml does not point to a package file that exists'
        candidates = self.source.find_opf_names()
        if not candidates:
            self._opf_problem = f'{problem}, and no .opf package file was found'
            return '', None
        full_path = candidates[0]
        warn(f'{problem}; using {full_path} instead')
        return posixpath.dirname(full_path), full_path

    def _check_mimetype_entry(self):
        """Some readers refuse an EPUB whose 'mimetype' entry is missing or wrong; this one
        doesn't, but the book's author would want to know."""
        try:
            declared = self.source.read('mimetype').strip()
        except (KeyError, FileNotFoundError, UnsupportedContentError, ResourceTooLargeError):
            warn("the book has no 'mimetype' file; strict EPUB readers may refuse it")
            return
        if declared != b'application/epub+zip':
            warn(
                "the book's 'mimetype' file does not say application/epub+zip; strict readers may refuse it"
            )

    def _check_package_compatibility(self, root, manifest, spine):
        """Warn about things that are legal but won't look or work as the author intended here."""
        version = (root.get('version') or '').strip()
        if not version:
            warn('the package file declares no EPUB version; assuming it is EPUB 2 or 3')
        elif version.split('.')[0] not in ('2', '3'):
            warn(
                f'EPUB version {version} is not one this tool knows (2.x and 3.x); '
                'some features may not display'
            )
        for meta in root.findall('.//opf:metadata/opf:meta', OPF_NS):
            if (
                meta.get('property') == 'rendition:layout'
                and (meta.text or '').strip() == 'pre-paginated'
            ):
                warn(
                    'this is a fixed-layout book: pages are positioned exactly, so the reading '
                    'bar may overlap content and text may not reflow'
                )
                break
        by_path = {mi.href: mi for mi in manifest.values()}
        odd = [
            p
            for p in spine
            if by_path.get(p)
            and not by_path[p].media_type.startswith(
                ('application/xhtml', 'text/html', 'text/x-oeb1-document', 'application/x-dtbook')
            )
        ]
        if odd:
            warn(
                f'{len(odd)} reading-order item(s) are not HTML pages (images or SVG, for '
                f'example, such as {odd[0]}); they are served as they are, without the reading bar'
            )

    def _parse_loose_pages(self):
        """No package file at all: serve every .html/.htm/.xhtml file, sorted by name.

        There is no metadata, manifest or table of contents, so the title is the file or
        folder name, and the contents page is a flat list of the pages' own titles."""
        pages = sorted(
            (
                n
                for n in self.source.list_names()
                if n.lower().endswith(LOOSE_PAGE_EXTENSIONS) and not n.startswith('META-INF/')
            ),
            key=natural_sort_key,
        )
        if not pages:
            raise ValueError(
                f'{self._opf_problem}, and no .html/.htm/.xhtml pages were found - '
                'not a valid EPUB'
            )
        warn(f'{self._opf_problem}; listing the {len(pages)} HTML page(s) by name instead')
        self.title = getattr(self.source, 'label', '') or 'Untitled'
        self.authors, self.language, self.identifier = [], None, None
        self.manifest, self.spine, self._toc_ref, self._cover_candidate = {}, pages, None, None

    def _parse_opf(self):
        root = parse_xml(self.source.read(self.opf_path))

        def texts(tag):
            return [
                el.text.strip()
                for el in root.findall(f'.//dc:{tag}', DC_NS)
                if el.text and el.text.strip()
            ]

        titles, languages = texts('title'), texts('language')
        unique_ref, identifier = root.get('unique-identifier'), None
        for el in root.findall('.//dc:identifier', DC_NS):
            if el.text and el.text.strip():
                if identifier is None or (unique_ref and el.get('id') == unique_ref):
                    identifier = el.text.strip()
        manifest = {}
        for item in root.findall('.//opf:manifest/opf:item', OPF_NS):
            href, item_id = item.get('href'), item.get('id')
            if href and item_id:
                path, _ = resolve_href(href, self.opf_dir)
                manifest[item_id] = ManifestItem(
                    item_id,
                    path,
                    item.get('media-type', ''),
                    frozenset((item.get('properties') or '').split()),
                )
        spine_el, spine = root.find('.//opf:spine', OPF_NS), []
        if spine_el is not None:
            for itemref in spine_el.findall('opf:itemref', OPF_NS):
                mi = manifest.get(itemref.get('idref'))
                if mi and mi.href:
                    spine.append(mi.href)
        toc_ref = None
        nav_item = next((mi for mi in manifest.values() if 'nav' in mi.properties), None)
        if nav_item:
            toc_ref = ('nav', nav_item.href)
        if toc_ref is None and spine_el is not None:
            ncx_item = manifest.get(spine_el.get('toc', ''))
            if ncx_item:
                toc_ref = ('ncx', ncx_item.href)
        if toc_ref is None:
            ncx_item = next(
                (mi for mi in manifest.values() if mi.media_type == 'application/x-dtbncx+xml'),
                None,
            )
            if ncx_item:
                toc_ref = ('ncx', ncx_item.href)
        cover_item = next((mi for mi in manifest.values() if 'cover-image' in mi.properties), None)
        cover = cover_item.href if cover_item else None
        if cover is None:
            meta_cover = root.find(".//opf:metadata/opf:meta[@name='cover']", OPF_NS)
            if meta_cover is not None:
                mi = manifest.get(meta_cover.get('content', ''))
                if mi:
                    cover = mi.href
        self._check_package_compatibility(root, manifest, spine)
        self.title = titles[0] if titles else 'Untitled'
        self.authors, self.language, self.identifier = (
            texts('creator'),
            (languages[0] if languages else None),
            identifier,
        )
        self.manifest, self.spine, self._toc_ref, self._cover_candidate = (
            manifest,
            spine,
            toc_ref,
            cover,
        )

    def _resolve_cover(self):
        if not self._cover_candidate:
            return None
        if not self.source.exists(self._cover_candidate):
            warn(f'the book declares a cover image that is missing: {self._cover_candidate}')
            return None
        return self._cover_candidate

    def _parse_encryption(self):
        try:
            raw = self.source.read('META-INF/encryption.xml')
        except (KeyError, FileNotFoundError):
            return {}, {}
        try:
            root = parse_xml(raw)
        except ET.ParseError as exc:
            warn(
                f'META-INF/encryption.xml is not valid XML ({exc}); protected content, '
                'if there is any, will not be detected and may show up as garbage'
            )
            return {}, {}
        obfuscated, drm = {}, {}
        for ed in _find_descendants(root, 'EncryptedData', XML_ENC_NS_URI):
            method = _find_child(ed, 'EncryptionMethod', XML_ENC_NS_URI)
            alg = method.get('Algorithm', '') if method is not None else ''
            cipher_data = _find_child(ed, 'CipherData', XML_ENC_NS_URI)
            ref = (
                _find_child(cipher_data, 'CipherReference', XML_ENC_NS_URI)
                if cipher_data is not None
                else None
            )
            if ref is None or not ref.get('URI'):
                continue
            path, _ = resolve_href(ref.get('URI'), '')
            (obfuscated if alg in FONT_OBFUSCATION_WINDOWS else drm)[path] = alg or 'unknown'
        return obfuscated, drm

    def _key(self, path):
        return unicodedata.normalize('NFC', self.source.canonical(path))

    def is_drm(self, path):
        return self._key(path) in self.drm_paths

    def is_obfuscated(self, path):
        return self._key(path) in self.obfuscated_fonts

    def exists(self, path):
        return self.source.exists(path)

    def read_resource(self, path):
        key = self._key(path)
        if key in self.drm_paths:
            raise DrmProtectedError(path, self.drm_paths[key])
        raw = self.source.read(path)
        alg = self.obfuscated_fonts.get(key)
        return deobfuscate_font(raw, alg, self.identifier) if alg else raw

    def open_resource(self, path):
        """Open a resource for streaming: (file object, size, validator).

        Not for obfuscated fonts, which have to be de-obfuscated in memory."""
        key = self._key(path)
        if key in self.drm_paths:
            raise DrmProtectedError(path, self.drm_paths[key])
        return self.source.open(path)

    def _build_toc(self):
        if not self._toc_ref:
            return []
        kind, path = self._toc_ref
        return self._parse_nav_toc(path) if kind == 'nav' else self._parse_ncx_toc(path)

    def _parse_nav_toc(self, nav_path):
        root, base_dir = parse_xml(self.source.read(nav_path)), posixpath.dirname(nav_path)
        toc_nav = None
        navs = _find_descendants(root, 'nav', XHTML_NS_URI)
        for nav in navs:
            t = nav.get(f'{{{EPUB_OPS_NS_URI}}}type', '') or nav.get('type', '')
            if 'toc' in t.split():
                toc_nav = nav
                break
        if toc_nav is None and navs:
            toc_nav = navs[0]  # no epub:type="toc" found - best guess
        ol = _find_child(toc_nav, 'ol', XHTML_NS_URI) if toc_nav is not None else None
        return self._parse_nav_ol(ol, base_dir) if ol is not None else []

    def _warn_toc_truncated(self):
        if not getattr(self, '_toc_truncated_warned', False):
            self._toc_truncated_warned = True
            warn(
                f'table of contents nests deeper than {MAX_TOC_DEPTH} levels; deeper entries dropped'
            )

    def _parse_nav_ol(self, ol, base_dir, depth=0):
        entries = []
        for li in _find_children(ol, 'li', XHTML_NS_URI):
            a = _find_child(li, 'a', XHTML_NS_URI)
            # `a or ...` would be a bug: an Element with no child tags is falsy, so a
            # plain <a>text</a> was skipped.
            label = a if a is not None else _find_child(li, 'span', XHTML_NS_URI)
            title = ' '.join(''.join(label.itertext()).split()) if label is not None else ''
            path = frag = ''
            if (
                a is not None
                and a.get('href')
                and not a.get('href').startswith(('http://', 'https://', 'mailto:'))
            ):
                path, frag = resolve_href(a.get('href'), base_dir)
            child = _find_child(li, 'ol', XHTML_NS_URI)
            if child is not None and depth >= MAX_TOC_DEPTH:
                self._warn_toc_truncated()
            children = (
                self._parse_nav_ol(child, base_dir, depth + 1)
                if child is not None and depth < MAX_TOC_DEPTH
                else []
            )
            if title or children:
                entries.append(TocEntry(title or path or 'Untitled', path, frag, children))
        return entries

    def _parse_ncx_toc(self, ncx_path):
        root, base_dir = parse_xml(self.source.read(ncx_path)), posixpath.dirname(ncx_path)
        navmap = _find_child(root, 'navMap', NCX_NS_URI)
        return self._parse_navpoints(navmap, base_dir) if navmap is not None else []

    def _parse_navpoints(self, parent, base_dir, depth=0):
        entries = []
        for np in _find_children(parent, 'navPoint', NCX_NS_URI):
            label = _find_child(np, 'navLabel', NCX_NS_URI)
            text_el = _find_child(label, 'text', NCX_NS_URI) if label is not None else None
            title = ' '.join((text_el.text or '').split()) if text_el is not None else ''
            content = _find_child(np, 'content', NCX_NS_URI)
            path = frag = ''
            if content is not None and content.get('src'):
                path, frag = resolve_href(content.get('src'), base_dir)
            if depth >= MAX_TOC_DEPTH and _find_children(np, 'navPoint', NCX_NS_URI):
                self._warn_toc_truncated()
            children = (
                self._parse_navpoints(np, base_dir, depth + 1) if depth < MAX_TOC_DEPTH else []
            )
            if title or children:
                entries.append(TocEntry(title or path or 'Untitled', path, frag, children))
        return entries

    def title_for(self, path, text=None):
        """A chapter's title from its <title> or first <h1>, else its file name.

        Looked up on first use and remembered, so starting the server never has to
        read every chapter. Pass `text` if the chapter has already been decoded."""
        cached = self._titles.get(path)
        if cached is not None:
            return cached
        title = posixpath.splitext(posixpath.basename(path))[0]
        if text is None:
            try:
                text = sniff_text(self.read_resource(path))
            except (
                KeyError,
                FileNotFoundError,
                DrmProtectedError,
                ResourceTooLargeError,
                UnsupportedContentError,
                zipfile.BadZipFile,
                zlib.error,
            ):
                text = None
        if text is not None:
            text = text[:TITLE_SCAN_CHARS]
            for name in ('title', 'h1'):  # a blank <title> falls through to the <h1>
                inner = first_real_element_text(text, name)
                clean = html.unescape(TAG_RE.sub('', inner)).strip() if inner is not None else ''
                if clean:
                    title = clean
                    break
        self._titles[path] = title
        return title

    def resolve(self, url_path):
        return posixpath.normpath(unquote(url_path).lstrip('/'))


NAV_CSS = (
    '<style>'
    '#__reader_nav{position:sticky;top:0;background:#222;color:#eee;font-family:sans-serif;'
    'font-size:14px;padding:8px 14px;display:flex;flex-wrap:wrap;gap:8px 16px;'
    'align-items:center;z-index:9999}'
    '#__reader_nav a{color:#9cf;text-decoration:none;white-space:nowrap}'
    '#__reader_nav a:hover{text-decoration:underline}'
    '#__reader_nav .sp{flex:1 1 auto}'
    '#__reader_nav .mid{display:flex;align-items:baseline;gap:8px;min-width:0}'
    '#__reader_nav .ch{max-width:40vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'
    '#__reader_nav .pos{opacity:.7;white-space:nowrap}'
    '</style>'
)
INDEX_CSS = (
    'body{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px}'
    'li{margin:6px 0}'
    'ol ol{margin-top:6px}'
    '.toc-heading{font-weight:bold;color:#444}'
    '.cover{display:block;max-width:220px;max-height:320px;margin:0 auto 20px;'
    'box-shadow:0 2px 10px rgba(0,0,0,.25)}'
    '.byline{color:#555;margin-top:-8px}'
    '.drm-notice{background:#fff3e0;border:1px solid #ffcc80;padding:10px 14px;'
    'border-radius:6px;font-size:14px}'
    '.lock{opacity:.6;font-size:.85em}'
)


def make_link(path, fragment=''):
    url = f'/book/{quote(path)}'
    return url + ('#' + html.escape(fragment, quote=True) if fragment else '')


def make_nav_bar(book, current_path, text=None):
    keys = [book._key(p) for p in book.spine]  # same spelling rules as DRM checks (NFC etc.)
    idx = keys.index(book._key(current_path)) if book._key(current_path) in keys else -1
    prev = f'<a href="{make_link(book.spine[idx-1])}">&#8592; Prev</a>' if idx > 0 else ''
    nxt = (
        f'<a href="{make_link(book.spine[idx+1])}">Next &#8594;</a>'
        if 0 <= idx < len(book.spine) - 1
        else ''
    )
    title = html.escape(book.title_for(current_path, text) if idx >= 0 else '')
    pos = f'{idx+1} / {len(book.spine)}' if idx >= 0 else ''
    middle = (
        f'<span class="mid"><span class="ch" title="{title}">{title}</span>'
        f'<span class="pos">{pos}</span></span>'
        if title or pos
        else ''
    )
    return (
        f'{NAV_CSS}<div id="__reader_nav"><a href="/">&#8962; Contents</a>{prev}'
        f'<span class="sp"></span>{middle}<span class="sp"></span>{nxt}</div>'
    )


def _lock_badge(book, path):
    return ' <span class="lock" title="DRM-protected">🔒</span>' if book.is_drm(path) else ''


def render_toc_entries(entries, book):
    items = []
    for e in entries:
        content = (
            f'<a href="{make_link(e.path, e.fragment)}">{html.escape(e.title)}</a>'
            f'{_lock_badge(book, e.path)}'
            if e.path
            else f'<span class="toc-heading">{html.escape(e.title)}</span>'
        )
        if e.children:
            content += render_toc_entries(e.children, book)
        items.append(f'<li>{content}</li>')
    return f'<ol>{"".join(items)}</ol>' if items else ''


def render_flat_list(book):
    return (
        '<ol>'
        + ''.join(
            f'<li><a href="{make_link(p)}">{html.escape(book.title_for(p))}</a>'
            f'{_lock_badge(book, p)}</li>'
            for p in book.spine
        )
        + '</ol>'
    )


def make_index_html(book, notice=None):
    toc = render_toc_entries(book.toc, book) if book.toc else render_flat_list(book)
    author = (
        f'<p class="byline">by {html.escape(", ".join(book.authors))}</p>' if book.authors else ''
    )
    cover = f'<img class="cover" src="{make_link(book.cover)}" alt="Cover">' if book.cover else ''
    drm = (
        '<p class="drm-notice">🔒 Part of this book is DRM-protected; '
        'those pages can\'t be shown here.</p>'
        if book.has_drm
        else ''
    )
    direction = ' dir="rtl"' if is_rtl_language(book.language) else ''
    title = html.escape(book.title)
    return (
        f'<!DOCTYPE html><html{direction}><head>{HTML_META}'
        f'<title>{title}</title><style>{INDEX_CSS}{COMPAT_CSS}</style></head>'
        f'<body>{compat_banner(notice)}{cover}<h1>{title}</h1>{author}{drm}{toc}</body></html>'
    )


# ---------------------------------------------------------------------------
# Browser compatibility
# ---------------------------------------------------------------------------

# The oldest browser versions the pages here are known to be fine in. The reading bar needs
# flexbox `gap` and `position: sticky`; these are the first releases with both.
MIN_BROWSER_VERSIONS = {
    'Chrome': 84,
    'Edge': 84,
    'Firefox': 78,
    'Safari': 14,
    'Opera': 70,
    'Samsung Internet': 14,
}
MIN_IOS_VERSION = 14

# Programs that fetch pages without being a browser: never shown a browser warning.
_TOOL_AGENT_RE = re.compile(
    r'curl|wget|python|urllib|http[._-]?client|bot\b|spider|crawl|libwww|go-http|okhttp|java/|'
    r'postman|insomnia|httpie',
    re.IGNORECASE,
)
_IOS_RE = re.compile(r'\b(iPhone|iPad|iPod)\b.*?\bOS (\d+)[_.]', re.IGNORECASE)
# (token in the User-Agent, name shown, regex capturing the version), most specific first.
_BROWSER_TOKENS = (
    ('Edg/', 'Edge', r'Edg/(\d+)'),
    ('EdgA/', 'Edge', r'EdgA/(\d+)'),
    ('EdgiOS/', 'Edge', r'EdgiOS/(\d+)'),
    ('OPR/', 'Opera', r'OPR/(\d+)'),
    ('SamsungBrowser/', 'Samsung Internet', r'SamsungBrowser/(\d+)'),
    ('Firefox/', 'Firefox', r'Firefox/(\d+)'),
    ('FxiOS/', 'Firefox', r'FxiOS/(\d+)'),
    ('Chrome/', 'Chrome', r'Chrome/(\d+)'),
    ('CriOS/', 'Chrome', r'CriOS/(\d+)'),
    ('Safari/', 'Safari', r'Version/(\d+)'),
)
# Phones/tablets + smart-TV engines (VIDAA/Hisense "Odin", many other TV browsers)
# that usually ship without a usable native PDF plugin.
_PDF_INLINE_TROUBLE_RE = re.compile(
    r'Android|iPhone|iPad|iPod|Mobile|Silk|Kindle|VIDAA|SmartTV|Hisense|Odin/|Web0S|Tizen|WebOS',
    re.IGNORECASE,
)


def assess_browser(user_agent, for_pdf=False, pdfjs=True):
    """A short heads-up for browsers this reader may not work well in, or None.

    A User-Agent can be wrong or missing, so this only ever *advises*: the page is
    served in full either way. Programs that are not browsers (curl, scripts, crawlers),
    and requests with no User-Agent at all, get no message."""
    ua = (user_agent or '').strip()[:500]
    if not ua or _TOOL_AGENT_RE.search(ua):
        return None
    notes = []
    ios = _IOS_RE.search(ua)
    if 'MSIE ' in ua or 'Trident/' in ua:
        notes.append(
            'Internet Explorer is too old to show this page properly '
            '(a current Edge, Chrome, Firefox or Safari is recommended)'
        )
    elif re.search(r'\bEdge/\d', ua):
        notes.append(
            'This is the old, pre-2020 Microsoft Edge, which is too old for this page '
            '(update Edge, or use Chrome or Firefox)'
        )
    elif ios and int(ios.group(2)) < MIN_IOS_VERSION:
        notes.append(
            f'This iPhone/iPad runs iOS {ios.group(2)}, older than the iOS {MIN_IOS_VERSION} '
            'this page is known to work in'
        )
    else:
        for token, name, version_re in _BROWSER_TOKENS:
            if token in ua:
                found = re.search(version_re, ua)
                version = int(found.group(1)) if found else None
                minimum = MIN_BROWSER_VERSIONS[name]
                if ios and name != 'Safari':
                    break  # on iOS every browser is built on Safari; iOS version decides above
                if version is not None and version < minimum:
                    notes.append(
                        f'Your browser ({name} {version}) is older than {name} {minimum}, '
                        'the oldest this page is known to work in'
                    )
                break
        else:
            notes.append(
                "This browser isn't one this page has been tested with"
                if ua.startswith('Mozilla/')
                else 'This looks like an unusual or text-mode browser'
            )
    if for_pdf and _PDF_INLINE_TROUBLE_RE.search(ua):
        if pdfjs:
            notes.append(
                'phones, tablets and many smart-TV browsers (including VIDAA / Hisense) often '
                'have no native PDF viewer - the page should switch to the PDF.js viewer '
                'automatically; if not, use the "PDF.js viewer" button'
            )
        else:
            notes.append(
                'phones, tablets and smart TVs often cannot show a PDF inside a page - if it '
                'looks wrong, use "Open in new tab" or "Download" (the PDF.js viewer is switched '
                'off on this server)'
            )
    if for_pdf and ('MSIE ' in ua or 'Trident/' in ua):
        notes.append(
            'it has no built-in PDF viewer - try "PDF.js viewer" or "Download"'
            if pdfjs
            else 'it has no built-in PDF viewer, so use "Download"'
        )
    if not notes:
        return None
    text = '; '.join(notes)
    return text[0].upper() + text[1:] + '. Some things may not work, but you can keep going.'


COMPAT_CSS = (
    '.compat{background:#fff4d6;color:#4a3800;border:1px solid #e0b84a;border-radius:6px;'
    'padding:10px 14px;margin:12px 0;font:14px/1.4 sans-serif}'
)


def compat_banner(notice):
    """The heads-up box for `notice` (plain text, or None for no box)."""
    if not notice:
        return ''
    return f'<div class="compat" role="note"><strong>Heads-up:</strong> {html.escape(notice)}</div>'


HTML_META = (
    '<meta charset="utf-8">' '<meta name="viewport" content="width=device-width, initial-scale=1">'
)

DRM_MESSAGE = (
    b'This part of the book is protected by DRM (rights-management encryption). '
    b"This tool doesn't attempt to circumvent real content protection, "
    b"so it can't display it."
)

_XML_ONLY_ENTITIES = {'lt', 'gt', 'amp', 'quot', 'apos'}
_ENTITY_REF_RE = re.compile(r'&([A-Za-z][A-Za-z0-9]*);')


def numeric_entities(text):
    """Rewrite named HTML entities (&nbsp;, &eacute;, &mdash; ...) as numeric
    character references (&#160; ...).

    Named entities are only legal in XML when a DTD defines them, and XML
    parsers (expat, and the browser's) only honour the XHTML set when the
    document carries a matching DOCTYPE - plenty of books use &nbsp; under an
    HTML5 doctype or none at all. Numeric references are valid everywhere.
    Comments and CDATA sections are left alone: there, "&nbsp;" is literal
    text (e.g. a code sample) and must stay exactly as written."""

    def repl(m):
        name = m.group(1)
        if name in _XML_ONLY_ENTITIES:
            return m.group(0)
        codepoint = html_entities.name2codepoint.get(name)
        return f'&#{codepoint};' if codepoint is not None else m.group(0)

    out, pos = [], 0
    for start, end in skipped_spans(text, comments_only=True):
        out.append(_ENTITY_REF_RE.sub(repl, text[pos:start]))
        out.append(text[start:end])
        pos = end
    out.append(_ENTITY_REF_RE.sub(repl, text[pos:]))
    return ''.join(out)


def is_wellformed_xhtml(text):
    """True if `text` parses as XML *and* its root is an XHTML <html>.

    EPUB content documents are XHTML, i.e. XML. Served as text/html a browser
    uses its HTML parser instead, which mishandles perfectly valid XHTML:
    self-closing non-void tags like <a id="page_12"/> or <span/> are treated
    as *open* tags, so everything after them ends up nested inside (an empty
    page-anchor <a/> turns the rest of the chapter into one giant link). Real
    readers parse these as XML. Run numeric_entities() first so named HTML
    entities don't cause a false "not well-formed"."""
    if _has_entity_declaration(text):
        return False
    parser = ET.XMLParser()
    try:
        parser.feed(text.encode('utf-8'))
        root = parser.close()
    except (ET.ParseError, ValueError):
        return False
    return root.tag == f'{{{XHTML_NS_URI}}}html'


def render_chapter(book, epub_path, raw):
    """Prepare an HTML/XHTML chapter for serving: (body bytes, content type)."""
    decoded = sniff_text(raw)
    text, nav = XML_DECL_RE.sub('', decoded), make_nav_bar(book, epub_path, decoded)
    body = first_real_tag(text, 'body')
    text = f'{text[: body.end()]}{nav}{text[body.end() :]}' if body else nav + text
    # Well-formed XHTML is served as XML so the browser parses it the way the author
    # intended; anything sloppy falls back to the forgiving HTML parser rather than
    # showing an XML error page.
    xml_text = numeric_entities(text)
    if is_wellformed_xhtml(xml_text):
        return xml_text.encode(), 'application/xhtml+xml; charset=utf-8'
    return text.encode(), 'text/html; charset=utf-8'


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """Threading server that doesn't print a traceback each time a client hangs up."""

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, TimeoutError)):
            return
        print(f'warning: error while handling a request: {printable(repr(exc))}', file=sys.stderr)


class ByteLRU:
    """A small least-recently-used cache, bounded by the total size of what it holds."""

    def __init__(self, max_bytes):
        self.max_bytes = max_bytes
        self._items = OrderedDict()  # key -> (value, size)
        self._total = 0
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._items.get(key)
            if entry is None:
                return None
            self._items.move_to_end(key)
            return entry[0]

    def put(self, key, value, size):
        if size > self.max_bytes // 4:  # one huge chapter shouldn't flush everything else
            return
        with self._lock:
            old = self._items.pop(key, None)
            if old is not None:
                self._total -= old[1]
            self._items[key] = (value, size)
            self._total += size
            while self._total > self.max_bytes:
                _, (_, evicted_size) = self._items.popitem(last=False)
                self._total -= evicted_size


def etag_matches(header, etag):
    """Whether an If-None-Match header means the client's copy is still current."""
    if not header:
        return False
    if header.strip() == '*':
        return True

    def strip_weak(tag):
        return tag[2:] if tag.startswith('W/') else tag

    return any(strip_weak(tag.strip()) == strip_weak(etag) for tag in header.split(','))


def printable(text, limit=200):
    """`text` made safe to print: control characters (a terminal escape sequence in a
    request path, say) are shown as \\xNN, and it is cut off at `limit` characters."""
    text = '-' if text is None else str(text)  # e.g. no request method when the line was garbage
    shown = ''.join(c if c.isprintable() else f'\\x{ord(c):02x}' for c in text[:limit])
    return shown + ('...' if len(text) > limit else '')


PDFJS_LATEST_VERSION = '6.5.438'
PDFJS_LEGACY_VERSION = '3.11.174'
PDFJS_MODES = ('auto', 'latest', 'legacy', 'off')
_PDFJS_VERSION_RE = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,4}')


class ReaderHandler(BaseHTTPRequestHandler):
    book = None
    verbose = False
    csp = None  # Content-Security-Policy to send with every response, if set
    chapter_cache = None  # ByteLRU of processed chapters, if set
    for_pdf = False  # whether entry pages host PDFs (changes the browser heads-up)
    pdfjs = True  # whether the PDF viewer may fall back to PDF.js (loaded from a CDN)
    pdfjs_mode = 'auto'  # auto / latest / legacy (which PDF.js version(s) to try)
    pdfjs_latest = PDFJS_LATEST_VERSION
    allowed_hosts = None  # accepted Host header names (DNS-rebinding defence), if set
    timeout = 60  # seconds a client may stall on the socket before its connection is dropped
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'same-origin',  # lets failed requests name the page that asked
        # Other sites can't embed this server's files (images, media, ...) into their pages.
        'Cross-Origin-Resource-Policy': 'same-origin',
    }
    _head_only = False

    def log_message(self, fmt, *args):
        pass  # all request logging goes through log_request below

    def log_request(self, code='-', size='-'):
        # Always surface failures (a 404 for a stylesheet or font is the usual
        # reason a book looks wrong); log every request with --verbose.
        try:
            failed = int(code) >= 400
        except (TypeError, ValueError):
            failed = False
        if self.verbose or failed:
            line = f'{code} {printable(self.command)} {printable(getattr(self, "path", None))}'
            source = self._referring_page() if failed else None
            if source:
                line += f'  (requested by {source})'
            print(line, file=sys.stderr)

    def _referring_page(self):
        """The page of ours that asked for this URL, from the Referer header, if any."""
        headers = getattr(self, 'headers', None)  # absent if the request line itself was bad
        referer = headers.get('Referer') if headers else None
        if not referer:
            return None
        parts = urlsplit(referer)
        if parts.netloc.lower() != (headers.get('Host') or '').strip().lower():
            return None  # not one of our own pages: don't repeat what an outside site sent
        return printable(unquote(parts.path), 120) or None

    def end_headers(self):
        # Every response gets these - including the ones the standard library generates for
        # malformed requests - so no code path can forget them.
        for name, value in self.security_headers.items():
            self.send_header(name, value)
        if self.csp:
            self.send_header('Content-Security-Policy', self.csp)
        super().end_headers()

    def _host_allowed(self):
        if self.allowed_hosts is None:
            return True
        value = self.headers.get('Host')
        return value is None or host_header_name(value) in self.allowed_hosts

    def do_GET(self):
        try:
            if not self._host_allowed():
                self._send(403, b'Forbidden: unexpected Host header', 'text/plain; charset=utf-8')
                return
            self._route()
        except (ConnectionError, TimeoutError, socket.timeout):
            # The browser gave up (closed the tab, seeked in a video) or stopped reading.
            self.close_connection = True
        except Exception:
            traceback.print_exc()  # the details stay in this terminal, not in the response
            try:
                self._send(500, b'Internal server error', 'text/plain; charset=utf-8')
            except OSError:
                self.close_connection = True

    def do_HEAD(self):  # same status and headers as GET, no body
        self._head_only = True
        self.do_GET()

    def _route(self):
        path = self.path.split('?', 1)[0]
        if path == '/':
            self._send_entry_page(lambda notice: make_index_html(self.book, notice))
        elif path.startswith('/book/'):
            self._serve_epub_file(self.book.resolve(path[6:]))
        else:
            # Some books reference resources by a root-absolute URL such as href="/styles/main.css"
            # or src="/OEBPS/images/a.png", meaning "from the root of the book". Serve those too,
            # trying the epub root first, then the package folder.
            rel = self.book.resolve(path)
            candidates = [rel] + (
                [posixpath.normpath(posixpath.join(self.book.opf_dir, rel))]
                if self.book.opf_dir
                else []
            )
            # (A DRM-protected file still counts as found: _serve_epub_file explains why it
            # can't be shown.)
            found = next((c for c in candidates if self.book.exists(c)), None)
            if found is None:
                self._send(404, b'Not found', 'text/plain; charset=utf-8')
            else:
                self._serve_epub_file(found)

    def _serve_epub_file(self, epub_path):
        lower = epub_path.lower()
        is_text = lower.endswith(TEXT_DOC_EXTS) or lower.endswith('.css')
        # Text is processed (nav bar, entities, charset), and obfuscated fonts are decoded,
        # so both need the whole file in memory. Everything else - images, audio, video,
        # plain fonts - is opened and, when it's big, streamed.
        buffered = is_text or self.book.is_obfuscated(epub_path)
        try:
            if buffered:
                fetched = self.book.read_resource(epub_path)
            else:
                fetched = self.book.open_resource(epub_path)
        except DrmProtectedError:
            self._send(403, DRM_MESSAGE, 'text/plain; charset=utf-8')
            return
        except (KeyError, FileNotFoundError):
            self._send(404, f'Not found in EPUB: {epub_path}'.encode(), 'text/plain; charset=utf-8')
            return
        except ResourceTooLargeError as exc:
            self._send(413, f'Too large to show: {exc}'.encode(), 'text/plain; charset=utf-8')
            return
        except UnsupportedContentError as exc:
            self._send(415, f'Cannot be shown: {exc}'.encode(), 'text/plain; charset=utf-8')
            return
        if buffered:
            self._send_buffered(epub_path, lower, is_text, fetched)
        else:
            self._send_opened(lower, *fetched)

    def _send_buffered(self, epub_path, lower, is_text, raw):
        digest = hashlib.sha1(raw).hexdigest()[:20]
        etag = f'"{ETAG_SALT}-{digest}"'
        if self._not_modified(etag):
            self._send_not_modified(etag)
            return
        if is_text:
            body, ctype = self._rendered(epub_path, lower, raw, digest)
        else:  # an obfuscated font, already de-obfuscated by the book
            body, ctype = raw, mimetypes.guess_type(lower)[0] or 'application/octet-stream'
        self._send(200, body, ctype, etag=etag)

    def _rendered(self, epub_path, lower, raw, digest):
        """The processed form of a chapter or stylesheet, from the cache when possible."""
        key = (
            epub_path,
            digest,
        )  # keyed on content, so an edited extracted folder never goes stale
        cache = self.chapter_cache
        result = cache.get(key) if cache is not None else None
        if result is None:
            if lower.endswith('.css'):
                result = sniff_text(raw).encode(), 'text/css; charset=utf-8'
            else:
                result = render_chapter(self.book, epub_path, raw)
            if cache is not None:
                cache.put(key, result, len(result[0]))
        return result

    def _send_opened(self, lower, f, size, validator):
        ctype = mimetypes.guess_type(lower)[0] or 'application/octet-stream'
        etag = f'"{validator}"'
        if ctype.startswith(('audio/', 'video/')) or size > STREAM_THRESHOLD:
            self._send_stream(f, size, ctype, etag)
            return
        try:
            if self._not_modified(etag):
                self._send_not_modified(etag)
                return
            body = f.read()
        finally:
            f.close()
        self._send(200, body, ctype, etag=etag)

    def _not_modified(self, etag):
        return etag_matches(self.headers.get('If-None-Match'), etag)

    def _send_common_headers(self, etag=None, extra_headers=None):
        if etag:
            self.send_header('ETag', etag)
            # Browsers may keep a copy but must check back first; the ETag makes that check
            # a cheap 304 instead of a re-download, and edits to a folder show up at once.
            self.send_header('Cache-Control', 'no-cache')
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)

    def _send_entry_page(self, make_html):
        """Send an entry page (contents, PDF library or viewer). It may carry a browser
        heads-up, so it varies with the User-Agent and caches are told so."""
        notice = assess_browser(self.headers.get('User-Agent'), self.for_pdf, self.pdfjs)
        self._send(
            200,
            make_html(notice).encode(),
            'text/html; charset=utf-8',
            extra_headers={'Vary': 'User-Agent', 'Cache-Control': 'no-cache'},
        )

    def _send_not_modified(self, etag):
        self.send_response(304)
        self._send_common_headers(etag)
        self.end_headers()

    def _send(self, status, body, ctype, etag=None, extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self._send_common_headers(etag, extra_headers)
        self.end_headers()
        if not self._head_only:
            self.wfile.write(body)

    def _send_stream(self, f, size, ctype, etag, extra_headers=None):
        """Send an open file in chunks (closing it afterwards).

        Supports Range, so browsers can seek in big PDFs, audio and video without
        downloading the lot, plus If-Range and If-None-Match."""
        with f:
            if self._not_modified(etag):
                self._send_not_modified(etag)
                return
            range_header, if_range = self.headers.get('Range'), self.headers.get('If-Range')
            if range_header and if_range and if_range.strip() != etag:
                range_header = None  # the file changed since the client's copy: send all of it
            byte_range = parse_byte_range(range_header, size)
            if byte_range is False:
                self.send_response(416)
                self.send_header('Content-Range', f'bytes */{size}')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            start, end = byte_range if byte_range else (0, size - 1)
            length = max(end - start + 1, 0)
            self.send_response(206 if byte_range else 200)
            self.send_header('Content-Type', ctype)
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Content-Length', str(length))
            if byte_range:
                self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
            self._send_common_headers(etag, extra_headers)
            self.end_headers()
            if self._head_only:
                return
            f.seek(start)
            remaining = length
            try:
                while remaining > 0:
                    chunk = f.read(min(STREAM_CHUNK, remaining))
                    if not chunk:  # file shrank mid-transfer: drop the connection rather than hang
                        self.close_connection = True
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the browser closed the tab or seeked elsewhere
            except Exception as exc:  # corrupt zip entry, disk error...
                # The headers are already out, so a 500 can't follow: report and drop the connection.
                warn(f'stream failed part-way: {printable(repr(exc))}')
                self.close_connection = True


# ---------------------------------------------------------------------------
# PDF hosting
# ---------------------------------------------------------------------------

PDF_MAGIC = b'%PDF-'
PDF_URL_RE = re.compile(r'/(view|pdf|dl)/([0-9a-f]{12})')

PDF_CSS = (
    'body{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px}'
    'li{margin:8px 0}'
    '.meta{color:#666;font-size:.85em;margin-left:6px}'
    '.dl{font-size:.85em;margin-left:10px}'
    'body.viewer{max-width:none;margin:0;padding:0;height:100vh;'
    'display:flex;flex-direction:column}'
    '#bar{background:#222;color:#eee;font-size:14px;padding:8px 14px;display:flex;'
    'flex-wrap:wrap;gap:8px 16px;align-items:center}'
    '#bar a,#bar button{color:#9cf;text-decoration:none;white-space:nowrap;'
    'background:none;border:0;padding:0;font:inherit;cursor:pointer}'
    '#bar a:hover,#bar button:hover{text-decoration:underline}'
    '#bar .t{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;flex:0 1 auto}'
    '#bar .sp{flex:1 1 auto}'
    'body.viewer .compat{margin:0;border-radius:0;border-width:0 0 1px}'
    'object,#native-wrap{flex:1 1 auto;width:100%;border:0;min-height:0}'
    'object p{padding:16px}'
)

# Only sent with the PDF.js fallback viewer, so a server run with --no-pdfjs has none of it.
PDFJS_CSS = (
    '#pdfjs-wrap{display:none;flex:1 1 auto;flex-direction:column;min-height:0;'
    'background:#525659}'
    '#pdfjs-wrap.active{display:flex}'
    '#pdfjs-toolbar{background:#323639;color:#eee;font-size:13px;padding:6px 12px;'
    'display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center}'
    '#pdfjs-toolbar button{background:#4a4d50;color:#eee;border:0;border-radius:3px;'
    'padding:4px 10px;cursor:pointer;font:inherit}'
    '#pdfjs-toolbar button:hover{background:#5c5f63}'
    '#pdfjs-toolbar button:disabled{opacity:.4;cursor:default}'
    '#pdfjs-toolbar .pg{min-width:4.5em;text-align:center}'
    '#pdfjs-scroll{flex:1 1 auto;overflow:auto;text-align:center;padding:12px}'
    '#pdfjs-scroll canvas{display:block;margin:0 auto 12px;box-shadow:0 2px 8px rgba(0,0,0,.4)}'
    '#pdfjs-status{color:#ccc;padding:24px;font:14px sans-serif}'
    '#pdfjs-status.error{color:#f88}'
)

# Mozilla PDF.js, loaded from a CDN, only when the browser has no PDF viewer of its own (or
# the "PDF.js viewer" button is pressed). The PDF itself is still fetched from this server.
# Two pinned versions: the newest, which is the one that gets security fixes, and an old
# classic-script release (3.11.x) that still runs on very old engines such as smart TVs and
# so serves as the backup if the newest does not load, open or draw the file.

PDFJS_VIEWER_SCRIPT = r'''
(function () {
  var body = document.body;
  var pdfUrl = body.getAttribute('data-pdf-url');
  var mode = body.getAttribute('data-pdfjs-mode') || 'auto';
  var versions = {
    latest: body.getAttribute('data-pdfjs-latest'),
    legacy: body.getAttribute('data-pdfjs-legacy')
  };
  var CDN = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/';
  var SKIP_KEY = 'epub_server_pdfjs_skip_latest';
  var nativeWrap = document.getElementById('native-wrap');
  var pdfjsWrap = document.getElementById('pdfjs-wrap');
  var statusEl = document.getElementById('pdfjs-status');
  var scrollEl = document.getElementById('pdfjs-scroll');
  var pageLabel = document.getElementById('pdfjs-page');
  var verLabel = document.getElementById('pdfjs-ver');
  var btnPrev = document.getElementById('pdfjs-prev');
  var btnNext = document.getElementById('pdfjs-next');
  var btnZoomIn = document.getElementById('pdfjs-zoomin');
  var btnZoomOut = document.getElementById('pdfjs-zoomout');
  var btnNative = document.getElementById('btn-native');
  var btnPdfjs = document.getElementById('btn-pdfjs');
  var pdfDoc = null;
  var started = false;
  var pageNum = 1;
  var scale = 1.1;
  var rendering = false;
  var pending = null;

  function setStatus(msg, isError) {
    statusEl.textContent = msg || '';
    statusEl.className = isError ? 'error' : '';
    statusEl.style.display = msg ? 'block' : 'none';
  }

  function message(err) {
    return err && err.message ? err.message : String(err);
  }

  function updateControls() {
    if (!pdfDoc) return;
    pageLabel.textContent = pageNum + ' / ' + pdfDoc.numPages;
    btnPrev.disabled = pageNum <= 1;
    btnNext.disabled = pageNum >= pdfDoc.numPages;
  }

  function withTimeout(promise, ms, what) {
    return new Promise(function (resolve, reject) {
      var timer = setTimeout(function () { reject(new Error(what + ' took too long')); }, ms);
      promise.then(
        function (value) { clearTimeout(timer); resolve(value); },
        function (err) { clearTimeout(timer); reject(err); }
      );
    });
  }

  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = src;
      s.onload = resolve;
      s.onerror = function () { reject(new Error('could not load ' + src)); };
      document.head.appendChild(s);
    });
  }

  // The newest PDF.js is an ES module; the old 3.x release is a classic script that works
  // on much older engines (smart TVs). import() is called through Function so that a browser
  // too old to parse it fails here, where it is caught, instead of breaking this whole script.
  function loadEngine(name) {
    var v = versions[name];
    if (name === 'latest') {
      var load;
      try { load = new Function('u', 'return import(u)'); } catch (e) {
        return Promise.reject(new Error('this browser cannot load modern scripts'));
      }
      return withTimeout(load(CDN + v + '/pdf.min.mjs'), 20000, 'loading PDF.js ' + v)
        .then(function (lib) {
          lib.GlobalWorkerOptions.workerSrc = CDN + v + '/pdf.worker.min.mjs';
          return lib;
        });
    }
    return withTimeout(loadScript(CDN + v + '/pdf.min.js'), 20000, 'loading PDF.js ' + v)
      .then(function () {
        if (!window.pdfjsLib) throw new Error('PDF.js loaded but pdfjsLib is missing');
        window.pdfjsLib.GlobalWorkerOptions.workerSrc = CDN + v + '/pdf.worker.min.js';
        return window.pdfjsLib;
      });
  }

  function openDocument(lib) {
    // isEvalSupported:false is Mozilla's mitigation for CVE-2024-4367 (a crafted PDF font
    // could run script in this page); keep it for every version.
    var task = lib.getDocument({
      url: pdfUrl,
      withCredentials: false,
      isEvalSupported: false,
      enableXfa: false
    });
    return withTimeout(task.promise, 45000, 'opening the PDF');
  }

  // Draws one page into a fresh canvas and swaps it in when it is done.
  function drawPage(pdf, num) {
    return pdf.getPage(num).then(function (page) {
      var viewport = page.getViewport({ scale: scale });
      var canvas = document.createElement('canvas');
      var ctx = canvas.getContext('2d');
      canvas.height = viewport.height;
      canvas.width = viewport.width;
      var task = page.render({ canvasContext: ctx, canvas: canvas, viewport: viewport });
      return task.promise.then(function () {
        scrollEl.innerHTML = '';
        scrollEl.appendChild(canvas);
      });
    });
  }

  function run(num) {
    rendering = true;
    drawPage(pdfDoc, num).then(function () {
      rendering = false;
      if (pending !== null) {
        var p = pending;
        pending = null;
        run(p);
      }
    }).catch(function (err) {
      rendering = false;
      setStatus('Could not render page: ' + message(err), true);
    });
  }

  function queue(num) {
    if (!pdfDoc || num < 1 || num > pdfDoc.numPages) return;
    pageNum = num;
    updateControls();
    if (rendering) {
      pending = num;
    } else {
      run(num);
    }
  }

  // An engine only counts as working once it has loaded, opened the file AND drawn page 1.
  function tryEngine(name) {
    setStatus('Loading PDF.js ' + versions[name] + '…');
    return loadEngine(name).then(function (lib) {
      setStatus('Opening PDF…');
      return openDocument(lib).then(function (pdf) {
        return drawPage(pdf, 1).then(function () {
          pdfDoc = pdf;
          pageNum = 1;
          verLabel.textContent = 'PDF.js ' + versions[name];
          updateControls();
          setStatus('');
        });
      });
    });
  }

  function skipLatest() {
    try { return window.localStorage.getItem(SKIP_KEY) === versions.latest; } catch (e) { return false; }
  }

  function rememberSkip() {
    try { window.localStorage.setItem(SKIP_KEY, versions.latest); } catch (e) {}
  }

  // Problems with the file itself: another PDF.js version would fail the same way.
  function isFileProblem(err) {
    var n = err && err.name;
    return n === 'PasswordException' || n === 'InvalidPDFException' || n === 'MissingPDFException';
  }

  function engineOrder() {
    if (mode === 'latest') return ['latest'];
    if (mode === 'legacy') return ['legacy'];
    return skipLatest() ? ['legacy'] : ['latest', 'legacy'];
  }

  function startViewer() {
    var order = engineOrder();
    (function next(i) {
      tryEngine(order[i]).catch(function (err) {
        var name = order[i];
        if (!isFileProblem(err) && i + 1 < order.length) {
          if (name === 'latest') rememberSkip();
          setStatus('PDF.js ' + versions[name] + ' did not work here (' + message(err) +
                    '); trying PDF.js ' + versions[order[i + 1]] + '…');
          next(i + 1);
          return;
        }
        setStatus(
          'Could not show this PDF with PDF.js ' + versions[name] + ': ' + message(err) +
          (isFileProblem(err)
            ? '. The file may be corrupt or password-protected.'
            : '. If this device has no internet access to cdnjs.cloudflare.com, PDF.js cannot load.'),
          true
        );
      });
    })(0);
  }

  function showPdfJs() {
    nativeWrap.style.display = 'none';
    pdfjsWrap.classList.add('active');
    btnPdfjs.style.display = 'none';
    if (btnNative) btnNative.style.display = '';
    if (!started) { started = true; startViewer(); }
  }

  function showNative() {
    pdfjsWrap.classList.remove('active');
    nativeWrap.style.display = '';
    if (btnNative) btnNative.style.display = 'none';
    btnPdfjs.style.display = '';
  }

  if (btnPdfjs) btnPdfjs.addEventListener('click', showPdfJs);
  if (btnNative) btnNative.addEventListener('click', showNative);
  btnPrev.addEventListener('click', function () { queue(pageNum - 1); });
  btnNext.addEventListener('click', function () { queue(pageNum + 1); });
  btnZoomIn.addEventListener('click', function () {
    scale = Math.min(scale + 0.2, 3);
    queue(pageNum);
  });
  btnZoomOut.addEventListener('click', function () {
    scale = Math.max(scale - 0.2, 0.4);
    queue(pageNum);
  });
  document.addEventListener('keydown', function (e) {
    if (!pdfjsWrap.classList.contains('active')) return;
    if (e.key === 'ArrowLeft' || e.key === 'PageUp') { e.preventDefault(); queue(pageNum - 1); }
    if (e.key === 'ArrowRight' || e.key === 'PageDown') { e.preventDefault(); queue(pageNum + 1); }
  });

  // Switch automatically on engines with no native PDF viewer (VIDAA / many smart-TV
  // Chromium builds, locked-down WebViews). navigator.pdfViewerEnabled is the modern
  // signal; older engines fall back to the plugin list.
  function nativePdfSupported() {
    if (typeof navigator.pdfViewerEnabled === 'boolean') {
      return navigator.pdfViewerEnabled;
    }
    try {
      var plugs = navigator.plugins;
      if (!plugs || !plugs.length) return false;
      for (var i = 0; i < plugs.length; i++) {
        var name = (plugs[i].name || '') + ' ' + (plugs[i].filename || '');
        if (/pdf/i.test(name)) return true;
      }
    } catch (e) {}
    return false;
  }
  if (!nativePdfSupported()) {
    showPdfJs();
  }
})();
'''


def is_pdf_file(path):
    """True for a file that is a PDF by extension or by its magic bytes."""
    path = Path(path)
    if not path.is_file():
        return False
    if path.suffix.lower() == '.pdf':
        return True
    try:
        with open(path, 'rb') as f:
            return f.read(len(PDF_MAGIC)) == PDF_MAGIC
    except OSError:
        return False


@dataclass
class PdfEntry:
    id: str
    path: Path
    name: str  # path relative to the library root, '/'-separated, shown in the list
    title: str
    size: int


class PdfLibrary:
    """A single PDF, or every PDF found (recursively) under a folder.

    The folder is rescanned whenever the list or a viewer page is loaded, so PDFs
    dropped in while the server is running show up on a page reload (the many
    Range requests a PDF viewer makes are answered from the last scan instead).
    Files are addressed by an id derived from their relative path - never by a
    path taken from the URL - so a request can only ever reach a file the scan
    found. A folder's PDFs must really be inside it: a symlink pointing at some
    other part of the disk is skipped, as is anything that isn't a regular file."""

    def __init__(self, path):
        self.root = Path(path).resolve()
        self.single = self.root.is_file()
        self._by_id = {}
        self._scan_lock = threading.Lock()

    def is_inside(self, path):
        """Whether `path`, with symlinks followed, still lies within the served folder."""
        if self.single:
            return Path(path).resolve() == self.root
        try:
            real = Path(path).resolve()
        except (OSError, RuntimeError):  # RuntimeError: a symlink loop on older Pythons
            return False
        return real == self.root or self.root in real.parents

    def find(self, entry_id):
        """The entry with this id: from the last scan, else (a PDF added since) a fresh one."""
        entry = self._by_id.get(entry_id)
        if entry is None:
            with self._scan_lock:  # concurrent misses share one rescan
                entry = self._by_id.get(entry_id)
                if entry is None:
                    self.scan()
                    entry = self._by_id.get(entry_id)
        return entry

    def scan(self):
        if self.single:
            found, base = [self.root], self.root.parent
        else:
            found, base = [], self.root
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = sorted(d for d in dirnames if not d.startswith('.'))
                found.extend(
                    Path(dirpath, f)
                    for f in sorted(filenames)
                    if f.lower().endswith('.pdf') and not f.startswith('.')
                )
            found.sort(key=lambda p: str(p.relative_to(base)).lower())
        entries = []
        for p in found:
            try:
                st = p.stat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or not self.is_inside(p):
                continue
            rel = p.relative_to(base).as_posix()
            entry_id = hashlib.sha1(rel.encode('utf-8', 'surrogateescape')).hexdigest()[:12]
            entries.append(PdfEntry(entry_id, p, rel, p.stem, st.st_size))
        self._by_id = {e.id: e for e in entries}
        return entries


def human_size(n):
    size = float(n)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024 or unit == 'GB':
            return f'{int(size)} {unit}' if unit == 'B' else f'{size:.1f} {unit}'
        size /= 1024


def parse_byte_range(header, size):
    """Interpret a Range header for a file of `size` bytes.

    Returns (start, end) inclusive for a satisfiable single range, None when the
    header should be ignored (absent, malformed, multi-range - the whole file is
    sent instead, which the HTTP spec allows), or False when it can't be satisfied."""
    # At most 18 digits per number (fits any file size that exists); anything longer is
    # treated as malformed. Converting a header's worth of digits would otherwise raise.
    m = re.fullmatch(r'\s*bytes\s*=\s*(\d{0,18})\s*-\s*(\d{0,18})\s*', header or '')
    if not m:
        return None
    first, last = m.groups()
    if not first and not last:
        return None
    if not first:  # suffix range: the last N bytes
        n = int(last)
        if n == 0 or size == 0:
            return False
        return max(size - n, 0), size - 1
    start = int(first)
    if start >= size:
        return False
    end = size - 1 if not last else min(int(last), size - 1)
    return None if end < start else (start, end)


def content_disposition(kind, filename):
    ascii_name = re.sub(r'[^\x20-\x7e]|["\\]', '_', filename)
    encoded = quote(filename, safe='', errors='replace')
    return f'{kind}; filename="{ascii_name}"; filename*=UTF-8\'\'{encoded}'


def make_pdf_library_html(entries, notice=None):
    if entries:
        items = ''.join(
            f'<li><a href="/view/{e.id}">{html.escape(e.name)}</a>'
            f'<span class="meta">{human_size(e.size)}</span>'
            f'<a class="dl" href="/dl/{e.id}">download</a></li>'
            for e in entries
        )
        body = f'<ol>{items}</ol>'
    else:
        body = '<p>No PDF files found.</p>'
    return (
        f'<!DOCTYPE html><html><head>{HTML_META}'
        f'<title>PDF library</title><style>{PDF_CSS}{COMPAT_CSS}</style></head>'
        f'<body>{compat_banner(notice)}<h1>PDF library</h1>{body}</body></html>'
    )


def make_pdf_viewer_html(entry, show_back, notice=None, pdfjs='auto', latest=PDFJS_LATEST_VERSION):
    """The viewer page: the browser's own PDF viewer, with Mozilla's PDF.js as the fallback
    for browsers that have none (many smart TVs and locked-down WebViews).

    `pdfjs` is the mode: 'auto' (newest PDF.js, the old one as backup), 'latest', 'legacy', or
    'off' / False, where nothing is loaded from any other site and no script is included."""
    mode = 'off' if pdfjs is False else ('auto' if pdfjs is True else pdfjs)
    pdfjs = mode != 'off'
    title = html.escape(entry.title)
    back = '<a href="/">&#8962; Library</a>' if show_back else ''
    src, dl = f'/pdf/{entry.id}', f'/dl/{entry.id}'
    pdfjs_buttons = (
        '<button type="button" id="btn-pdfjs">PDF.js viewer</button>'
        '<button type="button" id="btn-native" style="display:none">Native viewer</button>'
        if pdfjs
        else ''
    )
    hint = (
        'or use the <strong>PDF.js viewer</strong> button above '
        '(works even when the native plugin and download UI are disabled).'
        if pdfjs
        else ''
    )
    pdfjs_panel = (
        '<div id="pdfjs-wrap">'
        '<div id="pdfjs-toolbar">'
        '<button type="button" id="pdfjs-prev">&larr; Prev</button>'
        '<span class="pg" id="pdfjs-page">&ndash;</span>'
        '<button type="button" id="pdfjs-next">Next &rarr;</button>'
        '<button type="button" id="pdfjs-zoomout">&minus;</button>'
        '<button type="button" id="pdfjs-zoomin">+</button>'
        '<span class="pg" id="pdfjs-ver"></span>'
        '</div>'
        '<div id="pdfjs-status"></div>'
        '<div id="pdfjs-scroll"></div>'
        '</div>'
        f'<script>{PDFJS_VIEWER_SCRIPT}</script>'
        if pdfjs
        else ''
    )
    data_attr = (
        f' data-pdf-url="{html.escape(src, quote=True)}" data-pdfjs-mode="{html.escape(mode)}"'
        f' data-pdfjs-latest="{html.escape(latest)}" data-pdfjs-legacy="{PDFJS_LEGACY_VERSION}"'
        if pdfjs
        else ''
    )
    return (
        f'<!DOCTYPE html><html><head>{HTML_META}'
        f'<title>{title}</title><style>{PDF_CSS}{PDFJS_CSS if pdfjs else ""}{COMPAT_CSS}</style></head>'
        f'<body class="viewer"{data_attr}>'
        f'{compat_banner(notice)}'
        f'<div id="bar">{back}<span class="t" title="{title}">{title}</span>'
        f'<span class="sp"></span>{pdfjs_buttons}'
        f'<a href="{src}" target="_blank">Open in new tab</a>'
        f'<a href="{dl}">Download</a></div>'
        f'<div id="native-wrap">'
        f'<object data="{src}" type="application/pdf">'
        f"<p>Your browser can't show PDFs inline. "
        f'<a href="{src}">Open it</a> or <a href="{dl}">download it</a>'
        f'{", " + hint if hint else "."}</p>'
        f'</object></div>'
        f'{pdfjs_panel}'
        f'</body></html>'
    )


class PdfHandler(ReaderHandler):
    library = None
    for_pdf = True
    csp = None  # PDFs are shown by the browser's own viewer; a script policy would get in its way
    # No Cross-Origin-Resource-Policy here: some browsers fetch a PDF for their built-in
    # viewer in a way that header can break.
    security_headers = {'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'}

    def _route(self):
        path = unquote(self.path.split('?', 1)[0])
        if path == '/':
            entries = self.library.scan()
            if self.library.single and entries:
                self._send_entry_page(
                    lambda n: make_pdf_viewer_html(entries[0], False, n, *self._pdfjs())
                )
            else:
                self._send_entry_page(lambda n: make_pdf_library_html(entries, n))
            return
        m = PDF_URL_RE.fullmatch(path)
        entry = self.library.find(m.group(2)) if m else None
        if entry is None:
            self._send(404, b'Not found', 'text/plain; charset=utf-8')
        elif m.group(1) == 'view':
            show_back = not self.library.single
            self._send_entry_page(
                lambda n: make_pdf_viewer_html(entry, show_back, n, *self._pdfjs())
            )
        else:
            self._send_pdf(entry, 'attachment' if m.group(1) == 'dl' else 'inline')

    def _pdfjs(self):
        """(mode, newest version) for the viewer page."""
        return (self.pdfjs_mode if self.pdfjs else 'off'), self.pdfjs_latest

    def _send_pdf(self, entry, disposition):
        gone = (b'That PDF is no longer available', 'text/plain; charset=utf-8')
        # Checked again here: the file may have been swapped for a symlink since the scan.
        if not self.library.is_inside(entry.path):
            self._send(404, *gone)
            return
        try:
            f = open(entry.path, 'rb')
        except OSError:
            self._send(404, *gone)
            return
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            f.close()
            self._send(404, *gone)
            return
        self._send_stream(
            f,
            st.st_size,
            'application/pdf',
            f'"{st.st_mtime_ns:x}-{st.st_size:x}"',
            {'Content-Disposition': content_disposition(disposition, entry.path.name)},
        )


def foreign_format(path):
    """The name of a well-known non-EPUB format this file is in, judged by its first bytes."""
    try:
        with open(path, 'rb') as f:
            head = f.read(70)
    except OSError:
        return None
    if head[60:68] in (b'BOOKMOBI', b'TEXtREAd'):
        return 'a Kindle/Mobipocket (MOBI/AZW) book'
    if head.startswith(b'ITSF'):
        return 'a CHM help file'
    if head.startswith(b'AT&TFORM'):
        return 'a DjVu document'
    if head.startswith((b'Rar!', b'7z\xbc\xaf', b'\x1f\x8b')):
        return 'a compressed archive (extract it first, then point this at the folder)'
    if head.lstrip().startswith(b'<?xml') and b'FictionBook' in head:
        return 'an FB2 book'
    return None


def detect_mode(path):
    """'pdf' for a PDF file or a folder of PDFs, otherwise 'epub'."""
    if path.is_file():
        return 'pdf' if is_pdf_file(path) else 'epub'
    if (
        path.is_dir()
        and not (path / 'META-INF' / 'container.xml').is_file()
        and not DirSource(path).find_opf_names()
        and PdfLibrary(path).scan()
    ):
        return 'pdf'
    return 'epub'


def run_server(handler, host, port, no_browser):
    handler.allowed_hosts = allowed_host_names(host)
    if handler.allowed_hosts is None:
        warn(
            f'listening on {host}: anyone who can reach this machine on port {port} '
            'can read everything being served'
        )
    try:
        server_class = QuietThreadingHTTPServer
        if ':' in host:  # an IPv6 address such as ::1
            server_class = type(
                'QuietThreadingHTTPServerV6',
                (QuietThreadingHTTPServer,),
                {'address_family': socket.AF_INET6},
            )
        server = server_class((host, port), handler)
    except socket.gaierror as exc:
        sys.exit(f'error: {host!r} is not an address this machine can listen on ({exc.strerror})')
    except OSError as exc:
        if exc.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            sys.exit(
                f'error: this machine cannot listen on {host} ({exc.strerror or exc}). '
                'Is it an address this machine has (IPv6 may be switched off)? '
                'Try 127.0.0.1, or 0.0.0.0 for every IPv4 interface.'
            )
        sys.exit(
            f'error: could not listen on {host}:{port} ({exc.strerror or exc}). '
            'Is another copy already running? Try a different --port.'
        )
    if host in WILDCARD_HOSTS:
        # 0.0.0.0 / :: only means "every network connection"; it is not an address to visit.
        url = f'http://localhost:{port}/'
        print(f'serving at {url} on this device  (Ctrl+C to stop)')
        addresses = lan_addresses()
        for address in addresses:
            shown = f'[{address}]' if ':' in address else address
            print(f'on your network, open  http://{shown}:{port}/')
        if not addresses:
            print(
                'on your network, open  http://<this device\'s IP address>:' + str(port) + '/  '
                "(couldn't work out the address; see your Wi-Fi settings or run `ip a`)"
            )
    else:
        url = f'http://[{host}]:{port}/' if ':' in host else f'http://{host}:{port}/'
        print(f'serving at {url}  (Ctrl+C to stop)')
    if not no_browser:
        try:
            threading.Timer(0.5, lambda: webbrowser.open(url)).start()
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nstopped')


WILDCARD_HOSTS = ('0.0.0.0', '::', '')


def lan_addresses():
    """This machine's local-network IPv4 addresses (best effort; the router-facing one first).

    Nothing is sent: connecting a UDP socket only asks the OS which interface it would use."""
    found = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(('10.255.255.255', 1))
            found.append(probe.getsockname()[0])
    except OSError:
        pass
    try:
        found.extend(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    result = []
    for address in found:
        if address not in result and not address.startswith(('127.', '0.', '169.254.')):
            result.append(address)
    return result


# ---------------------------------------------------------------------------
# Config file: settings that would otherwise be typed on every run
# ---------------------------------------------------------------------------

CONFIG_FILE_NAME = 'epub_server.ini'

# >>> Where the settings file is looked for when you don't pass --config. Edit this list. <<<
# The first file that exists is used, and --init-config writes to the FIRST entry. A relative
# path means "relative to the folder you run the script from". These are understood:
#   ~               your home folder
#   {script_dir}    the folder this script is in
#   {user_config}   your per-user config folder (~/.config, or %APPDATA% on Windows)
DEFAULT_CONFIG_LOCATIONS = [
    'epub_server.ini',
    '{script_dir}/epub_server.ini',
    '{user_config}/epub_server/config.ini',
]

MAX_CONFIG_BYTES = 64 * 1024

CONFIG_TEMPLATE = """\
# epub_server settings.  Anything you type on the command line wins over this file,
# and anything left out here uses the built-in default.
# Lines starting with # or ; are comments.  Yes/no values: yes, no, true, false, on, off.

[server]

# Apply this file automatically whenever you run the script without --config, e.g. just
#   python3 epub_server.py        (or: uv run epub_server.py)
# With "no" (or this line missing) the file is only used when you pass --config FILE.
auto_apply_custom_settings = yes

# Who can open it:
#   only-me  - only this device (the default)
#   share    - any device on the same Wi-Fi/network (there is no password: trusted networks only)
# access = only-me

# Advanced alternative to "access": the exact network address to listen on
# (127.0.0.1 = this device only, 0.0.0.0 = every network connection).
# Use either "access" or "host", not both.
# host = 127.0.0.1

# Port number, 1-65535.
# port = 8000

# Open a browser tab automatically when the server starts.
# open_browser = yes

# Print every request in the terminal (failed requests are always printed).
# verbose = no

# Let books run their own JavaScript / load things from https:// sites.
# Both are off by default for safety; turn on only for books you trust.
# allow_scripts = no
# allow_remote = no

# PDF pages: browsers that have no PDF viewer of their own (many smart TVs, e.g. VIDAA) use
# PDF.js, loaded from cdnjs.cloudflare.com only when needed.
#   auto   - try the newest PDF.js first and fall back to the old 3.11.174 if it doesn't work
#            on that device (the default)
#   latest - the newest only         legacy - the old 3.11.174 only
#   off    - never load anything from another site (same as "no")
# pdfjs = auto
# Which version "latest" means (default: the one this script was released with).
# pdfjs_latest_version = 6.5.438

# A book, PDF or folder to serve when none is given on the command line, so that
# running the script with no arguments opens the book you want.
# A relative path is relative to this file's folder.  ~ means your home folder.
# path = ~/Books/my-book.epub
"""
CONFIG_KEYS = (
    'auto_apply_custom_settings',
    'access',
    'host',
    'port',
    'open_browser',
    'verbose',
    'allow_scripts',
    'allow_remote',
    'pdfjs',
    'pdfjs_latest_version',
    'path',
)


# Other spellings accepted for a setting name (after lower-casing and '-' -> '_').
CONFIG_ALIASES = {
    'auto_apply_settings': 'auto_apply_custom_settings',
    'auto_apply': 'auto_apply_custom_settings',
}


class ConfigError(ValueError):
    """The config file can't be used; the message says why, in plain words."""


def user_config_dir():
    """Your per-user config folder (it need not exist)."""
    if os.name == 'nt':
        return Path(os.environ.get('APPDATA') or Path.home() / 'AppData' / 'Roaming')
    return Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')


def config_candidates(locations=None):
    """The places an unnamed settings file is looked for, in order (see DEFAULT_CONFIG_LOCATIONS)."""
    found, seen = [], set()
    for text in DEFAULT_CONFIG_LOCATIONS if locations is None else locations:
        text = str(text).replace('{script_dir}', str(Path(__file__).resolve().parent))
        text = text.replace('{user_config}', str(user_config_dir()))
        try:
            place = Path(text).expanduser()
            key = place.resolve()
        except (OSError, RuntimeError, ValueError):
            continue
        if key not in seen:
            seen.add(key)
            found.append(place)
    return found


def find_config_file():
    """The config file to use when none was named: the first of `config_candidates` that exists."""
    for candidate in config_candidates():
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def read_config(path):
    """Read and check a config file; returns only the settings it actually sets."""
    path = Path(path)
    try:
        with open(path, 'rb') as f:
            raw = f.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError(f'cannot be read ({exc.strerror or exc})') from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f'is too big to be a settings file (over {MAX_CONFIG_BYTES // 1024} KB)')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise ConfigError('is not UTF-8 text') from None
    parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=('#',))
    parser.optionxform = lambda key: CONFIG_ALIASES.get(
        key.strip().lower().replace('-', '_'), key.strip().lower().replace('-', '_')
    )
    try:
        parser.read_string(text, source=path.name)
    except configparser.MissingSectionHeaderError:
        raise ConfigError('must start with a [server] line before the settings') from None
    except configparser.Error as exc:
        raise ConfigError(f'is not valid settings text ({" ".join(str(exc).split())})') from None
    unknown_sections = [name for name in parser.sections() if name.lower() != 'server']
    if unknown_sections:
        raise ConfigError(f'has an unknown section [{unknown_sections[0]}]; only [server] is used')
    names = [name for name in parser.sections() if name.lower() == 'server']
    if not names:
        return {}
    section = parser[names[0]]
    for key in section:
        if key not in CONFIG_KEYS:
            raise ConfigError(f'has an unknown setting "{key}" (valid: {", ".join(CONFIG_KEYS)})')
    settings = {}
    for key in (
        'auto_apply_custom_settings',
        'open_browser',
        'verbose',
        'allow_scripts',
        'allow_remote',
    ):
        if key in section:
            try:
                settings[key] = section.getboolean(key)
            except ValueError:
                raise ConfigError(f'"{key}" must be yes or no, not "{section[key]}"') from None
    if 'pdfjs' in section:
        settings['pdfjs'] = parse_pdfjs_mode(section['pdfjs'], ConfigError)
    if 'pdfjs_latest_version' in section:
        try:
            settings['pdfjs_latest_version'] = pdfjs_version_text(section['pdfjs_latest_version'])
        except argparse.ArgumentTypeError as exc:
            raise ConfigError(f'"pdfjs_latest_version": {exc}') from None
    if 'port' in section:
        try:
            settings['port'] = port_number(section['port'].strip())
        except argparse.ArgumentTypeError as exc:
            raise ConfigError(f'"port": {exc}') from None
    if 'access' in section:
        access = section['access'].strip().lower().replace('_', '-')
        if access not in ('only-me', 'share'):
            raise ConfigError(f'"access" must be only-me or share, not "{section["access"]}"')
        settings['access'] = access
    if 'host' in section:
        settings['host'] = section['host'].strip()
        if not settings['host']:
            raise ConfigError('"host" is empty')
    if 'access' in settings and 'host' in settings:
        raise ConfigError('sets both "access" and "host"; use one of them')
    if 'path' in section:
        value = section['path'].strip()
        if not value:
            raise ConfigError('"path" is empty')
        settings['path'] = str((path.resolve().parent / Path(value).expanduser()))
    return settings


def write_new_file_atomically(target, text):
    """Create `target` with `text` so that it either exists completely or not at all.

    The text goes to a temporary file in the same folder first, is flushed to disk, and is
    then put in place without overwriting anything. A crash or a full disk part-way can leave
    a stray temporary file, never a half-written settings file. Raises FileExistsError if
    `target` is already there."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(dir=str(target.parent), prefix='.epub_server_', suffix='.tmp')
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(str(temp), str(target))  # fails, atomically, if target exists
        except FileExistsError:
            raise
        except OSError:  # a file system without hard links: check, then rename
            if target.exists():
                raise FileExistsError(str(target)) from None
            os.rename(str(temp), str(target))
    finally:
        try:
            temp.unlink()
        except OSError:
            pass


def parse_pdfjs_mode(text, error=ValueError):
    """auto / latest / legacy / off; yes means auto and no means off."""
    word = text.strip().lower()
    word = {'yes': 'auto', 'true': 'auto', 'on': 'auto', '1': 'auto'}.get(word, word)
    word = {'no': 'off', 'false': 'off', '0': 'off'}.get(word, word)
    if word not in PDFJS_MODES:
        raise error(
            f'"pdfjs" must be auto, latest, legacy or off (yes and no also work), not "{text.strip()}"'
        )
    return word


def pdfjs_version_text(text):
    """argparse type: a PDF.js version number such as 6.5.438 (it ends up in a URL)."""
    value = text.strip()
    if not _PDFJS_VERSION_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(f'{value!r} is not a version number like 6.5.438')
    return value


def init_config(target):
    """Write the commented template to `target`. Returns 0, or an error message to exit with."""
    try:
        write_new_file_atomically(target, CONFIG_TEMPLATE)
    except FileExistsError:
        return f'error: {target} already exists; edit it, or remove it first to start over'
    except OSError as exc:
        return f'error: could not write {target}: {exc.strerror or exc}'
    print(f'wrote {target}\nEdit it to change the defaults; command-line options still win.')
    return 0


def describe_config(path):
    """(is it fine, one line saying what the file is) for `check_config`."""
    if not path.is_file():
        return True, 'not found (that is fine: built-in defaults are used)'
    try:
        found = read_config(path)
    except ConfigError as exc:
        return False, f'CORRUPTED or invalid: it {exc}. It will be skipped.'
    if found.get('auto_apply_custom_settings'):
        return True, f'valid, and applied automatically ({len(found) - 1} setting(s) changed)'
    return (
        True,
        'valid, but auto_apply_custom_settings is not "yes", so it is only used with --config',
    )


def check_config(explicit):
    """Report on the settings file(s) without starting a server; returns the exit status."""
    if explicit is not None:
        ok, message = describe_config(explicit)
        if not explicit.is_file():
            ok, message = False, 'not found'
        print(f'{explicit}: {message}')
        return 0 if ok else 1
    status = 0
    for candidate in config_candidates():
        ok, message = describe_config(candidate)
        print(f'{candidate}: {message}')
        status = status or (0 if ok else 1)
    return status


def port_number(text):
    """argparse type: a TCP port, 1-65535."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f'{text!r} is not a number') from None
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError(f'{value} is not a valid port (use 1-65535)')
    return value


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'epub',
        metavar='path',
        nargs='?',
        help='.epub or .pdf file, or a folder: either extracted epub contents or PDFs to host '
        '(may be left out if a config file sets "path")',
    )
    who = parser.add_mutually_exclusive_group()
    who.add_argument(
        '--only-me',
        action='store_true',
        help='only this device can open it (this is the default)',
    )
    who.add_argument(
        '--share',
        action='store_true',
        help='any device on the same Wi-Fi/network can open it (no password: use trusted networks)',
    )
    parser.add_argument(
        '--port',
        type=port_number,
        default=None,
        help='port number to serve on, 1-65535 (default 8000)',
    )
    parser.add_argument(
        '--host',
        default=None,
        metavar='ADDRESS',
        help='advanced: the exact network address to listen on, instead of --only-me/--share '
        '(127.0.0.1 = this device only, 0.0.0.0 = every network connection)',
    )
    parser.add_argument(
        '--no-browser', action='store_true', help="don't try to auto-open a browser tab"
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='log every request (failed requests are always logged)',
    )
    parser.add_argument(
        '--allow-scripts',
        action='store_true',
        help='let EPUBs run their own JavaScript (blocked by default; only for books you trust)',
    )
    parser.add_argument(
        '--pdfjs',
        metavar='MODE',
        type=lambda text: parse_pdfjs_mode(text, argparse.ArgumentTypeError),
        default=None,
        help='PDF.js fallback viewer for browsers with no PDF viewer of their own (many smart TVs; '
        'loaded from cdnjs.cloudflare.com): auto = newest, with the old 3.11.174 as backup '
        '(default); latest = newest only; legacy = old only; off = never load it',
    )
    parser.add_argument(
        '--no-pdfjs',
        action='store_true',
        help='same as --pdfjs off',
    )
    parser.add_argument(
        '--pdfjs-latest-version',
        metavar='X.Y.Z',
        type=pdfjs_version_text,
        default=None,
        help=f'which PDF.js release "latest" means (default {PDFJS_LATEST_VERSION})',
    )
    parser.add_argument(
        '--allow-remote',
        action='store_true',
        help='let EPUBs load images, fonts and styles from https:// sites '
        '(blocked by default, so a book cannot phone home while you read it)',
    )
    configuration = parser.add_argument_group('settings file')
    configuration.add_argument(
        '--config',
        metavar='FILE',
        help='read default settings from this file (otherwise the first file that exists in '
        'DEFAULT_CONFIG_LOCATIONS, a list near the top of this script, is used)',
    )
    configuration.add_argument(
        '--no-config', action='store_true', help='ignore any settings file this time'
    )
    configuration.add_argument(
        '--init-config',
        action='store_true',
        help='write a commented settings file (to --config FILE, or the first entry of '
        'DEFAULT_CONFIG_LOCATIONS) and exit',
    )
    configuration.add_argument(
        '--check-config',
        action='store_true',
        help='report whether the settings file is valid, without starting a server',
    )
    args = parser.parse_args()
    if args.host is not None and (args.share or args.only_me):
        parser.error('--host cannot be combined with --share or --only-me (pick one way to choose)')
    if args.config and args.no_config:
        parser.error('--config cannot be combined with --no-config')
    if args.check_config:
        sys.exit(check_config(Path(args.config) if args.config else None))
    if args.init_config:
        places = config_candidates()
        if not args.config and not places:
            sys.exit(
                'error: DEFAULT_CONFIG_LOCATIONS in this script is empty; name a file with --config'
            )
        sys.exit(init_config(Path(args.config) if args.config else places[0]))
    settings, config_file = {}, None
    if args.config and not args.no_config:
        # A file you named yourself is always applied, and a problem with it is an error.
        config_file = Path(args.config)
        try:
            settings = read_config(config_file)
        except ConfigError as exc:
            sys.exit(f'error: settings file {config_file} {exc}')
        print(f'using settings from {config_file}')
    elif not args.no_config:
        # A file found automatically is applied only if it is valid AND says to apply itself;
        # a missing, unreadable or broken one is simply skipped.
        candidate = find_config_file()
        if candidate is not None:
            try:
                found = read_config(candidate)
            except ConfigError as exc:
                warn(f'ignoring settings file {candidate}: it {exc}')
            else:
                if found.get('auto_apply_custom_settings'):
                    settings, config_file = found, candidate
                    print(f'using settings from {candidate} (auto-applied)')
    if args.share or args.only_me or args.host is not None:
        chosen_host = '0.0.0.0' if args.share else args.host or '127.0.0.1'  # the command line wins
    elif settings.get('access') == 'share':
        chosen_host = '0.0.0.0'
    else:
        chosen_host = settings.get('host') or '127.0.0.1'
    args.host = chosen_host
    args.port = args.port if args.port is not None else settings.get('port', 8000)
    args.no_browser = args.no_browser or not settings.get('open_browser', True)
    for flag in ('verbose', 'allow_scripts', 'allow_remote'):
        setattr(args, flag, getattr(args, flag) or settings.get(flag, False))
    if args.no_pdfjs and args.pdfjs not in (None, 'off'):
        parser.error('--no-pdfjs cannot be combined with --pdfjs ' + args.pdfjs)
    args.pdfjs = 'off' if args.no_pdfjs else args.pdfjs or settings.get('pdfjs', 'auto')
    args.pdfjs_latest_version = (
        args.pdfjs_latest_version or settings.get('pdfjs_latest_version') or PDFJS_LATEST_VERSION
    )
    args.epub = args.epub or settings.get('path')
    if not args.epub:
        parser.error(
            'the following arguments are required: path (or set "path" in a settings file)'
        )
    for stream in (sys.stdout, sys.stderr):
        # A Windows console in a legacy code page would crash on a title with, say, CJK
        # characters; show a replacement mark instead.
        try:
            stream.reconfigure(errors='replace')
        except (AttributeError, ValueError):
            pass
    src_path = Path(args.epub)
    if not src_path.exists():
        sys.exit(f'error: {src_path} not found')
    if detect_mode(src_path) == 'pdf':
        library = PdfLibrary(src_path)
        count = len(library.scan())
        print(f'hosting {count} PDF file{"" if count == 1 else "s"} from {library.root}')
        PdfHandler.library = library
        PdfHandler.verbose = args.verbose
        PdfHandler.pdfjs = args.pdfjs != 'off'
        PdfHandler.pdfjs_mode = args.pdfjs if PdfHandler.pdfjs else 'auto'
        PdfHandler.pdfjs_latest = args.pdfjs_latest_version
        if PdfHandler.pdfjs:
            newest, old = args.pdfjs_latest_version, PDFJS_LEGACY_VERSION
            plan = {
                'auto': f'PDF.js {newest}, with {old} as backup',
                'latest': f'PDF.js {newest} only',
                'legacy': f'PDF.js {old} only',
            }[args.pdfjs]
            print(
                f'PDF.js fallback is on ({plan}): browsers with no PDF viewer of their own '
                '(many smart TVs) load it from cdnjs.cloudflare.com; --pdfjs off turns it off'
            )
        run_server(PdfHandler, args.host, args.port, args.no_browser)
        return
    try:
        book = Book(open_source(src_path))
    except zipfile.BadZipFile as exc:
        other = foreign_format(src_path) if src_path.is_file() else None
        sys.exit(
            f'error: {src_path} is not an EPUB'
            + (
                f': it looks like {other}. Convert it to EPUB first.'
                if other
                else f' - it is not a readable zip file ({exc}). Is the download incomplete?'
            )
        )
    except PermissionError:
        sys.exit(f'error: no permission to read {src_path}')
    except (NotImplementedError, UnsupportedContentError) as exc:
        sys.exit(f'error: this EPUB uses a zip feature that is not supported: {exc}')
    except OSError as exc:
        sys.exit(f'error: could not read {src_path}: {exc.strerror or exc}')
    except Exception as exc:
        sys.exit(f'error: could not parse EPUB structure: {exc}')
    print(f'"{book.title}"' + (f' by {", ".join(book.authors)}' if book.authors else ''))
    print(
        f'{len(book.spine)} chapters, ' + (f'OPF at {book.opf_path}' if book.opf_path else 'no OPF')
    )
    if book.toc:
        print(f'table of contents: {len(book.toc)} top-level entries')
    if book.obfuscated_fonts:
        print(f'{len(book.obfuscated_fonts)} obfuscated font(s) will be de-obfuscated on the fly')
    if book.has_drm:
        warn(f'{len(book.drm_paths)} resource(s) are DRM-protected and will not be viewable')
    ReaderHandler.book = book
    ReaderHandler.verbose = args.verbose
    ReaderHandler.chapter_cache = ByteLRU(CHAPTER_CACHE_BYTES)
    if args.allow_scripts:
        warn('scripts inside the book are allowed to run - only do this for books you trust')
    if args.allow_remote:
        warn('the book may load content from https:// sites - only for books you trust')
    ReaderHandler.csp = build_csp(args.allow_scripts, args.allow_remote)
    run_server(ReaderHandler, args.host, args.port, args.no_browser)


if __name__ == '__main__':
    main()
