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

import argparse
import hashlib
import html
import html.entities as html_entities
import mimetypes
import os
import posixpath
import re
import sys
import threading
import traceback
import unicodedata
import webbrowser
import zipfile
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote
from xml.etree import ElementTree as ET

CONTAINER_NS = {'c': 'urn:oasis:names:tc:opendocument:xmlns:container'}
OPF_NS = {'opf': 'http://www.idpf.org/2007/opf'}
DC_NS = {'dc': 'http://purl.org/dc/elements/1.1/'}

XHTML_NS_URI = 'http://www.w3.org/1999/xhtml'
EPUB_OPS_NS_URI = 'http://www.idpf.org/2007/ops'
NCX_NS_URI = 'http://www.daisy.org/z3986/2005/ncx/'
XML_ENC_NS_URI = 'http://www.w3.org/2001/04/xmlenc#'

TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
H1_RE = re.compile(r'<h1[^>]*>(.*?)</h1>', re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r'<[^>]+>')
XML_DECL_RE = re.compile(r'^\s*<\?xml[^>]*\?>\s*')
BODY_OPEN_RE = re.compile(r'<body\b[^>]*>', re.IGNORECASE)

SKIP_BLOCK_RE = re.compile(
    r'<!--.*?-->|<!\[CDATA\[.*?\]\]>|<(script|style)\b[^>]*>.*?</\1\s*>',
    re.IGNORECASE | re.DOTALL,
)

IDPF_FONT_ALG = 'http://www.idpf.org/2008/embedding'
ADOBE_FONT_ALG = 'http://ns.adobe.com/pdf/enc#RC'
FONT_OBFUSCATION_WINDOWS = {IDPF_FONT_ALG: 1040, ADOBE_FONT_ALG: 1024}
RTL_LANGUAGES = {'ar', 'he', 'fa', 'ur', 'yi', 'ps', 'sd', 'dv', 'ckb', 'syr'}

for ext, ctype in [('.woff2', 'font/woff2'), ('.woff', 'font/woff'),
                    ('.ttf', 'font/ttf'), ('.otf', 'font/otf')]:
    mimetypes.add_type(ctype, ext)


class ZipSource:
    """Reads epub content directly from the .epub zip - no extraction."""

    def __init__(self, path):
        self._zf = zipfile.ZipFile(path)
        self._lock = threading.Lock()
        self._names = self._zf.namelist()

    def read(self, name):
        with self._lock:
            try:
                return self._zf.read(name)
            except KeyError:
                alt = self._find_alt_name(name)
                if alt is None:
                    raise
                return self._zf.read(alt)

    def _find_alt_name(self, name):
        target_nfc = unicodedata.normalize('NFC', name)
        for n in self._names:
            if unicodedata.normalize('NFC', n) == target_nfc:
                return n
        target_bytes = name.encode('utf-8', 'surrogateescape')
        for n in self._names:
            try:
                if n.encode('cp437') == target_bytes:
                    return n
            except UnicodeEncodeError:
                continue
        return None


class DirSource:
    """Reads epub content from an already-extracted folder."""

    def __init__(self, path):
        self._root = Path(path).resolve()

    def read(self, name):
        last_exc = None
        for candidate in self._candidates(name):
            try:
                p = (self._root / candidate).resolve()
                if self._root != p and self._root not in p.parents:
                    continue  # path escaped the root - never follow it
                return p.read_bytes()
            except (OSError, ValueError) as exc:  # ValueError: e.g. NUL byte in a crafted URL
                last_exc = exc
        raise FileNotFoundError(name) from last_exc

    @staticmethod
    def _candidates(name):
        seen = set()
        for form in (name, unicodedata.normalize('NFC', name),
                     unicodedata.normalize('NFD', name)):
            if form not in seen:
                seen.add(form)
                yield form


def open_source(path):
    path = Path(path)
    return DirSource(path) if path.is_dir() else ZipSource(path)


def sniff_text(raw):
    """Decode text while honoring declared encodings, with safe fallbacks."""
    # The 'utf-16' codec reads the BOM to pick the byte order *and* consumes it; 'utf-16-le'/'-be'
    # would leave a U+FEFF at the start of the text, which stops the leading <?xml ...?>
    # declaration from being recognised and stripped (so the chapter fell back to HTML mode).
    for bom, enc in ((b'\xef\xbb\xbf', 'utf-8-sig'),
                      (b'\xff\xfe', 'utf-16'), (b'\xfe\xff', 'utf-16')):
        if raw.startswith(bom):
            return raw.decode(enc, errors='replace')
    head = raw[:1024].decode('ascii', errors='ignore')
    m = (re.search(r'encoding=["\']([\w-]+)["\']', head, re.IGNORECASE) or
         re.search(r'@charset\s+["\']([\w-]+)["\']', head, re.IGNORECASE) or
         re.search(r'charset=["\']?([\w-]+)', head, re.IGNORECASE))
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


def first_real_match(pattern, text):
    skip_spans = [m.span() for m in SKIP_BLOCK_RE.finditer(text)]
    for m in pattern.finditer(text):
        if not any(start <= m.start() < end for start, end in skip_spans):
            return m
    return None


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
        self._parse_opf()
        self.obfuscated_fonts, self.drm_paths = self._parse_encryption()
        self.has_drm = bool(self.drm_paths)
        self.cover = self._resolve_cover()
        self.titles = self._collect_titles()
        try:
            self.toc = self._build_toc()
        except Exception:
            self.toc = []

    def _find_opf(self):
        root = ET.fromstring(self.source.read('META-INF/container.xml'))
        rootfile = root.find('.//c:rootfile', CONTAINER_NS)
        if rootfile is None:
            raise ValueError('container.xml has no <rootfile> - not a valid EPUB')
        full_path, _ = resolve_href(rootfile.get('full-path'), '')
        return posixpath.dirname(full_path), full_path

    def _parse_opf(self):
        root = ET.fromstring(self.source.read(self.opf_path))
        def texts(tag):
            return [el.text.strip() for el in root.findall(f'.//dc:{tag}', DC_NS)
                    if el.text and el.text.strip()]
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
                manifest[item_id] = ManifestItem(item_id, path, item.get('media-type', ''),
                                                 frozenset((item.get('properties') or '').split()))
        spine_el, spine = root.find('.//opf:spine', OPF_NS), []
        if spine_el is not None:
            for itemref in spine_el.findall('opf:itemref', OPF_NS):
                mi = manifest.get(itemref.get('idref'))
                if mi and mi.href: spine.append(mi.href)
        toc_ref = None
        nav_item = next((mi for mi in manifest.values() if 'nav' in mi.properties), None)
        if nav_item: toc_ref = ('nav', nav_item.href)
        if toc_ref is None and spine_el is not None:
            ncx_item = manifest.get(spine_el.get('toc', ''))
            if ncx_item: toc_ref = ('ncx', ncx_item.href)
        if toc_ref is None:
            ncx_item = next((mi for mi in manifest.values() if mi.media_type == 'application/x-dtbncx+xml'), None)
            if ncx_item: toc_ref = ('ncx', ncx_item.href)
        cover_item = next((mi for mi in manifest.values() if 'cover-image' in mi.properties), None)
        cover = cover_item.href if cover_item else None
        if cover is None:
            meta_cover = root.find(".//opf:metadata/opf:meta[@name='cover']", OPF_NS)
            if meta_cover is not None:
                mi = manifest.get(meta_cover.get('content', ''))
                if mi: cover = mi.href
        self.title = titles[0] if titles else 'Untitled'
        self.authors, self.language, self.identifier = texts('creator'), (languages[0] if languages else None), identifier
        self.manifest, self.spine, self._toc_ref, self._cover_candidate = manifest, spine, toc_ref, cover

    def _resolve_cover(self):
        if not self._cover_candidate: return None
        try: self.source.read(self._cover_candidate)
        except (KeyError, FileNotFoundError): return None
        return self._cover_candidate

    def _parse_encryption(self):
        try: raw = self.source.read('META-INF/encryption.xml')
        except (KeyError, FileNotFoundError): return {}, {}
        try: root = ET.fromstring(raw)
        except ET.ParseError: return {}, {}
        obfuscated, drm = {}, {}
        for ed in _find_descendants(root, 'EncryptedData', XML_ENC_NS_URI):
            method = _find_child(ed, 'EncryptionMethod', XML_ENC_NS_URI)
            alg = method.get('Algorithm', '') if method is not None else ''
            cipher_data = _find_child(ed, 'CipherData', XML_ENC_NS_URI)
            ref = _find_child(cipher_data, 'CipherReference', XML_ENC_NS_URI) if cipher_data is not None else None
            if ref is None or not ref.get('URI'): continue
            path, _ = resolve_href(ref.get('URI'), '')
            (obfuscated if alg in FONT_OBFUSCATION_WINDOWS else drm)[path] = alg or 'unknown'
        return obfuscated, drm

    def is_drm(self, path): return path in self.drm_paths

    def read_resource(self, path):
        if path in self.drm_paths: raise DrmProtectedError(path, self.drm_paths[path])
        raw = self.source.read(path)
        alg = self.obfuscated_fonts.get(path)
        return deobfuscate_font(raw, alg, self.identifier) if alg else raw

    def _build_toc(self):
        if not self._toc_ref: return []
        kind, path = self._toc_ref
        return self._parse_nav_toc(path) if kind == 'nav' else self._parse_ncx_toc(path)

    def _parse_nav_toc(self, nav_path):
        root, base_dir = ET.fromstring(self.source.read(nav_path)), posixpath.dirname(nav_path)
        toc_nav = None
        for nav in _find_descendants(root, 'nav', XHTML_NS_URI):
            t = nav.get(f'{{{EPUB_OPS_NS_URI}}}type', '') or nav.get('type', '')
            if 'toc' in t.split(): toc_nav = nav; break
        navs = _find_descendants(root, 'nav', XHTML_NS_URI)
        if toc_nav is None and navs: toc_nav = navs[0]  # no epub:type="toc" found - best guess
        ol = _find_child(toc_nav, 'ol', XHTML_NS_URI) if toc_nav is not None else None
        return self._parse_nav_ol(ol, base_dir) if ol is not None else []

    def _parse_nav_ol(self, ol, base_dir):
        entries = []
        for li in _find_children(ol, 'li', XHTML_NS_URI):
            a = _find_child(li, 'a', XHTML_NS_URI)
            # `a or ...` would be a bug: an Element with no child tags is falsy, so a plain <a>text</a> was skipped.
            label = a if a is not None else _find_child(li, 'span', XHTML_NS_URI)
            title = ' '.join(''.join(label.itertext()).split()) if label is not None else ''
            path = frag = ''
            if a is not None and a.get('href') and not a.get('href').startswith(('http://', 'https://', 'mailto:')):
                path, frag = resolve_href(a.get('href'), base_dir)
            child = _find_child(li, 'ol', XHTML_NS_URI)
            children = self._parse_nav_ol(child, base_dir) if child is not None else []
            if title or children: entries.append(TocEntry(title or path or 'Untitled', path, frag, children))
        return entries

    def _parse_ncx_toc(self, ncx_path):
        root, base_dir = ET.fromstring(self.source.read(ncx_path)), posixpath.dirname(ncx_path)
        navmap = _find_child(root, 'navMap', NCX_NS_URI)
        return self._parse_navpoints(navmap, base_dir) if navmap is not None else []

    def _parse_navpoints(self, parent, base_dir):
        entries = []
        for np in _find_children(parent, 'navPoint', NCX_NS_URI):
            label = _find_child(np, 'navLabel', NCX_NS_URI)
            text_el = _find_child(label, 'text', NCX_NS_URI) if label is not None else None
            title = ' '.join((text_el.text or '').split()) if text_el is not None else ''
            content = _find_child(np, 'content', NCX_NS_URI)
            path = frag = ''
            if content is not None and content.get('src'): path, frag = resolve_href(content.get('src'), base_dir)
            children = self._parse_navpoints(np, base_dir)
            if title or children: entries.append(TocEntry(title or path or 'Untitled', path, frag, children))
        return entries

    def _collect_titles(self):
        titles = {}
        for path in self.spine:
            fallback = posixpath.splitext(posixpath.basename(path))[0]
            try: text = sniff_text(self.read_resource(path))
            except (KeyError, FileNotFoundError, DrmProtectedError): titles[path] = fallback; continue
            m = first_real_match(TITLE_RE, text) or first_real_match(H1_RE, text)
            titles[path] = html.unescape(TAG_RE.sub('', m.group(1))).strip() if m else fallback
        return titles

    def resolve(self, url_path): return posixpath.normpath(unquote(url_path).lstrip('/'))


NAV_CSS = '<style>#__reader_nav{position:sticky;top:0;background:#222;color:#eee;font-family:sans-serif;font-size:14px;padding:8px 14px;display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;z-index:9999}#__reader_nav a{color:#9cf;text-decoration:none;white-space:nowrap}#__reader_nav a:hover{text-decoration:underline}#__reader_nav .sp{flex:1 1 auto}#__reader_nav .mid{display:flex;align-items:baseline;gap:8px;min-width:0}#__reader_nav .ch{max-width:40vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}#__reader_nav .pos{opacity:.7;white-space:nowrap}</style>'
INDEX_CSS = 'body{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px}li{margin:6px 0}ol ol{margin-top:6px}.toc-heading{font-weight:bold;color:#444}.cover{display:block;max-width:220px;max-height:320px;margin:0 auto 20px;box-shadow:0 2px 10px rgba(0,0,0,.25)}.byline{color:#555;margin-top:-8px}.drm-notice{background:#fff3e0;border:1px solid #ffcc80;padding:10px 14px;border-radius:6px;font-size:14px}.lock{opacity:.6;font-size:.85em}'


def make_link(path, fragment=''):
    url = f'/book/{quote(path)}'
    return url + ('#' + html.escape(fragment, quote=True) if fragment else '')


def make_nav_bar(book, current_path):
    idx = book.spine.index(current_path) if current_path in book.spine else -1
    prev = f'<a href="{make_link(book.spine[idx-1])}">&#8592; Prev</a>' if idx > 0 else ''
    nxt = f'<a href="{make_link(book.spine[idx+1])}">Next &#8594;</a>' if 0 <= idx < len(book.spine)-1 else ''
    title = html.escape(book.titles.get(current_path, ''))
    pos = f'{idx+1} / {len(book.spine)}' if idx >= 0 else ''
    middle = f'<span class="mid"><span class="ch" title="{title}">{title}</span><span class="pos">{pos}</span></span>' if title or pos else ''
    return f'{NAV_CSS}<div id="__reader_nav"><a href="/">&#8962; Contents</a>{prev}<span class="sp"></span>{middle}<span class="sp"></span>{nxt}</div>'


def _lock_badge(book, path): return ' <span class="lock" title="DRM-protected">🔒</span>' if book.is_drm(path) else ''


def render_toc_entries(entries, book):
    items = []
    for e in entries:
        content = (f'<a href="{make_link(e.path, e.fragment)}">{html.escape(e.title)}</a>{_lock_badge(book, e.path)}' if e.path else f'<span class="toc-heading">{html.escape(e.title)}</span>')
        if e.children: content += render_toc_entries(e.children, book)
        items.append(f'<li>{content}</li>')
    return f'<ol>{"".join(items)}</ol>' if items else ''


def render_flat_list(book):
    return '<ol>' + ''.join(f'<li><a href="{make_link(p)}">{html.escape(book.titles.get(p, p))}</a>{_lock_badge(book, p)}</li>' for p in book.spine) + '</ol>'


def make_index_html(book):
    toc = render_toc_entries(book.toc, book) if book.toc else render_flat_list(book)
    author = f'<p class="byline">by {html.escape(", ".join(book.authors))}</p>' if book.authors else ''
    cover = f'<img class="cover" src="{make_link(book.cover)}" alt="Cover">' if book.cover else ''
    drm = '<p class="drm-notice">🔒 Part of this book is DRM-protected; those pages can\'t be shown here.</p>' if book.has_drm else ''
    direction = ' dir="rtl"' if is_rtl_language(book.language) else ''
    return f'<!DOCTYPE html><html{direction}><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(book.title)}</title><style>{INDEX_CSS}</style></head><body>{cover}<h1>{html.escape(book.title)}</h1>{author}{drm}{toc}</body></html>'


_XML_ONLY_ENTITIES = {'lt', 'gt', 'amp', 'quot', 'apos'}
_ENTITY_REF_RE = re.compile(r'&([A-Za-z][A-Za-z0-9]*);')
_COMMENT_OR_CDATA_RE = re.compile(r'<!--.*?-->|<!\[CDATA\[.*?\]\]>', re.DOTALL)


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
        if name in _XML_ONLY_ENTITIES: return m.group(0)
        codepoint = html_entities.name2codepoint.get(name)
        return f'&#{codepoint};' if codepoint is not None else m.group(0)

    out, pos = [], 0
    for m in _COMMENT_OR_CDATA_RE.finditer(text):
        out.append(_ENTITY_REF_RE.sub(repl, text[pos:m.start()])); out.append(m.group(0)); pos = m.end()
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
    parser = ET.XMLParser()
    try:
        parser.feed(text.encode('utf-8')); root = parser.close()
    except (ET.ParseError, ValueError):
        return False
    return root.tag == f'{{{XHTML_NS_URI}}}html'


class ReaderHandler(BaseHTTPRequestHandler):
    book = None
    verbose = False
    _head_only = False
    def log_message(self, fmt, *args): pass  # all request logging goes through log_request below
    def log_request(self, code='-', size='-'):
        # Always surface failures (a 404 for a stylesheet or font is the usual
        # reason a book looks wrong); log every request with --verbose.
        try: failed = int(code) >= 400
        except (TypeError, ValueError): failed = False
        if self.verbose or failed: print(f'{code} {self.command} {self.path}', file=sys.stderr)
    def do_GET(self):
        try: self._route()
        except Exception as exc:
            traceback.print_exc(); self._send(500, f'Internal error: {exc}'.encode('utf-8', 'replace'), 'text/plain; charset=utf-8')
    def do_HEAD(self):  # same status and headers as GET, no body
        self._head_only = True; self.do_GET()
    def _route(self):
        path = self.path.split('?', 1)[0]
        if path == '/': self._send(200, make_index_html(self.book).encode(), 'text/html; charset=utf-8')
        elif path.startswith('/book/'): self._serve_epub_file(self.book.resolve(path[6:]))
        else:
            # Some books reference resources by a root-absolute URL such as href="/styles/main.css"
            # or src="/OEBPS/images/a.png", meaning "from the root of the book". Serve those too,
            # trying the epub root first, then the package folder.
            rel = self.book.resolve(path)
            candidates = [rel] + ([posixpath.normpath(posixpath.join(self.book.opf_dir, rel))] if self.book.opf_dir else [])
            found = None
            for candidate in candidates:
                try: self.book.read_resource(candidate)
                except (KeyError, FileNotFoundError): continue
                except DrmProtectedError: pass  # it exists; _serve_epub_file will send the DRM notice
                found = candidate; break
            if found is None: self._send(404, b'Not found', 'text/plain; charset=utf-8')
            else: self._serve_epub_file(found)
    def _serve_epub_file(self, epub_path):
        try: raw = self.book.read_resource(epub_path)
        except DrmProtectedError:
            self._send(403, b"This part of the book is protected by DRM (rights-management encryption). This tool doesn't attempt to circumvent real content protection, so it can't display it.", 'text/plain; charset=utf-8'); return
        except (KeyError, FileNotFoundError):
            self._send(404, f'Not found in EPUB: {epub_path}'.encode(), 'text/plain; charset=utf-8'); return
        lower = epub_path.lower()
        if lower.endswith(('.xhtml', '.html', '.htm')):
            text, nav = XML_DECL_RE.sub('', sniff_text(raw)), make_nav_bar(self.book, epub_path)
            body = first_real_match(BODY_OPEN_RE, text)
            text = f'{text[:body.end()]}{nav}{text[body.end():]}' if body else nav + text
            # Well-formed XHTML is served as XML so the browser parses it the way the author
            # intended; anything sloppy falls back to the forgiving HTML parser rather than
            # showing an XML error page.
            xml_text = numeric_entities(text)
            if is_wellformed_xhtml(xml_text): self._send(200, xml_text.encode(), 'application/xhtml+xml; charset=utf-8')
            else: self._send(200, text.encode(), 'text/html; charset=utf-8')
        elif lower.endswith('.css'): self._send(200, sniff_text(raw).encode(), 'text/css; charset=utf-8')
        else:
            ctype, _ = mimetypes.guess_type(lower); self._send(200, raw, ctype or 'application/octet-stream')
    def _send(self, status, body, ctype):
        self.send_response(status); self.send_header('Content-Type', ctype); self.send_header('Content-Length', str(len(body))); self.end_headers()
        if not self._head_only: self.wfile.write(body)


# ---------------------------------------------------------------------------
# PDF hosting
# ---------------------------------------------------------------------------

PDF_MAGIC = b'%PDF-'
PDF_CHUNK = 64 * 1024
PDF_URL_RE = re.compile(r'/(view|pdf|dl)/([0-9a-f]{12})')

PDF_CSS = ('body{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px}li{margin:8px 0}'
           '.meta{color:#666;font-size:.85em;margin-left:6px}.dl{font-size:.85em;margin-left:10px}'
           'body.viewer{max-width:none;margin:0;padding:0;height:100vh;display:flex;flex-direction:column}'
           '#bar{background:#222;color:#eee;font-size:14px;padding:8px 14px;display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center}'
           '#bar a{color:#9cf;text-decoration:none;white-space:nowrap}#bar a:hover{text-decoration:underline}'
           '#bar .t{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;flex:0 1 auto}#bar .sp{flex:1 1 auto}'
           'object{flex:1 1 auto;width:100%;border:0}object p{padding:16px}')


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

    The folder is rescanned on every request, so PDFs dropped in while the
    server is running show up on a page reload. Files are addressed by an id
    derived from their relative path - never by a path taken from the URL - so
    a request can only ever reach a file the scan found."""

    def __init__(self, path):
        self.root = Path(path).resolve()
        self.single = self.root.is_file()

    def scan(self):
        if self.single:
            found, base = [self.root], self.root.parent
        else:
            found, base = [], self.root
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = sorted(d for d in dirnames if not d.startswith('.'))
                found.extend(Path(dirpath, f) for f in sorted(filenames)
                             if f.lower().endswith('.pdf') and not f.startswith('.'))
            found.sort(key=lambda p: str(p.relative_to(base)).lower())
        entries = []
        for p in found:
            try:
                size = p.stat().st_size
            except OSError:
                continue
            rel = p.relative_to(base).as_posix()
            entry_id = hashlib.sha1(rel.encode('utf-8', 'surrogateescape')).hexdigest()[:12]
            entries.append(PdfEntry(entry_id, p, rel, p.stem, size))
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
    m = re.fullmatch(r'\s*bytes\s*=\s*(\d*)\s*-\s*(\d*)\s*', header or '')
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
    return f'{kind}; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(filename, safe="", errors="replace")}'


def make_pdf_library_html(entries):
    if entries:
        items = ''.join(
            f'<li><a href="/view/{e.id}">{html.escape(e.name)}</a><span class="meta">{human_size(e.size)}</span>'
            f'<a class="dl" href="/dl/{e.id}">download</a></li>' for e in entries)
        body = f'<ol>{items}</ol>'
    else:
        body = '<p>No PDF files found.</p>'
    return (f'<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>PDF library</title><style>{PDF_CSS}</style></head><body><h1>PDF library</h1>{body}</body></html>')


def make_pdf_viewer_html(entry, show_back):
    title = html.escape(entry.title)
    back = '<a href="/">&#8962; Library</a>' if show_back else ''
    src, dl = f'/pdf/{entry.id}', f'/dl/{entry.id}'
    return (f'<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>{title}</title><style>{PDF_CSS}</style></head><body class="viewer">'
            f'<div id="bar">{back}<span class="t" title="{title}">{title}</span><span class="sp"></span>'
            f'<a href="{src}" target="_blank">Open in new tab</a><a href="{dl}">Download</a></div>'
            f'<object data="{src}" type="application/pdf"><p>Your browser can\'t show PDFs inline. '
            f'<a href="{src}">Open it</a> or <a href="{dl}">download it</a>.</p></object></body></html>')


class PdfHandler(ReaderHandler):
    library = None

    def _route(self):
        path = unquote(self.path.split('?', 1)[0])
        entries = self.library.scan()
        if path == '/':
            if self.library.single and entries:
                self._send(200, make_pdf_viewer_html(entries[0], show_back=False).encode(), 'text/html; charset=utf-8')
            else:
                self._send(200, make_pdf_library_html(entries).encode(), 'text/html; charset=utf-8')
            return
        m = PDF_URL_RE.fullmatch(path)
        entry = next((e for e in entries if m and e.id == m.group(2)), None)
        if entry is None:
            self._send(404, b'Not found', 'text/plain; charset=utf-8')
        elif m.group(1) == 'view':
            self._send(200, make_pdf_viewer_html(entry, show_back=not self.library.single).encode(), 'text/html; charset=utf-8')
        else:
            self._send_pdf(entry, 'attachment' if m.group(1) == 'dl' else 'inline')

    def _send_pdf(self, entry, disposition):
        try:
            f = open(entry.path, 'rb')
        except OSError:
            self._send(404, b'That PDF is no longer available', 'text/plain; charset=utf-8')
            return
        with f:
            size = os.fstat(f.fileno()).st_size
            byte_range = parse_byte_range(self.headers.get('Range'), size)
            if byte_range is False:
                self.send_response(416); self.send_header('Content-Range', f'bytes */{size}')
                self.send_header('Content-Length', '0'); self.end_headers()
                return
            start, end = byte_range if byte_range else (0, size - 1)
            length = max(end - start + 1, 0)
            self.send_response(206 if byte_range else 200)
            self.send_header('Content-Type', 'application/pdf')
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Content-Length', str(length))
            self.send_header('Content-Disposition', content_disposition(disposition, entry.path.name))
            self.send_header('X-Content-Type-Options', 'nosniff')
            if byte_range: self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
            self.end_headers()
            if self._head_only:
                return
            f.seek(start)
            remaining = length
            try:
                while remaining > 0:
                    chunk = f.read(min(PDF_CHUNK, remaining))
                    if not chunk:  # file shrank mid-transfer: drop the connection rather than hang the client
                        self.close_connection = True
                        break
                    self.wfile.write(chunk); remaining -= len(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the browser closed the tab or seeked elsewhere


def detect_mode(path):
    """'pdf' for a PDF file or a folder of PDFs, otherwise 'epub'."""
    if path.is_file():
        return 'pdf' if is_pdf_file(path) else 'epub'
    if path.is_dir() and not (path / 'META-INF' / 'container.xml').is_file() and PdfLibrary(path).scan():
        return 'pdf'
    return 'epub'


def run_server(handler, host, port, no_browser):
    try: server = ThreadingHTTPServer((host, port), handler)
    except OSError as exc:
        sys.exit(f'error: could not listen on {host}:{port} ({exc.strerror or exc}). Is another copy already running? Try a different --port.')
    url = f'http://{host}:{port}/'; print(f'serving at {url}  (Ctrl+C to stop)')
    if not no_browser:
        try: threading.Timer(0.5, lambda: webbrowser.open(url)).start()
        except Exception: pass
    try: server.serve_forever()
    except KeyboardInterrupt: print('\nstopped')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('epub', metavar='path', help='.epub or .pdf file, or a folder: either extracted epub contents or PDFs to host')
    parser.add_argument('--port', type=int, default=8000); parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--no-browser', action='store_true', help="don't try to auto-open a browser tab")
    parser.add_argument('--verbose', action='store_true', help='log every request (failed requests are always logged)')
    args = parser.parse_args(); src_path = Path(args.epub)
    if not src_path.exists(): sys.exit(f'error: {src_path} not found')
    if detect_mode(src_path) == 'pdf':
        library = PdfLibrary(src_path); count = len(library.scan())
        print(f'hosting {count} PDF file{"" if count == 1 else "s"} from {library.root}')
        PdfHandler.library = library; PdfHandler.verbose = args.verbose
        run_server(PdfHandler, args.host, args.port, args.no_browser); return
    try: book = Book(open_source(src_path))
    except Exception as exc: sys.exit(f'error: could not parse EPUB structure: {exc}')
    print(f'"{book.title}"' + (f' by {", ".join(book.authors)}' if book.authors else ''))
    print(f'{len(book.spine)} chapters, OPF at {book.opf_path}')
    if book.toc: print(f'table of contents: {len(book.toc)} top-level entries')
    if book.obfuscated_fonts: print(f'{len(book.obfuscated_fonts)} obfuscated font(s) will be de-obfuscated on the fly')
    if book.has_drm: print(f'warning: {len(book.drm_paths)} resource(s) are DRM-protected and will not be viewable')
    ReaderHandler.book = book; ReaderHandler.verbose = args.verbose
    run_server(ReaderHandler, args.host, args.port, args.no_browser)


if __name__ == '__main__': main()
