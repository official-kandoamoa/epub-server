"""Tests for epub_server.py. Standard library only, like the script itself.

Run from the repository root:

    python -m unittest discover -s tests -v
"""

import collections
import contextlib
import hashlib
import io
import os
import posixpath
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import unittest
import zipfile
from http.client import HTTPConnection
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import epub_server as es  # noqa: E402

SCRIPT = ROOT / 'epub_server.py'
Response = collections.namedtuple('Response', 'status headers body')


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def quiet_handler(base, **attrs):
    """A handler class that doesn't print failed requests, with class attributes set."""
    attrs.setdefault('log_request', lambda self, *args, **kwargs: None)
    return type('QuietHandler', (base,), attrs)


class Running:
    """A real HTTP server on a free port, running in a background thread."""

    def __init__(self, handler):
        self.server = es.QuietThreadingHTTPServer(('127.0.0.1', 0), handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def request(self, method, path, headers=None):
        conn = HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            body = resp.read()
            return Response(resp.status, {k.lower(): v for k, v in resp.getheaders()}, body)
        finally:
            conn.close()

    def get(self, path, headers=None):
        return self.request('GET', path, headers)

    def head(self, path, headers=None):
        return self.request('HEAD', path, headers)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Cli:
    """The script run as a real subprocess, the way a user would run it."""

    def __init__(self, *args):
        self.port = free_port()
        self.proc = subprocess.Popen(
            [
                sys.executable,
                '-I',
                '-u',
                str(SCRIPT),
                *map(str, args),
                '--no-browser',
                '--port',
                str(self.port),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        for _ in range(100):
            try:
                socket.create_connection(('127.0.0.1', self.port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    def get(self, path, headers=None):
        return Running.request(self, 'GET', path, headers)

    def stop(self):
        self.proc.terminate()
        try:
            return self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.communicate()


def run_script(*args):
    """Run the script expecting it to exit on its own (bad input); returns the process."""
    return subprocess.run(
        [sys.executable, '-I', str(SCRIPT), *map(str, args), '--no-browser'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=30,
    )


# ---------------------------------------------------------------------------
# EPUB fixtures
# ---------------------------------------------------------------------------

IDENTIFIER = 'urn:uuid:12345678-1234-1234-1234-123456789abc'

CONTAINER_XML = (
    '<?xml version="1.0"?><container version="1.0" '
    'xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles>'
    '<rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>'
    '</rootfiles></container>'
)

XHTML = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<html xmlns="http://www.w3.org/1999/xhtml">'
    '<head>{head}</head><body><h1>{h1}</h1>{body}</body></html>'
)

CHAPTER_1 = XHTML.format(
    head='<!-- <body> and <title>Fake Title</title> in a comment --><title>Chapter One</title>'
    '<link rel="stylesheet" href="style.css"/>',
    h1='One',
    body='<p>Hello&nbsp;world &mdash; caf&eacute;</p><a id="anchor"/><p>tail</p>'
    '<script>window.pwned = 1</script>',
)
CHAPTER_2 = XHTML.format(head='', h1='Second Heading', body='<p>two</p>')
CHAPTER_3 = '<html><head><title>Sloppy</title></head><body><p>unclosed<br><p>second</body></html>'  # not well-formed XML, must fall back to text/html
CHAPTER_ACCENT = XHTML.format(head='<title>Café chapter</title>', h1='x', body='<p>x</p>')
CHAPTER_DRM = XHTML.format(head='<title>Secret</title>', h1='x', body='<p>x</p>')
CHAPTER_BIG = XHTML.format(head='<title>Big</title>', h1='x', body='<p>' + 'x' * 5000 + '</p>')

NAV_XHTML = (
    '<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml" '
    'xmlns:epub="http://www.idpf.org/2007/ops"><head><title>Contents</title></head><body>'
    '<nav epub:type="toc"><ol>'
    '<li><a href="c1.xhtml#anchor">Part One</a><ol><li><a href="c2.xhtml">Nested Two</a></li></ol></li>'
    '<li><span>Heading Without Link</span></li>'
    '</ol></nav></body></html>'
)

STYLE_CSS = b'@charset "iso-8859-1";\n.x{content:"caf\xe9"}\n'
PNG = b'\x89PNG\r\n\x1a\n' + bytes(range(256))
BIG_IMAGE = bytes(range(256)) * 20  # 5120 bytes
VIDEO = bytes(range(256)) * 80  # 20480 bytes, compresses well so it exercises the deflate stream
FONT_ORIGINAL = bytes(range(256)) * 8


def obfuscate_idpf(data, identifier):
    """Independent implementation of the IDPF font obfuscation, to check the server's."""
    key = hashlib.sha1(identifier.encode('utf-8')).digest()
    out = bytearray(data)
    for i in range(min(1040, len(out))):
        out[i] ^= key[i % len(key)]
    return bytes(out)


ENCRYPTION_XML = (
    '<encryption xmlns="urn:oasis:names:tc:opendocument:xmlns:container" '
    'xmlns:enc="http://www.w3.org/2001/04/xmlenc#">'
    '<enc:EncryptedData><enc:EncryptionMethod Algorithm="http://www.idpf.org/2008/embedding"/>'
    '<enc:CipherData><enc:CipherReference URI="OEBPS/fonts/f.otf"/></enc:CipherData>'
    '</enc:EncryptedData>'
    '<enc:EncryptedData><enc:EncryptionMethod '
    'Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>'
    '<enc:CipherData><enc:CipherReference URI="OEBPS/drm.xhtml"/></enc:CipherData>'
    '</enc:EncryptedData></encryption>'
)


def make_opf(
    manifest,
    spine,
    title='Test Book',
    creators=('Ann Author', 'Bob Writer'),
    language='en',
    ncx_id=None,
    extra_metadata='',
):
    items = ''.join(
        f'<item id="{i}" href="{h}" media-type="{m}"' + (f' properties="{p}"' if p else '') + '/>'
        for i, h, m, p in manifest
    )
    refs = ''.join(f'<itemref idref="{i}"/>' for i in spine)
    authors = ''.join(f'<dc:creator>{c}</dc:creator>' for c in creators)
    toc_attr = f' toc="{ncx_id}"' if ncx_id else ''
    return (
        '<?xml version="1.0"?><package xmlns="http://www.idpf.org/2007/opf" version="3.0" '
        'unique-identifier="bookid"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f'<dc:title>{title}</dc:title>{authors}<dc:language>{language}</dc:language>'
        f'<dc:identifier id="bookid">{IDENTIFIER}</dc:identifier>{extra_metadata}</metadata>'
        f'<manifest>{items}</manifest><spine{toc_attr}>{refs}</spine></package>'
    )


XH = 'application/xhtml+xml'
MAIN_MANIFEST = [
    ('nav', 'nav.xhtml', XH, 'nav'),
    ('c1', 'c1.xhtml', XH, ''),
    ('c2', 'c2.xhtml', XH, ''),
    ('c3', 'c3.html', 'text/html', ''),
    ('acc', 'café.xhtml', XH, ''),
    ('big', 'big.xhtml', XH, ''),
    ('drm', 'drm.xhtml', XH, ''),
    ('css', 'style.css', 'text/css', ''),
    ('cover', 'img/cover.png', 'image/png', 'cover-image'),
]
MAIN_SPINE = ['c1', 'c2', 'c3', 'acc', 'big', 'drm']


def main_epub_files():
    """Every file of the main test book, as {zip entry name: bytes}."""
    return {
        'mimetype': b'application/epub+zip',
        'META-INF/container.xml': CONTAINER_XML.encode(),
        'META-INF/encryption.xml': ENCRYPTION_XML.encode(),
        'OEBPS/content.opf': make_opf(MAIN_MANIFEST, MAIN_SPINE).encode(),
        'OEBPS/nav.xhtml': NAV_XHTML.encode(),
        'OEBPS/c1.xhtml': CHAPTER_1.encode(),
        'OEBPS/c2.xhtml': CHAPTER_2.encode(),
        'OEBPS/c3.html': CHAPTER_3.encode(),
        # Stored in decomposed (NFD) form while the manifest says composed (NFC): macOS-style.
        unicodedata.normalize('NFD', 'OEBPS/café.xhtml'): CHAPTER_ACCENT.encode(),
        'OEBPS/big.xhtml': CHAPTER_BIG.encode(),
        'OEBPS/drm.xhtml': CHAPTER_DRM.encode(),
        'OEBPS/style.css': STYLE_CSS,
        'OEBPS/img/cover.png': PNG,
        'OEBPS/img/pic.png': PNG,
        'OEBPS/img/big.png': BIG_IMAGE,
        'OEBPS/media/clip.mp4': VIDEO,
        'OEBPS/fonts/f.otf': obfuscate_idpf(FONT_ORIGINAL, IDENTIFIER),
    }


def write_epub(path, files):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return path


def load_book(path):
    """Build a Book, returning it with whatever warnings it wrote to stderr."""
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        book = es.Book(es.open_source(path))
    return book, err.getvalue()


class TempDirCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix='epub_server_tests_')
        cls.tmp = Path(cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------


class ByteRangeTests(unittest.TestCase):
    def test_variants(self):
        P = es.parse_byte_range
        self.assertIsNone(P(None, 100))
        self.assertEqual(P('bytes=0-9', 100), (0, 9))
        self.assertEqual(P('bytes=90-', 100), (90, 99))
        self.assertEqual(P('bytes=90-500', 100), (90, 99))
        self.assertEqual(P('bytes=-10', 100), (90, 99))
        self.assertEqual(P('bytes=-500', 100), (0, 99))

    def test_unsatisfiable(self):
        P = es.parse_byte_range
        self.assertIs(P('bytes=100-', 100), False)
        self.assertIs(P('bytes=-0', 100), False)
        self.assertIs(P('bytes=0-', 0), False)

    def test_ignored(self):
        P = es.parse_byte_range
        self.assertIsNone(P('bytes=0-1,5-6', 100))  # multi-range: just send everything
        self.assertIsNone(P('lines=1-2', 100))
        self.assertIsNone(P('bytes=9-2', 100))
        self.assertIsNone(P('bytes=-', 100))


class SmallHelperTests(unittest.TestCase):
    def test_etag_matches(self):
        self.assertTrue(es.etag_matches('"a"', '"a"'))
        self.assertTrue(es.etag_matches('"x", "a"', '"a"'))
        self.assertTrue(es.etag_matches('W/"a"', '"a"'))
        self.assertTrue(es.etag_matches('*', '"a"'))
        self.assertFalse(es.etag_matches('"b"', '"a"'))
        self.assertFalse(es.etag_matches(None, '"a"'))
        self.assertFalse(es.etag_matches('', '"a"'))

    def test_human_size(self):
        self.assertEqual(es.human_size(0), '0 B')
        self.assertEqual(es.human_size(2048), '2.0 KB')
        self.assertEqual(es.human_size(5 * 1024 * 1024), '5.0 MB')

    def test_content_disposition_is_ascii_safe(self):
        header = es.content_disposition('inline', 'café "x".pdf')
        header.encode('ascii')  # must not raise
        self.assertIn("filename*=UTF-8''caf%C3%A9%20%22x%22.pdf", header)
        self.assertTrue(header.startswith('inline;'))

    def test_numeric_entities_leave_comments_and_xml_entities(self):
        out = es.numeric_entities('a&nbsp;b &amp; c<!-- &nbsp; --><![CDATA[&nbsp;]]>&eacute;')
        self.assertEqual(out, 'a&#160;b &amp; c<!-- &nbsp; --><![CDATA[&nbsp;]]>&#233;')

    def test_wellformed_xhtml(self):
        good = '<html xmlns="http://www.w3.org/1999/xhtml"><body/></html>'
        self.assertTrue(es.is_wellformed_xhtml(good))
        self.assertFalse(es.is_wellformed_xhtml('<html><body><p>unclosed</body></html>'))
        self.assertFalse(es.is_wellformed_xhtml('<html><body/></html>'))  # XML but not XHTML

    def test_sniff_text(self):
        self.assertEqual(es.sniff_text('café'.encode('utf-8-sig')), 'café')
        self.assertEqual(es.sniff_text('héllo'.encode('utf-16')), 'héllo')
        latin = b'<?xml version="1.0" encoding="iso-8859-1"?><p>caf\xe9</p>'
        self.assertIn('café', es.sniff_text(latin))
        self.assertEqual(es.sniff_text(b'caf\xe9'), 'café')  # undeclared, not UTF-8

    def test_first_real_element_skips_comments_cdata_script_style(self):
        text = (
            '<!-- <title>no</title> --><![CDATA[<title>no</title>]]>'
            '<script>"<title>no</title>"</script><SCRIPT type="x">1</SCRIPT >'
            '<style>/* <title>no</title> */</style><title>yes</title>'
        )
        self.assertEqual(es.first_real_element_text(text, 'title'), 'yes')

    def test_element_lookup_edge_cases(self):
        T = es.first_real_element_text
        self.assertEqual(T('<TITLE lang="en">Caps</TITLE>', 'title'), 'Caps')
        self.assertIsNone(T('<titles>not a title</titles>', 'title'))  # a different element
        self.assertIsNone(T('<title/>', 'title'))  # empty
        self.assertIsNone(T('<title>never closed', 'title'))
        self.assertIsNone(T('<p>nothing here</p>', 'title'))
        # A self-closed <script/> must not swallow the real title after it.
        self.assertEqual(T('<script src="a.js"/><title>seen</title>', 'title'), 'seen')
        # An unterminated comment runs to the end of the text, as in a browser.
        self.assertIsNone(T('<!-- oops <title>hidden</title>', 'title'))

    def test_skipped_spans(self):
        text = 'a<!--x-->b<![CDATA[y]]>c<script>z</script>d'
        self.assertEqual(
            [text[s:e] for s, e in es.skipped_spans(text)],
            ['<!--x-->', '<![CDATA[y]]>', '<script>z</script>'],
        )
        self.assertEqual(
            [text[s:e] for s, e in es.skipped_spans(text, comments_only=True)],
            ['<!--x-->', '<![CDATA[y]]>'],
        )
        self.assertEqual(es.skipped_spans('<!-- open'), [(0, 9)])

    def test_first_real_tag_finds_body_outside_comments(self):
        text = '<!-- <body class="fake"> --><head/><body class="real">'
        self.assertEqual(es.first_real_tag(text, 'body').group(0), '<body class="real">')
        self.assertIsNone(es.first_real_tag('<!-- <body> -->', 'body'))

    def test_parse_xml_refuses_entity_declarations(self):
        bomb = (
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa">'
            '<!ENTITY b "&a;&a;&a;&a;">]><x>&b;</x>'
        )
        for payload in (bomb, bomb.encode(), bomb.encode('utf-16-le'), bomb.encode('utf-16-be')):
            with self.assertRaises(es.ET.ParseError):
                es.parse_xml(payload)
        # A DOCTYPE that only points at the XHTML DTD is perfectly normal and still parses.
        ok = (
            b'<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" '
            b'"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd"><html xmlns="x"/>'
        )
        self.assertEqual(es.parse_xml(ok).tag, '{x}html')
        self.assertFalse(es.is_wellformed_xhtml(bomb))

    def test_printable_neutralises_control_characters(self):
        self.assertEqual(es.printable('/a\x1b[31m\r\nb'), '/a\\x1b[31m\\x0d\\x0ab')
        self.assertEqual(es.printable('x' * 300), 'x' * 200 + '...')

    def test_host_header_names(self):
        H = es.host_header_name
        self.assertEqual(H('localhost:8000'), 'localhost')
        self.assertEqual(H('LOCALHOST'), 'localhost')
        self.assertEqual(H('127.0.0.1:9'), '127.0.0.1')
        self.assertEqual(H('[::1]:8000'), '::1')
        self.assertEqual(H('localhost.:80'), 'localhost')
        self.assertEqual(H('evil.example:80'), 'evil.example')

    def test_allowed_host_names_only_for_loopback_binds(self):
        self.assertIn('localhost', es.allowed_host_names('127.0.0.1'))
        self.assertIn('127.0.0.1', es.allowed_host_names('localhost'))
        self.assertIn('127.0.0.2', es.allowed_host_names('127.0.0.2'))
        self.assertIsNone(es.allowed_host_names('0.0.0.0'))
        self.assertIsNone(es.allowed_host_names('192.168.1.5'))

    def test_build_csp(self):
        default = es.build_csp()
        self.assertIn("script-src 'none'", default)
        self.assertIn("default-src 'self' data:", default)
        self.assertNotIn('https:', default)
        self.assertIn("frame-ancestors 'none'", default)
        scripts = es.build_csp(allow_scripts=True)
        self.assertNotIn("script-src 'none'", scripts)
        self.assertIn("'unsafe-inline'", scripts.split('script-src')[1])
        self.assertIn('https:', es.build_csp(allow_remote=True))
        self.assertEqual(es.build_csp(), default)

    def test_resolve_href(self):
        self.assertEqual(
            es.resolve_href('../a%20b.xhtml#x', 'OEBPS/text'), ('OEBPS/a b.xhtml', 'x')
        )
        self.assertEqual(es.resolve_href('#only', 'OEBPS'), ('', 'only'))

    def test_font_deobfuscation_round_trip(self):
        scrambled = obfuscate_idpf(FONT_ORIGINAL, IDENTIFIER)
        self.assertNotEqual(scrambled, FONT_ORIGINAL)
        self.assertEqual(
            es.deobfuscate_font(scrambled, es.IDPF_FONT_ALG, IDENTIFIER), FONT_ORIGINAL
        )
        self.assertEqual(es.deobfuscate_font(scrambled, 'unknown-alg', IDENTIFIER), scrambled)

    def test_rtl_languages(self):
        self.assertTrue(es.is_rtl_language('ar'))
        self.assertTrue(es.is_rtl_language('he-IL'))
        self.assertFalse(es.is_rtl_language('en'))
        self.assertFalse(es.is_rtl_language(None))


class ByteLRUTests(unittest.TestCase):
    def test_evicts_least_recently_used(self):
        cache = es.ByteLRU(100)
        for key in 'abcd':
            cache.put(key, key.upper(), 24)  # 96 bytes: just fits
        self.assertEqual(cache.get('a'), 'A')  # touch a, so b is now the oldest
        cache.put('e', 'E', 24)  # 120 bytes > 100: evict b
        self.assertIsNone(cache.get('b'))
        self.assertEqual([cache.get(k) for k in 'acde'], ['A', 'C', 'D', 'E'])

    def test_skips_items_that_would_dominate(self):
        cache = es.ByteLRU(100)
        cache.put('huge', 'H', 60)  # more than a quarter of the budget
        self.assertIsNone(cache.get('huge'))

    def test_replacing_a_key_does_not_leak_size(self):
        cache = es.ByteLRU(100)
        for _ in range(50):
            cache.put('k', 'v', 20)
        cache.put('other', 'o', 20)
        self.assertEqual(cache.get('k'), 'v')
        self.assertEqual(cache.get('other'), 'o')


# ---------------------------------------------------------------------------
# EPUB serving
# ---------------------------------------------------------------------------


class EpubServerTests(TempDirCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.epub = write_epub(cls.tmp / 'book.epub', main_epub_files())
        cls.book, cls.load_warnings = load_book(cls.epub)
        cls.handler = quiet_handler(
            es.ReaderHandler,
            book=cls.book,
            csp=es.build_csp(),
            chapter_cache=es.ByteLRU(es.CHAPTER_CACHE_BYTES),
        )
        cls.srv = Running(cls.handler)

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        super().tearDownClass()

    # -- index page ---------------------------------------------------------

    def test_loads_without_warnings(self):
        self.assertEqual(self.load_warnings, '')

    def test_index_shows_title_authors_cover_and_nested_toc(self):
        r = self.srv.get('/')
        self.assertEqual(r.status, 200)
        page = r.body.decode()
        self.assertIn('<h1>Test Book</h1>', page)
        self.assertIn('by Ann Author, Bob Writer', page)
        self.assertIn('<img class="cover" src="/book/OEBPS/img/cover.png"', page)
        self.assertIn('Part One</a><ol><li><a href="/book/OEBPS/c2.xhtml">Nested Two', page)
        self.assertIn('<span class="toc-heading">Heading Without Link</span>', page)
        self.assertIn('/book/OEBPS/c1.xhtml#anchor', page)

    def test_drm_notice_and_lock_badges(self):
        page = self.srv.get('/').body.decode()
        self.assertIn('DRM-protected', page)
        self.assertEqual(self.book.drm_paths, {'OEBPS/drm.xhtml': mock.ANY})

    # -- chapters -----------------------------------------------------------

    def test_wellformed_chapter_is_xhtml_with_nav_bar_and_numeric_entities(self):
        r = self.srv.get('/book/OEBPS/c1.xhtml')
        self.assertEqual(r.status, 200)
        self.assertEqual(r.headers['content-type'], 'application/xhtml+xml; charset=utf-8')
        page = r.body.decode()
        self.assertIn('Hello&#160;world &#8212; caf&#233;', page)
        self.assertIn('id="__reader_nav"', page)
        self.assertIn('1 / 6', page)
        self.assertIn('Next &#8594;', page)
        self.assertNotIn('Prev', page.split('__reader_nav')[1].split('</div>')[0])
        # The nav goes after the real <body>, not the one mentioned inside a comment.
        self.assertGreater(page.index('id="__reader_nav"'), page.index('</head>'))

    def test_nav_bar_title_ignores_title_tags_inside_comments(self):
        page = self.srv.get('/book/OEBPS/c1.xhtml').body.decode()
        self.assertIn('title="Chapter One"', page)
        self.assertNotIn('Fake Title"', page.split('<body>')[1])

    def test_title_falls_back_to_first_h1(self):
        page = self.srv.get('/book/OEBPS/c2.xhtml').body.decode()
        self.assertIn('title="Second Heading"', page)

    def test_sloppy_html_falls_back_to_html_parser(self):
        r = self.srv.get('/book/OEBPS/c3.html')
        self.assertEqual(r.status, 200)
        self.assertEqual(r.headers['content-type'], 'text/html; charset=utf-8')
        self.assertIn(b'__reader_nav', r.body)

    def test_nfd_filename_inside_zip_is_found_by_nfc_url(self):
        r = self.srv.get('/book/OEBPS/caf%C3%A9.xhtml')
        self.assertEqual(r.status, 200)
        self.assertIn('Café chapter', r.body.decode())

    def test_css_charset_is_normalised_to_utf8(self):
        r = self.srv.get('/book/OEBPS/style.css')
        self.assertEqual(r.headers['content-type'], 'text/css; charset=utf-8')
        self.assertIn('café', r.body.decode('utf-8'))

    def test_root_absolute_urls_resolve_against_book_then_package_folder(self):
        self.assertEqual(self.srv.get('/OEBPS/img/pic.png').body, PNG)  # epub root
        self.assertEqual(self.srv.get('/img/pic.png').body, PNG)  # package folder
        self.assertEqual(self.srv.get('/definitely/missing.png').status, 404)

    def test_missing_resource_is_404(self):
        self.assertEqual(self.srv.get('/book/OEBPS/missing.css').status, 404)

    def test_path_traversal_cannot_leave_the_book(self):
        for path in ('/book/../../etc/passwd', '/book/%2e%2e/%2e%2e/etc/passwd'):
            self.assertEqual(self.srv.get(path).status, 404, path)

    def test_obfuscated_font_is_served_deobfuscated(self):
        r = self.srv.get('/book/OEBPS/fonts/f.otf')
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, FONT_ORIGINAL)
        self.assertEqual(r.headers['content-type'], 'font/otf')

    def test_drm_protected_chapter_is_refused_clearly(self):
        r = self.srv.get('/book/OEBPS/drm.xhtml')
        self.assertEqual(r.status, 403)
        self.assertIn(b'DRM', r.body)
        # ... including when reached through a root-absolute URL
        self.assertEqual(self.srv.get('/OEBPS/drm.xhtml').status, 403)

    def test_head_matches_get_without_a_body(self):
        get = self.srv.get('/book/OEBPS/c1.xhtml')
        head = self.srv.head('/book/OEBPS/c1.xhtml')
        self.assertEqual(head.status, 200)
        self.assertEqual(head.body, b'')
        self.assertEqual(head.headers['content-length'], get.headers['content-length'])

    # -- caching ------------------------------------------------------------

    def test_etag_and_304_for_chapters(self):
        first = self.srv.get('/book/OEBPS/c2.xhtml')
        etag = first.headers['etag']
        self.assertEqual(first.headers['cache-control'], 'no-cache')
        again = self.srv.get('/book/OEBPS/c2.xhtml', {'If-None-Match': etag})
        self.assertEqual(again.status, 304)
        self.assertEqual(again.body, b'')
        self.assertEqual(again.headers['etag'], etag)
        stale = self.srv.get('/book/OEBPS/c2.xhtml', {'If-None-Match': '"something-else"'})
        self.assertEqual(stale.status, 200)
        self.assertEqual(stale.body, first.body)

    def test_etag_and_304_for_images_without_reading_the_body(self):
        first = self.srv.get('/book/OEBPS/img/pic.png')
        self.assertEqual(first.body, PNG)
        again = self.srv.get('/book/OEBPS/img/pic.png', {'If-None-Match': first.headers['etag']})
        self.assertEqual(again.status, 304)

    def test_processed_chapters_are_cached(self):
        calls = []
        real = es.render_chapter

        def counting(book, path, raw):
            calls.append(path)
            return real(book, path, raw)

        handler = quiet_handler(
            es.ReaderHandler, book=self.book, chapter_cache=es.ByteLRU(es.CHAPTER_CACHE_BYTES)
        )
        srv = Running(handler)
        try:
            with mock.patch.object(es, 'render_chapter', counting):
                bodies = [srv.get('/book/OEBPS/c2.xhtml').body for _ in range(3)]
        finally:
            srv.close()
        self.assertEqual(calls, ['OEBPS/c2.xhtml'])  # rendered once, served three times
        self.assertEqual(len(set(bodies)), 1)

    def test_cache_can_be_switched_off(self):
        handler = quiet_handler(es.ReaderHandler, book=self.book, chapter_cache=None)
        srv = Running(handler)
        try:
            self.assertEqual(srv.get('/book/OEBPS/c2.xhtml').status, 200)
        finally:
            srv.close()

    # -- scripts ------------------------------------------------------------

    def test_csp_blocks_scripts_and_remote_content_on_every_response(self):
        for path in ('/', '/book/OEBPS/c1.xhtml', '/book/OEBPS/img/pic.png', '/book/OEBPS/nope'):
            r = self.srv.get(path)
            policy = r.headers.get('content-security-policy', '')
            self.assertEqual(policy, es.build_csp(), path)
            self.assertIn("script-src 'none'", policy)
            self.assertIn("default-src 'self' data:", policy)

    def test_no_csp_header_when_the_handler_has_no_policy(self):
        srv = Running(quiet_handler(es.ReaderHandler, book=self.book, csp=None))
        try:
            self.assertNotIn('content-security-policy', srv.get('/book/OEBPS/c1.xhtml').headers)
        finally:
            srv.close()

    def test_security_headers_on_every_kind_of_response(self):
        url = '/book/OEBPS/media/clip.mp4'
        responses = [
            self.srv.get('/'),  # index
            self.srv.get('/book/OEBPS/c1.xhtml'),  # chapter
            self.srv.get('/book/OEBPS/img/pic.png'),  # buffered image
            self.srv.get(url),  # streamed
            self.srv.get(url, {'Range': 'bytes=999999-'}),  # 416
            self.srv.get('/book/OEBPS/c1.xhtml', {'If-None-Match': '*'}),  # 304
            self.srv.get('/book/OEBPS/missing'),  # 404
            self.srv.get('/book/OEBPS/drm.xhtml'),  # 403
            self.srv.request('POST', '/'),  # 501 generated by the standard library
        ]
        self.assertEqual(
            [r.status for r in responses], [200, 200, 200, 200, 416, 304, 404, 403, 501]
        )
        for r in responses:
            self.assertEqual(r.headers.get('x-content-type-options'), 'nosniff', r.status)
            self.assertEqual(r.headers.get('referrer-policy'), 'same-origin', r.status)
            self.assertEqual(r.headers.get('cross-origin-resource-policy'), 'same-origin', r.status)
            self.assertEqual(r.headers.get('content-security-policy'), es.build_csp(), r.status)
            # sent once, not twice
            self.assertNotIn(',', r.headers['x-content-type-options'])

    # -- streaming ----------------------------------------------------------

    def test_video_is_streamed_with_range_support(self):
        r = self.srv.get('/book/OEBPS/media/clip.mp4')
        self.assertEqual((r.status, r.body), (200, VIDEO))
        self.assertEqual(r.headers['accept-ranges'], 'bytes')
        self.assertEqual(r.headers['content-type'], 'video/mp4')

        part = self.srv.get('/book/OEBPS/media/clip.mp4', {'Range': 'bytes=1000-1999'})
        self.assertEqual(part.status, 206)
        self.assertEqual(part.body, VIDEO[1000:2000])
        self.assertEqual(part.headers['content-range'], f'bytes 1000-1999/{len(VIDEO)}')

        tail = self.srv.get('/book/OEBPS/media/clip.mp4', {'Range': 'bytes=-100'})
        self.assertEqual((tail.status, tail.body), (206, VIDEO[-100:]))

        # Seeking backwards after a forward read (the zip stream has to restart) still works.
        again = self.srv.get('/book/OEBPS/media/clip.mp4', {'Range': 'bytes=0-9'})
        self.assertEqual(again.body, VIDEO[:10])

        past = self.srv.get('/book/OEBPS/media/clip.mp4', {'Range': 'bytes=999999-'})
        self.assertEqual(past.status, 416)
        self.assertEqual(past.headers['content-range'], f'bytes */{len(VIDEO)}')

    def test_large_non_text_resources_are_streamed_small_ones_are_not(self):
        with mock.patch.object(es, 'STREAM_THRESHOLD', 1000):
            big = self.srv.get('/book/OEBPS/img/big.png', {'Range': 'bytes=10-19'})
            self.assertEqual((big.status, big.body), (206, BIG_IMAGE[10:20]))
            small = self.srv.get('/book/OEBPS/img/pic.png', {'Range': 'bytes=0-4'})
            self.assertEqual((small.status, small.body), (200, PNG))  # buffered: Range ignored

    def test_if_range_with_stale_validator_sends_the_whole_file(self):
        url = '/book/OEBPS/media/clip.mp4'
        etag = self.srv.head(url).headers['etag']
        stale = self.srv.get(url, {'Range': 'bytes=0-9', 'If-Range': '"old"'})
        self.assertEqual((stale.status, len(stale.body)), (200, len(VIDEO)))
        fresh = self.srv.get(url, {'Range': 'bytes=0-9', 'If-Range': etag})
        self.assertEqual((fresh.status, fresh.body), (206, VIDEO[:10]))

    def test_streamed_video_head_and_304(self):
        url = '/book/OEBPS/media/clip.mp4'
        head = self.srv.head(url)
        self.assertEqual((head.status, head.body), (200, b''))
        self.assertEqual(head.headers['content-length'], str(len(VIDEO)))
        self.assertEqual(self.srv.get(url, {'If-None-Match': head.headers['etag']}).status, 304)

    # -- limits -------------------------------------------------------------

    def test_oversized_text_resource_is_refused_instead_of_loaded(self):
        with mock.patch.object(es, 'MAX_INMEMORY_BYTES', 1000):
            r = self.srv.get('/book/OEBPS/big.xhtml')
        self.assertEqual(r.status, 413)
        self.assertEqual(self.srv.get('/book/OEBPS/big.xhtml').status, 200)  # limit lifted again

    def test_source_read_enforces_the_cap_but_open_streams_regardless(self):
        source = es.open_source(self.epub)
        with mock.patch.object(es, 'MAX_INMEMORY_BYTES', 1000):
            with self.assertRaises(es.ResourceTooLargeError):
                source.read('OEBPS/media/clip.mp4')
            f, size, validator = source.open('OEBPS/media/clip.mp4')
            with f:
                self.assertEqual((size, f.read()), (len(VIDEO), VIDEO))
            self.assertTrue(validator)

    # -- concurrency --------------------------------------------------------

    def test_many_simultaneous_requests_get_correct_bytes(self):
        errors = []

        def hit(i):
            try:
                if i % 3 == 0:
                    r = self.srv.get(
                        '/book/OEBPS/media/clip.mp4', {'Range': f'bytes={i}-{i + 500}'}
                    )
                    ok = r.status == 206 and r.body == VIDEO[i : i + 501]
                elif i % 3 == 1:
                    r = self.srv.get('/book/OEBPS/c2.xhtml')
                    ok = r.status == 200 and b'Second Heading' in r.body
                else:
                    r = self.srv.get('/book/OEBPS/fonts/f.otf')
                    ok = r.status == 200 and r.body == FONT_ORIGINAL
                if not ok:
                    errors.append((i, r.status))
            except Exception as exc:  # noqa: BLE001 - report any failure from a worker thread
                errors.append((i, repr(exc)))

        threads = [threading.Thread(target=hit, args=(i,)) for i in range(60)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


class ExtractedFolderTests(TempDirCase):
    """The same book served from an already-extracted folder."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.folder = cls.tmp / 'extracted'
        for name, data in main_epub_files().items():
            target = cls.folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        cls.book, _ = load_book(cls.folder)
        cls.srv = Running(
            quiet_handler(
                es.ReaderHandler,
                book=cls.book,
                csp=es.build_csp(),
                chapter_cache=es.ByteLRU(es.CHAPTER_CACHE_BYTES),
            )
        )

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        super().tearDownClass()

    def test_serves_chapters_and_media(self):
        self.assertIn(b'Second Heading', self.srv.get('/book/OEBPS/c2.xhtml').body)
        part = self.srv.get('/book/OEBPS/media/clip.mp4', {'Range': 'bytes=5-14'})
        self.assertEqual((part.status, part.body), (206, VIDEO[5:15]))

    def test_nfc_url_finds_nfd_file_on_disk_or_a_normalised_name(self):
        # On disk the file is stored under its NFD name; the NFC URL must still find it.
        self.assertEqual(self.srv.get('/book/OEBPS/caf%C3%A9.xhtml').status, 200)

    def test_edits_show_up_immediately_and_are_never_served_stale(self):
        url = '/book/OEBPS/c2.xhtml'
        first = self.srv.get(url)
        path = self.folder / 'OEBPS' / 'c2.xhtml'
        path.write_bytes(CHAPTER_2.replace('Second Heading', 'Edited Heading').encode())
        second = self.srv.get(url, {'If-None-Match': first.headers['etag']})
        self.assertEqual(second.status, 200)
        self.assertIn(b'Edited Heading', second.body)
        self.assertNotEqual(second.headers['etag'], first.headers['etag'])
        path.write_bytes(CHAPTER_2.encode())  # restore for other tests

    def test_directories_and_escapes_are_not_served(self):
        self.assertEqual(self.srv.get('/book/OEBPS/img').status, 404)
        self.assertEqual(self.srv.get('/book/../extracted/../../../etc/passwd').status, 404)


class BookParsingTests(TempDirCase):
    def test_epub2_ncx_table_of_contents(self):
        ncx = (
            '<?xml version="1.0"?><ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">'
            '<navMap><navPoint id="a"><navLabel><text>Intro</text></navLabel>'
            '<content src="c1.xhtml"/><navPoint id="b"><navLabel><text>Deeper</text></navLabel>'
            '<content src="c2.xhtml#x"/></navPoint></navPoint></navMap></ncx>'
        )
        manifest = [
            ('ncx', 'toc.ncx', 'application/x-dtbncx+xml', ''),
            ('c1', 'c1.xhtml', XH, ''),
            ('c2', 'c2.xhtml', XH, ''),
        ]
        path = write_epub(
            self.tmp / 'epub2.epub',
            {
                'mimetype': b'application/epub+zip',
                'META-INF/container.xml': CONTAINER_XML.encode(),
                'OEBPS/content.opf': make_opf(manifest, ['c1', 'c2'], ncx_id='ncx').encode(),
                'OEBPS/toc.ncx': ncx.encode(),
                'OEBPS/c1.xhtml': CHAPTER_1.encode(),
                'OEBPS/c2.xhtml': CHAPTER_2.encode(),
            },
        )
        book, warnings = load_book(path)
        self.assertEqual(warnings, '')
        self.assertEqual([e.title for e in book.toc], ['Intro'])
        self.assertEqual(book.toc[0].children[0].title, 'Deeper')
        self.assertEqual(book.toc[0].children[0].fragment, 'x')

    def test_without_any_toc_the_index_lists_chapters_by_their_titles(self):
        manifest = [('c1', 'c1.xhtml', XH, ''), ('c2', 'c2.xhtml', XH, '')]
        path = write_epub(
            self.tmp / 'notoc.epub',
            {
                'mimetype': b'application/epub+zip',
                'META-INF/container.xml': CONTAINER_XML.encode(),
                'OEBPS/content.opf': make_opf(manifest, ['c1', 'c2']).encode(),
                'OEBPS/c1.xhtml': CHAPTER_1.encode(),
                'OEBPS/c2.xhtml': CHAPTER_2.encode(),
            },
        )
        book, warnings = load_book(path)
        self.assertEqual((book.toc, warnings), ([], ''))
        page = es.make_index_html(book)
        self.assertIn('>Chapter One</a>', page)
        self.assertIn('>Second Heading</a>', page)

    def test_right_to_left_language_sets_dir(self):
        manifest = [('c1', 'c1.xhtml', XH, '')]
        path = write_epub(
            self.tmp / 'rtl.epub',
            {
                'META-INF/container.xml': CONTAINER_XML.encode(),
                'OEBPS/content.opf': make_opf(manifest, ['c1'], language='ar').encode(),
                'OEBPS/c1.xhtml': CHAPTER_1.encode(),
            },
        )
        book, _ = load_book(path)
        self.assertIn('<html dir="rtl">', es.make_index_html(book))

    def test_not_an_epub_is_a_clean_error(self):
        path = self.tmp / 'junk.epub'
        write_epub(path, {'hello.txt': b'hi'})
        with self.assertRaisesRegex(ValueError, 'no .opf package file was found'):
            es.Book(es.open_source(path))


class LazyTitleTests(TempDirCase):
    class RecordingSource(es.ZipSource):
        def __init__(self, path):
            super().__init__(path)
            self.reads = []

        def read(self, name):
            self.reads.append(name)
            return super().read(name)

    def test_starting_up_does_not_read_any_chapter(self):
        path = write_epub(self.tmp / 'lazy.epub', main_epub_files())
        source = self.RecordingSource(path)
        book = es.Book(source)
        chapters = {'OEBPS/' + h for _, h, m, _ in MAIN_MANIFEST if m != 'text/css'}
        self.assertEqual(chapters & set(source.reads), {'OEBPS/nav.xhtml'})  # only the TOC itself

        before = len(source.reads)
        self.assertEqual(book.title_for('OEBPS/c1.xhtml'), 'Chapter One')
        self.assertEqual(len(source.reads), before + 1)
        self.assertEqual(book.title_for('OEBPS/c1.xhtml'), 'Chapter One')
        self.assertEqual(len(source.reads), before + 1)  # remembered

    def test_title_for_uses_text_it_is_given_instead_of_rereading(self):
        path = write_epub(self.tmp / 'lazy2.epub', main_epub_files())
        source = self.RecordingSource(path)
        book = es.Book(source)
        before = len(source.reads)
        self.assertEqual(book.title_for('OEBPS/c2.xhtml', '<h1>Given</h1>'), 'Given')
        self.assertEqual(len(source.reads), before)

    def test_unreadable_chapters_fall_back_to_the_file_name(self):
        path = write_epub(self.tmp / 'lazy3.epub', main_epub_files())
        book, _ = load_book(path)
        self.assertEqual(book.title_for('OEBPS/drm.xhtml'), 'drm')  # DRM-protected
        self.assertEqual(book.title_for('OEBPS/gone.xhtml'), 'gone')  # missing


class WarningTests(TempDirCase):
    def _epub(self, name, **overrides):
        files = main_epub_files()
        for key, value in overrides.items():
            files[key.replace('__', '/')] = value
        return write_epub(self.tmp / name, files)

    def test_unreadable_toc_warns_and_falls_back(self):
        path = self._epub('badnav.epub', META_INF_unused=b'')  # no-op override, keeps files intact
        files = main_epub_files()
        files['OEBPS/nav.xhtml'] = b'<<< this is not xml'
        write_epub(path, files)
        book, warnings = load_book(path)
        self.assertEqual(book.toc, [])
        self.assertIn('warning: could not read the table of contents', warnings)

    def test_unparseable_encryption_xml_warns_loudly(self):
        files = main_epub_files()
        files['META-INF/encryption.xml'] = b'<encryption><unclosed>'
        path = write_epub(self.tmp / 'badenc.epub', files)
        book, warnings = load_book(path)
        self.assertFalse(book.has_drm)
        self.assertIn('encryption.xml is not valid XML', warnings)

    def test_missing_cover_warns(self):
        files = main_epub_files()
        del files['OEBPS/img/cover.png']
        path = write_epub(self.tmp / 'nocover.epub', files)
        book, warnings = load_book(path)
        self.assertIsNone(book.cover)
        self.assertIn('cover image that is missing', warnings)

    def test_a_healthy_book_is_silent(self):
        path = write_epub(self.tmp / 'healthy.epub', main_epub_files())
        self.assertEqual(load_book(path)[1], '')


# ---------------------------------------------------------------------------
# PDF hosting
# ---------------------------------------------------------------------------


class PdfTests(TempDirCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pdf = b'%PDF-1.4\n' + bytes(range(256)) * 20 + b'\n%%EOF\n'
        cls.lib = cls.tmp / 'lib'
        (cls.lib / 'sub').mkdir(parents=True)
        (cls.lib / 'a.pdf').write_bytes(cls.pdf)
        (cls.lib / 'sub' / 'B é.PDF').write_bytes(cls.pdf[:1000])
        (cls.lib / '.hidden.pdf').write_bytes(cls.pdf)
        (cls.lib / 'notes.txt').write_text('not a pdf')
        (cls.tmp / 'noext').write_bytes(cls.pdf)

    def serve(self, target):
        library = es.PdfLibrary(target)
        srv = Running(quiet_handler(es.PdfHandler, library=library))
        self.addCleanup(srv.close)
        return srv, library

    @staticmethod
    def first_id(page):
        marker = '/pdf/'
        start = page.index(marker) + len(marker)
        return page[start : start + 12]

    # -- single file --------------------------------------------------------

    def test_single_pdf_root_is_the_viewer(self):
        srv, _ = self.serve(self.lib / 'a.pdf')
        page = srv.get('/').body.decode()
        self.assertIn('<object', page)
        self.assertNotIn('Library', page)  # nothing to go back to

    def test_pdf_bytes_headers_and_ranges(self):
        srv, _ = self.serve(self.lib / 'a.pdf')
        pid = self.first_id(srv.get('/').body.decode())
        full = srv.get(f'/pdf/{pid}')
        self.assertEqual((full.status, full.body), (200, self.pdf))
        self.assertEqual(full.headers['content-type'], 'application/pdf')
        self.assertEqual(full.headers['accept-ranges'], 'bytes')
        self.assertTrue(full.headers['content-disposition'].startswith('inline;'))
        self.assertEqual(full.headers['x-content-type-options'], 'nosniff')

        part = srv.get(f'/pdf/{pid}', {'Range': 'bytes=100-199'})
        self.assertEqual((part.status, part.body), (206, self.pdf[100:200]))
        self.assertEqual(part.headers['content-range'], f'bytes 100-199/{len(self.pdf)}')

        tail = srv.get(f'/pdf/{pid}', {'Range': 'bytes=-50'})
        self.assertEqual(tail.body, self.pdf[-50:])

        past = srv.get(f'/pdf/{pid}', {'Range': 'bytes=99999999-'})
        self.assertEqual(past.status, 416)
        self.assertEqual(past.headers['content-range'], f'bytes */{len(self.pdf)}')

    def test_head_and_download(self):
        srv, _ = self.serve(self.lib / 'a.pdf')
        pid = self.first_id(srv.get('/').body.decode())
        head = srv.head(f'/pdf/{pid}')
        self.assertEqual((head.status, head.body), (200, b''))
        self.assertEqual(head.headers['content-length'], str(len(self.pdf)))
        dl = srv.get(f'/dl/{pid}')
        self.assertEqual(dl.status, 200)
        self.assertTrue(dl.headers['content-disposition'].startswith('attachment;'))

    def test_etag_304_and_if_range(self):
        srv, _ = self.serve(self.lib / 'a.pdf')
        pid = self.first_id(srv.get('/').body.decode())
        etag = srv.head(f'/pdf/{pid}').headers['etag']
        self.assertEqual(srv.get(f'/pdf/{pid}', {'If-None-Match': etag}).status, 304)
        stale = srv.get(f'/pdf/{pid}', {'Range': 'bytes=0-9', 'If-Range': '"old"'})
        self.assertEqual((stale.status, stale.body), (200, self.pdf))
        fresh = srv.get(f'/pdf/{pid}', {'Range': 'bytes=0-9', 'If-Range': etag})
        self.assertEqual((fresh.status, fresh.body), (206, self.pdf[:10]))

    def test_unknown_ids_and_traversal_attempts_are_404(self):
        srv, _ = self.serve(self.lib / 'a.pdf')
        for path in (
            '/pdf/000000000000',
            '/pdf/../../etc/passwd',
            '/pdf/%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '/view/zzzzzzzzzzzz',
            '/anything',
        ):
            self.assertEqual(srv.get(path).status, 404, path)

    def test_no_csp_header_on_pdf_pages(self):
        srv, _ = self.serve(self.lib / 'a.pdf')
        self.assertNotIn('content-security-policy', srv.get('/').headers)

    # -- folder library -----------------------------------------------------

    def test_library_lists_pdfs_recursively_skipping_hidden_and_non_pdfs(self):
        srv, _ = self.serve(self.lib)
        page = srv.get('/').body.decode()
        self.assertEqual(page.count('/view/'), 2)
        self.assertIn('sub/B é.PDF', page)
        self.assertNotIn('.hidden', page)
        self.assertNotIn('notes.txt', page)

    def test_library_viewer_has_a_back_link_and_serves_every_file(self):
        srv, library = self.serve(self.lib)
        entries = library.scan()
        self.assertIn('Library', srv.get(f'/view/{entries[0].id}').body.decode())
        for entry in entries:
            r = srv.get(f'/pdf/{entry.id}')
            self.assertEqual(r.body, entry.path.read_bytes())

    def test_library_rescans_on_every_request(self):
        folder = self.tmp / 'growing'
        folder.mkdir()
        srv, _ = self.serve(folder)
        self.assertIn('No PDF files found', srv.get('/').body.decode())
        (folder / 'new.pdf').write_bytes(self.pdf)
        self.assertEqual(srv.get('/').body.decode().count('/view/'), 1)

    def test_unicode_filenames_produce_valid_headers(self):
        srv, library = self.serve(self.lib)
        entry = next(e for e in library.scan() if e.name.startswith('sub/'))
        r = srv.get(f'/dl/{entry.id}')
        self.assertEqual(r.status, 200)
        r.headers['content-disposition'].encode('ascii')

    def test_ids_are_stable_and_distinct(self):
        _, library = self.serve(self.lib)
        first = [e.id for e in library.scan()]
        self.assertEqual(first, [e.id for e in library.scan()])
        self.assertEqual(len(set(first)), len(first))

    # -- mode detection -----------------------------------------------------

    def test_detect_mode(self):
        self.assertEqual(es.detect_mode(self.lib / 'a.pdf'), 'pdf')
        self.assertEqual(es.detect_mode(self.tmp / 'noext'), 'pdf')  # by magic bytes
        self.assertEqual(es.detect_mode(self.lib), 'pdf')
        epub = write_epub(self.tmp / 'mode.epub', main_epub_files())
        self.assertEqual(es.detect_mode(epub), 'epub')
        empty = self.tmp / 'empty'
        empty.mkdir()
        self.assertEqual(es.detect_mode(empty), 'epub')

    def test_extracted_epub_folder_containing_a_pdf_is_still_an_epub(self):
        folder = self.tmp / 'epub_with_pdf'
        (folder / 'META-INF').mkdir(parents=True)
        (folder / 'META-INF' / 'container.xml').write_bytes(CONTAINER_XML.encode())
        (folder / 'handout.pdf').write_bytes(self.pdf)
        self.assertEqual(es.detect_mode(folder), 'epub')


# ---------------------------------------------------------------------------
# the real command line
# ---------------------------------------------------------------------------


class BrowserCompatibilityTests(TempDirCase):
    CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36'
    AGENTS = {
        'modern_chrome': CHROME.format(v=120),
        'old_chrome': CHROME.format(v=70),
        'modern_edge': CHROME.format(v=120) + ' Edg/120.0.0.0',
        'legacy_edge': CHROME.format(v=64) + ' Edge/18.19582',
        'ie11': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'ie9': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
        'modern_firefox': 'Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0',
        'old_firefox': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
        'modern_safari': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'old_safari': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.8 (KHTML, like Gecko) Version/9.1.3 Safari/601.7.8',
        'iphone': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
        'old_iphone': 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Mobile/15E148 Safari/604.1',
        'ios_chrome': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1',
        'android_chrome': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'samsung_old': 'Mozilla/5.0 (Linux; Android 9; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.2 Chrome/67.0.3396.87 Mobile Safari/537.36',
        'mystery': 'Mozilla/5.0 (X11; Linux) NewBrowser/1.0',
        'text_mode': 'Lynx/2.9.0 libwww-FM/2.14',
        'opera_mini': 'Opera/9.80 (Android; Opera Mini/36.2.2254/119.132; U; en) Presto/2.12.423 Version/12.16',
        'curl': 'curl/8.4.0',
        'script': 'python-requests/2.31',
        'crawler': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    }

    def notice(self, name, for_pdf=False):
        return es.assess_browser(self.AGENTS[name], for_pdf)

    def test_current_browsers_get_no_warning(self):
        for name in (
            'modern_chrome',
            'modern_edge',
            'modern_firefox',
            'modern_safari',
            'iphone',
            'ios_chrome',
            'android_chrome',
        ):
            self.assertIsNone(self.notice(name), name)

    def test_non_browsers_and_missing_user_agents_get_no_warning(self):
        for name in ('curl', 'script', 'crawler'):
            self.assertIsNone(self.notice(name, True), name)
        self.assertIsNone(es.assess_browser(None))
        self.assertIsNone(es.assess_browser('   '))

    def test_outdated_browsers_are_named_with_versions(self):
        self.assertIn('Chrome 70', self.notice('old_chrome'))
        self.assertIn('Chrome 84', self.notice('old_chrome'))
        self.assertIn('Firefox 60', self.notice('old_firefox'))
        self.assertIn('Safari 9', self.notice('old_safari'))
        self.assertIn('Samsung Internet 9', self.notice('samsung_old'))
        self.assertIn('iOS 12', self.notice('old_iphone'))
        self.assertIn('Internet Explorer', self.notice('ie11'))
        self.assertIn('Internet Explorer', self.notice('ie9'))
        self.assertIn('old, pre-2020 Microsoft Edge', self.notice('legacy_edge'))
        for name in ('old_chrome', 'ie11', 'legacy_edge'):
            self.assertIn('you can keep going', self.notice(name))

    def test_unknown_browsers_get_a_may_not_work_notice(self):
        self.assertIn("isn't one this page has been tested with", self.notice('mystery'))
        self.assertIn('unusual or text-mode browser', self.notice('opera_mini'))
        self.assertIn('unusual or text-mode browser', es.assess_browser('Netsurf/3.10'))

    def test_pdf_pages_add_a_note_for_phones_and_ie(self):
        for name in ('iphone', 'android_chrome', 'ios_chrome'):
            self.assertIsNone(self.notice(name, False), name)
            note = self.notice(name, True)
            self.assertIn('often cannot show a PDF inside a page', note, name)
            self.assertIn('Open in new tab', note)
        self.assertIsNone(self.notice('modern_chrome', True))
        self.assertIn('no built-in PDF viewer', self.notice('ie11', True))

    def test_the_banner_never_repeats_the_user_agent_and_is_escaped(self):
        evil = 'Mozilla/5.0 <script>alert(1)</script> Chrome/5.0 evil.example'
        notice = es.assess_browser(evil)
        self.assertIn('Chrome 5', notice)
        self.assertNotIn('<script>', notice)
        self.assertNotIn('evil.example', notice)
        self.assertEqual(es.compat_banner(None), '')
        self.assertNotIn('<b>', es.compat_banner('<b>x</b>'))

    def test_oversized_user_agents_are_handled(self):
        import time

        start = time.monotonic()
        # Only the first 500 characters are examined, so this is quick and just "unrecognised".
        huge = es.assess_browser('Mozilla/5.0 ' + 'a' * 10**6 + ' Chrome/120.0')
        self.assertLess(time.monotonic() - start, 1)
        self.assertIn("isn't one this page has been tested with", huge)
        # a real browser string with the token inside the examined part is still understood
        self.assertIsNone(es.assess_browser('Mozilla/5.0 Chrome/120.0 ' + 'a' * 10**6))

    def serve_epub(self):
        book, _ = load_book(write_epub(self.tmp / 'compat.epub', main_epub_files()))
        srv = Running(quiet_handler(es.ReaderHandler, book=book, csp=es.build_csp()))
        self.addCleanup(srv.close)
        return srv

    def test_epub_index_shows_the_warning_only_to_old_or_unknown_browsers(self):
        srv = self.serve_epub()
        for name, warned in (
            ('old_chrome', True),
            ('ie11', True),
            ('mystery', True),
            ('modern_chrome', False),
            ('curl', False),
        ):
            r = srv.get('/', {'User-Agent': self.AGENTS[name]})
            self.assertEqual(r.status, 200, name)
            self.assertEqual(b'class="compat"' in r.body, warned, name)
            self.assertIn(b'Test Book', r.body, name)  # the page itself is always served in full
        self.assertNotIn(b'class="compat"', srv.get('/').body)  # no User-Agent at all

    def test_warned_pages_vary_by_user_agent_and_chapters_are_never_touched(self):
        srv = self.serve_epub()
        index = srv.get('/', {'User-Agent': self.AGENTS['old_chrome']})
        self.assertEqual(index.headers['vary'], 'User-Agent')
        self.assertEqual(index.headers['cache-control'], 'no-cache')
        old = srv.get('/book/OEBPS/c1.xhtml', {'User-Agent': self.AGENTS['ie11']})
        new = srv.get('/book/OEBPS/c1.xhtml', {'User-Agent': self.AGENTS['modern_chrome']})
        self.assertEqual(old.body, new.body)
        self.assertNotIn(b'compat', old.body)

    def serve_pdfs(self, single):
        root = self.tmp / ('onepdf' if single else 'manypdf')
        root.mkdir(exist_ok=True)
        (root / 'a.pdf').write_bytes(b'%PDF-1.4 a')
        (root / 'b.pdf').write_bytes(b'%PDF-1.4 b')
        library = es.PdfLibrary(root / 'a.pdf' if single else root)
        srv = Running(quiet_handler(es.PdfHandler, library=library))
        self.addCleanup(srv.close)
        return srv, library

    def test_pdf_pages_warn_phones_and_old_browsers(self):
        for single in (True, False):
            srv, library = self.serve_pdfs(single)
            pages = ['/'] if single else ['/', '/view/' + library.scan()[0].id]
            for page in pages:
                phone = srv.get(page, {'User-Agent': self.AGENTS['android_chrome']})
                self.assertIn(b'often cannot show a PDF', phone.body, page)
                self.assertIn(b'Open in new tab', phone.body, page)
                self.assertEqual(phone.headers['vary'], 'User-Agent')
                ie = srv.get(page, {'User-Agent': self.AGENTS['ie11']})
                self.assertIn(b'no built-in PDF viewer', ie.body, page)
                desktop = srv.get(page, {'User-Agent': self.AGENTS['modern_chrome']})
                self.assertNotIn(b'class="compat"', desktop.body, page)

    def test_pdf_files_themselves_are_unaffected_by_the_user_agent(self):
        srv, library = self.serve_pdfs(False)
        entry = library.scan()[0]
        a = srv.get(f'/pdf/{entry.id}', {'User-Agent': self.AGENTS['ie11']})
        b = srv.get(f'/pdf/{entry.id}', {'User-Agent': self.AGENTS['modern_chrome']})
        self.assertEqual(a.body, b.body)
        self.assertNotIn('vary', a.headers)


class CompatibilityTests(TempDirCase):
    """Things that are legal but unusual, or that this tool can't read, are reported plainly."""

    def book_with(self, name, mutate):
        files = main_epub_files()
        mutate(files)
        return load_book(write_epub(self.tmp / f'{name}.epub', files))

    def opf(self, files, old, new):
        files['OEBPS/content.opf'] = files['OEBPS/content.opf'].decode().replace(old, new).encode()

    def test_a_tidy_book_produces_no_warnings(self):
        _, err = self.book_with('tidy', lambda f: None)
        self.assertEqual(err, '')

    def test_missing_or_wrong_mimetype_file_warns(self):
        _, err = self.book_with('nomime', lambda f: f.pop('mimetype'))
        self.assertIn("no 'mimetype' file", err)
        _, err = self.book_with('badmime', lambda f: f.update(mimetype=b'text/plain'))
        self.assertIn('does not say application/epub+zip', err)

    def test_unknown_or_missing_package_version_warns(self):
        _, err = self.book_with('v9', lambda f: self.opf(f, 'version="3.0"', 'version="9.1"'))
        self.assertIn('EPUB version 9.1 is not one this tool knows', err)
        _, err = self.book_with('v0', lambda f: self.opf(f, ' version="3.0"', ''))
        self.assertIn('declares no EPUB version', err)
        _, err = self.book_with('v2', lambda f: self.opf(f, 'version="3.0"', 'version="2.0"'))
        self.assertEqual(err, '')

    def test_fixed_layout_book_warns(self):
        meta = '<meta property="rendition:layout">pre-paginated</meta>'
        _, err = self.book_with('fxl', lambda f: self.opf(f, '</metadata>', meta + '</metadata>'))
        self.assertIn('fixed-layout', err)

    def test_non_html_reading_order_items_are_reported_once(self):
        def mutate(files):
            self.opf(
                files, '<itemref idref="c1"/>', '<itemref idref="cover"/><itemref idref="c1"/>'
            )

        book, err = self.book_with('imgspine', mutate)
        self.assertEqual(err.count('not HTML pages'), 1)
        self.assertIn('img/cover.png', err)

    def test_password_protected_zip_entries_are_reported_not_crashed(self):
        entry = zipfile.ZipInfo('OEBPS/c1.xhtml')
        entry.flag_bits |= 0x1
        book, _ = load_book(write_epub(self.tmp / 'zipenc.epub', main_epub_files()))
        zf = book.source._zf
        info = zf.getinfo('OEBPS/c1.xhtml')
        info.flag_bits |= 0x1  # pretend the entry is encrypted
        with self.assertRaises(es.UnsupportedContentError):
            book.source.read('OEBPS/c1.xhtml')
        srv = Running(quiet_handler(es.ReaderHandler, book=book, csp=es.build_csp()))
        self.addCleanup(srv.close)
        r = srv.get('/book/OEBPS/c1.xhtml')
        self.assertEqual(r.status, 415)
        self.assertIn(b'password-protected', r.body)
        info.flag_bits &= ~0x1

    def test_unsupported_zip_compression_is_reported(self):
        book, _ = load_book(write_epub(self.tmp / 'zipcomp.epub', main_epub_files()))
        info = book.source._zf.getinfo('OEBPS/c1.xhtml')
        info.compress_type = 99  # not a method the zip library knows
        with self.assertRaisesRegex(es.UnsupportedContentError, 'compression'):
            book.source.read('OEBPS/c1.xhtml')

    def test_foreign_formats_are_recognised_by_their_first_bytes(self):
        cases = {
            'a.mobi': (b'x' * 60 + b'BOOKMOBI' + b'x' * 20, 'Kindle'),
            'a.rar': (b'Rar!\x1a\x07\x00', 'archive'),
            'a.chm': (b'ITSF\x03\x00', 'CHM'),
            'a.fb2': (b'<?xml version="1.0"?><FictionBook>', 'FB2'),
            'a.txt': (b'hello', None),
        }
        for name, (data, expected) in cases.items():
            path = self.tmp / name
            path.write_bytes(data)
            found = es.foreign_format(path)
            if expected is None:
                self.assertIsNone(found, name)
            else:
                self.assertIn(expected, found, name)

    def test_command_line_explains_unreadable_inputs(self):
        junk = self.tmp / 'junk.epub'
        junk.write_bytes(b'this is not a zip file at all')
        mobi = self.tmp / 'book.epub'
        mobi.write_bytes(b'x' * 60 + b'BOOKMOBI' + b'x' * 100)
        for path, expected in ((junk, 'not a readable zip file'), (mobi, 'Kindle/Mobipocket')):
            r = run_script(str(path), '--no-browser')
            self.assertNotEqual(r.returncode, 0)
            self.assertIn(expected, r.stderr)
            self.assertNotIn('Traceback', r.stderr)

    def test_port_must_be_a_real_port(self):
        for bad in ('0', '70000', 'abc', '-5'):
            r = run_script(str(self.tmp / 'junk.epub'), '--port', bad, '--no-browser')
            self.assertEqual(r.returncode, 2, bad)
            self.assertIn('port', r.stderr)
        self.assertEqual(es.port_number('8080'), 8080)

    def test_ipv6_loopback_is_served_when_the_machine_supports_it(self):
        if not socket.has_ipv6:
            self.skipTest('no IPv6 here')
        epub = write_epub(self.tmp / 'v6.epub', main_epub_files())
        port = free_port()
        proc = subprocess.Popen(
            [
                sys.executable,
                '-I',
                str(SCRIPT),
                str(epub),
                '--host',
                '::1',
                '--port',
                str(port),
                '--no-browser',
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for _ in range(50):
                try:
                    socket.create_connection(('::1', port), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                self.skipTest('could not use ::1 in this environment')
            conn = HTTPConnection('::1', port, timeout=5)
            conn.request('GET', '/', headers={'Host': f'[::1]:{port}'})
            self.assertEqual(conn.getresponse().status, 200)
        finally:
            proc.terminate()
            out, err = proc.communicate(timeout=5)
        self.assertIn(f'http://[::1]:{port}/', out)

    def test_unusable_listen_addresses_get_a_plain_explanation(self):
        epub = write_epub(self.tmp / 'badhost.epub', main_epub_files())
        for host, expected in (
            ('203.0.113.7', 'cannot listen on'),
            ('no such host', 'not an address'),
        ):
            r = run_script(str(epub), '--host', host, '--port', str(free_port()))
            self.assertNotEqual(r.returncode, 0, host)
            self.assertIn(expected, r.stderr, host)
            self.assertNotIn('Traceback', r.stderr, host)

    def test_wildcard_host_prints_usable_links_not_0_0_0_0(self):
        epub = write_epub(self.tmp / 'lan.epub', main_epub_files())
        cli = Cli(epub, '--host', '0.0.0.0')
        try:
            cli.get('/')
        finally:
            out, err = cli.stop()
        self.assertIn(f'serving at http://localhost:{cli.port}/ on this device', out)
        self.assertNotIn('http://0.0.0.0', out)
        self.assertIn('on your network, open', out)

    def test_lan_addresses_skip_loopback_and_link_local_and_repeats(self):
        class FakeProbe:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def connect(self, addr):
                pass

            def getsockname(self):
                return ('192.168.1.23', 5)

        with mock.patch.object(es.socket, 'socket', return_value=FakeProbe()), mock.patch.object(
            es.socket,
            'gethostbyname_ex',
            return_value=('h', [], ['127.0.0.1', '169.254.3.3', '192.168.1.23', '10.0.0.5']),
        ):
            self.assertEqual(es.lan_addresses(), ['192.168.1.23', '10.0.0.5'])
        with mock.patch.object(es.socket, 'socket', side_effect=OSError), mock.patch.object(
            es.socket, 'gethostbyname_ex', side_effect=OSError
        ):
            self.assertEqual(es.lan_addresses(), [])

    def test_old_python_gets_a_clear_message(self):
        source = SCRIPT.read_text()
        head = source.split('import argparse')[0]
        self.assertIn('needs Python 3.7 or newer', head)
        self.assertLess(head.index('sys.version_info'), source.index('import argparse'))


class CachePoisoningTests(TempDirCase):
    """Nothing in a request may change what another request gets from the cache."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.book, _ = load_book(write_epub(cls.tmp / 'cp.epub', main_epub_files()))
        cls.srv = Running(
            quiet_handler(
                es.ReaderHandler,
                book=cls.book,
                csp=es.build_csp(),
                chapter_cache=es.ByteLRU(es.CHAPTER_CACHE_BYTES),
                allowed_hosts=es.allowed_host_names('127.0.0.1'),
            )
        )

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        super().tearDownClass()

    def test_request_headers_and_query_never_change_the_body(self):
        url = '/book/OEBPS/c1.xhtml'
        expected = self.srv.get(url)
        variants = [
            (url, {'X-Forwarded-Host': 'evil.example'}),
            (url, {'X-Original-URL': '/other'}),
            (url, {'Cookie': 'a=b', 'Accept-Language': 'zz'}),
            (url, {'User-Agent': '<script>alert(1)</script>'}),
            (url + '?x=<script>', {}),
            (url + '?a=1&a=2', {}),
            (url, {'Range': 'bytes=0-5'}),
        ]
        for path, headers in variants:
            r = self.srv.get(path, headers)
            self.assertEqual(r.body, expected.body, (path, headers))
            self.assertEqual(r.headers['etag'], expected.headers['etag'])
            self.assertNotIn(b'evil.example', r.body)

    def test_responses_must_be_revalidated_and_never_reflect_input(self):
        r = self.srv.get('/book/OEBPS/c1.xhtml')
        self.assertEqual(r.headers['cache-control'], 'no-cache')
        self.assertNotIn('vary', r.headers)

    def test_wrong_etag_never_yields_a_stale_304(self):
        url = '/book/OEBPS/c1.xhtml'
        good = self.srv.get(url).headers['etag']
        self.assertEqual(self.srv.get(url, {'If-None-Match': good}).status, 304)
        self.assertEqual(self.srv.get(url, {'If-None-Match': '"nope"'}).status, 200)
        # an ETag from one file must not validate another
        self.assertEqual(self.srv.get('/book/OEBPS/c2.xhtml', {'If-None-Match': good}).status, 200)

    def test_concurrent_requests_all_get_identical_bodies(self):
        url = '/book/OEBPS/c1.xhtml'
        expected = self.srv.get(url).body
        bad = []

        def worker():
            for _ in range(25):
                if self.srv.get(url).body != expected:
                    bad.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(bad, [])

    def test_path_tricks_never_reach_other_content(self):
        for path in (
            '/book/../../etc/passwd',
            '/book/%2e%2e/%2e%2e/etc/passwd',
            '/book/OEBPS/..%2f..%2fMETA-INF/container.xml',
            '/book/OEBPS/c1.xhtml%00.png',
            '/book/OEBPS\\c1.xhtml',
        ):
            self.assertEqual(self.srv.get(path).status, 404, path)
        for path in (
            '/book/OEBPS/./drm.xhtml',
            '/book/OEBPS/x/../drm.xhtml',
            '/book/OEBPS/%64rm.xhtml',
        ):
            self.assertEqual(self.srv.get(path).status, 403, path)

    def test_oversized_and_excessive_headers_are_rejected(self):
        for raw, code in (
            (b'GET / HTTP/1.1\r\nHost: localhost\r\nX: ' + b'a' * 70000 + b'\r\n\r\n', b'431'),
            (b'GET / HTTP/1.1\r\nHost: localhost\r\n' + b'H: 1\r\n' * 150 + b'\r\n', b'431'),
        ):
            with socket.create_connection(('127.0.0.1', self.srv.port), timeout=5) as s:
                s.sendall(raw)
                self.assertIn(code, s.recv(100))


class ReviewFollowUpTests(TempDirCase):
    """Findings from an outside code review, each checked against the real behaviour."""

    def test_unnamespaced_toc_does_not_duplicate_nested_entries(self):
        files = main_epub_files()
        files['OEBPS/nav.xhtml'] = (
            b'<html><body><nav epub:type="toc" xmlns:epub="http://www.idpf.org/2007/ops"><ol>'
            b'<li><a href="c1.xhtml">Ch 1</a><ol><li><a href="c2.xhtml">Sec 1.1</a></li></ol></li>'
            b'</ol></nav></body></html>'
        )
        book, _ = load_book(write_epub(self.tmp / 'plain_toc.epub', files))
        flat = []

        def walk(entries):
            for e in entries:
                flat.append(e.title)
                walk(e.children)

        walk(book.toc)
        self.assertEqual(flat, ['Ch 1', 'Sec 1.1'])

    def _book_with_container(self, name, container, drop=(), as_folder=False):
        files = main_epub_files()
        files.pop('META-INF/container.xml')
        if container is not None:
            files['META-INF/container.xml'] = container
        for d in drop:
            files.pop(d)
        if as_folder:
            folder = self.tmp / name
            for n, data in files.items():
                target = folder / n
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            return load_book(folder)
        return load_book(write_epub(self.tmp / f'{name}.epub', files))

    CONTAINER_HEAD = (
        b'<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles>'
    )

    def test_missing_container_xml_falls_back_to_finding_the_opf(self):
        for as_folder in (False, True):
            book, err = self._book_with_container(f'nocont{as_folder}', None, as_folder=as_folder)
            self.assertEqual(book.opf_path, 'OEBPS/content.opf')
            self.assertEqual(book.title, 'Test Book')
            self.assertIn('container.xml is missing', err)
            self.assertIn('using OEBPS/content.opf', err)

    def test_container_pointing_at_a_missing_file_falls_back(self):
        bad = self.CONTAINER_HEAD + b'<rootfile full-path="nope/gone.opf"/></rootfiles></container>'
        book, err = self._book_with_container('ghost', bad)
        self.assertEqual(book.opf_path, 'OEBPS/content.opf')
        self.assertIn('does not point to a package file that exists', err)

    def test_rootfile_without_full_path_or_broken_container_falls_back(self):
        for name, data in (
            ('nofp', self.CONTAINER_HEAD + b'<rootfile media-type="x"/></rootfiles></container>'),
            ('empty', self.CONTAINER_HEAD + b'</rootfiles></container>'),
            ('garbage', b'<container><unclosed>'),
        ):
            book, err = self._book_with_container(name, data)
            self.assertEqual(book.opf_path, 'OEBPS/content.opf', name)
            self.assertIn('using OEBPS/content.opf', err, name)

    def test_a_later_valid_rootfile_is_used_before_any_search(self):
        two = (
            self.CONTAINER_HEAD
            + b'<rootfile full-path="nope.opf"/><rootfile full-path="OEBPS/content.opf"/>'
            + b'</rootfiles></container>'
        )
        book, err = self._book_with_container('two', two)
        self.assertEqual(book.opf_path, 'OEBPS/content.opf')
        self.assertEqual(err, '')

    def test_no_opf_anywhere_falls_back_to_listing_the_pages(self):
        for as_folder in (False, True):
            book, err = self._book_with_container(
                f'noopf{as_folder}', None, drop=('OEBPS/content.opf',), as_folder=as_folder
            )
            self.assertIsNone(book.opf_path)
            self.assertIn('no .opf package file was found', err)
            names = [posixpath.basename(unicodedata.normalize('NFC', p)) for p in book.spine]
            self.assertEqual(
                names,
                [
                    'big.xhtml',
                    'c1.xhtml',
                    'c2.xhtml',
                    'c3.html',
                    'café.xhtml',
                    'drm.xhtml',
                    'nav.xhtml',
                ],
            )

    def test_opf_search_prefers_the_shallowest_and_skips_hidden_folders(self):
        folder = self.tmp / 'search'
        (folder / '.hidden').mkdir(parents=True)
        (folder / '.hidden' / 'a.opf').write_text('x')
        (folder / 'deep' / 'er').mkdir(parents=True)
        (folder / 'deep' / 'er' / 'z.opf').write_text('x')
        (folder / 'deep' / 'm.OPF').write_text('x')
        self.assertEqual(es.DirSource(folder).find_opf_names(), ['deep/m.OPF', 'deep/er/z.opf'])

    def test_no_opf_lists_html_pages_sorted_by_name(self):
        files = {
            'page10.html': b'<html><head><title>Ten</title></head><body><p>ten</p></body></html>',
            'Page2.HTM': b'<html><body><h1>Two</h1></body></html>',
            'sub/a.xhtml': b'<html xmlns="http://www.w3.org/1999/xhtml"><body>a</body></html>',
            'style.css': b'p{color:red}',
            'notes.txt': b'skip me',
            'META-INF/skip.html': b'<html><body>no</body></html>',
        }
        for as_folder in (False, True):
            name = f'loose{as_folder}'
            if as_folder:
                folder = self.tmp / name
                for n, data in files.items():
                    (folder / n).parent.mkdir(parents=True, exist_ok=True)
                    (folder / n).write_bytes(data)
                src = folder
            else:
                src = write_epub(self.tmp / f'{name}.epub', files)
            book, err = load_book(src)
            self.assertEqual(book.spine, ['Page2.HTM', 'page10.html', 'sub/a.xhtml'])
            self.assertEqual(book.title, name if as_folder else name)
            self.assertIn('listing the 3 HTML page(s) by name', err)
            self.assertEqual(book.toc, [])
            index = es.make_index_html(book)
            for title in ('Two', 'Ten'):
                self.assertIn(title, index)
            self.assertLess(index.index('Two'), index.index('Ten'))
            srv = Running(quiet_handler(es.ReaderHandler, book=book, csp=es.build_csp()))
            self.addCleanup(srv.close)
            r = srv.get('/book/page10.html')
            self.assertEqual(r.status, 200)
            self.assertIn(b'__reader_nav', r.body)
            self.assertEqual(srv.get('/book/style.css').status, 200)

    def test_no_opf_and_no_pages_means_not_an_epub(self):
        path = write_epub(self.tmp / 'nothing.epub', {'a.txt': b'x', 'b.png': b'x'})
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'no .html/.htm/.xhtml pages were found'):
                es.Book(es.open_source(path))

    def test_natural_sort_key(self):
        names = ['p10.html', 'P2.html', 'p1.html', 'a/p1.html']
        self.assertEqual(
            sorted(names, key=es.natural_sort_key),
            ['a/p1.html', 'p1.html', 'P2.html', 'p10.html'],
        )

    def test_folder_with_pdfs_and_an_opf_is_still_an_epub(self):
        folder = self.tmp / 'mixed'
        (folder / 'OEBPS').mkdir(parents=True)
        (folder / 'OEBPS' / 'content.opf').write_text('x')
        (folder / 'a.pdf').write_bytes(b'%PDF-1.4 x')
        self.assertEqual(es.detect_mode(folder), 'epub')

    def test_blank_title_falls_back_to_h1_and_corrupt_chapter_to_filename(self):
        files = main_epub_files()
        files['OEBPS/c1.xhtml'] = (
            b'<html><head><title>   </title></head><body><h1>Real</h1></body></html>'
        )
        book, _ = load_book(write_epub(self.tmp / 'blank.epub', files))
        self.assertEqual(book.title_for('OEBPS/c1.xhtml'), 'Real')
        with mock.patch.object(book, 'read_resource', side_effect=zipfile.BadZipFile('crc')):
            self.assertEqual(book.title_for('OEBPS/c2.xhtml'), 'c2')

    def test_nav_bar_still_finds_the_chapter_under_another_unicode_spelling(self):
        book, _ = load_book(write_epub(self.tmp / 'nfdnav.epub', main_epub_files()))
        nfc = 'OEBPS/café.xhtml'
        nfd = unicodedata.normalize('NFD', nfc)
        self.assertEqual(es.make_nav_bar(book, nfd), es.make_nav_bar(book, nfc))
        self.assertIn('Prev', es.make_nav_bar(book, nfd))

    def test_log_line_neutralises_escape_sequences_in_the_method(self):
        handler = quiet_handler(es.ReaderHandler, book=None)
        h = handler.__new__(handler)
        h.verbose, h.command, h.path = True, '\x1b[31mGET', '/\x1b]52;c;x\x07'
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            es.ReaderHandler.log_request(h, 404)
        self.assertNotIn('\x1b', err.getvalue())
        self.assertNotIn('\x07', err.getvalue())

    def test_failed_request_log_names_the_page_that_asked_for_it(self):
        handler = quiet_handler(es.ReaderHandler, book=None)
        h = handler.__new__(handler)
        h.verbose, h.command, h.path = False, 'GET', '/book/OEBPS/missing.css'
        for referer, expected in (
            ('http://127.0.0.1:8000/book/OEBPS/c%201.xhtml', 'requested by /book/OEBPS/c 1.xhtml'),
            ('http://evil.example/secret?token=1', None),
            (None, None),
        ):
            h.headers = {'Host': '127.0.0.1:8000'}
            if referer:
                h.headers['Referer'] = referer
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                es.ReaderHandler.log_request(h, 404)
            line = err.getvalue()
            self.assertIn('404 GET /book/OEBPS/missing.css', line)
            if expected:
                self.assertIn(expected, line)
            else:
                self.assertNotIn('requested by', line)
                self.assertNotIn('evil', line)

    def test_log_line_survives_a_request_that_never_got_its_headers_parsed(self):
        handler = quiet_handler(es.ReaderHandler, book=None)
        h = handler.__new__(handler)  # no .headers, as after a malformed request line
        h.verbose, h.command = False, None  # no .path either
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            es.ReaderHandler.log_request(h, 400)
        self.assertIn('400', err.getvalue())

    def test_missing_resource_is_reported_when_a_page_loads_it_for_real(self):
        files = main_epub_files()
        files['OEBPS/c1.xhtml'] = (
            b'<html xmlns="http://www.w3.org/1999/xhtml"><head><title>x</title>'
            b'<link rel="stylesheet" href="nope.css"/></head><body>hi</body></html>'
        )
        epub = write_epub(self.tmp / 'brokenref.epub', files)
        cli = Cli(epub)
        try:
            page = cli.get('/book/OEBPS/c1.xhtml')
            cli.get(
                '/book/OEBPS/nope.css',
                {'Referer': f'http://127.0.0.1:{cli.port}/book/OEBPS/c1.xhtml'},
            )
        finally:
            out, err = cli.stop()
        self.assertEqual(page.status, 200)
        self.assertIn('404 GET /book/OEBPS/nope.css  (requested by /book/OEBPS/c1.xhtml)', err)

    def test_stream_failure_after_headers_closes_the_connection(self):
        class Boom:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def seek(self, n):
                pass

            def read(self, n):
                raise zipfile.BadZipFile('crc mismatch')

        handler = quiet_handler(es.ReaderHandler, book=None, csp=None)
        h = handler.__new__(handler)
        h.headers, h._head_only, h.close_connection = {}, False, False
        h.send_response = h.send_header = h.end_headers = lambda *a, **k: None
        h._send_common_headers = lambda *a, **k: None
        h.wfile = io.BytesIO()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            h._send_stream(Boom(), 100, 'video/mp4', '"e"')
        self.assertTrue(h.close_connection)
        self.assertEqual(h.wfile.getvalue(), b'')  # no second (500) response appended
        self.assertIn('stream failed', err.getvalue())

    def test_security_warnings_go_to_stderr(self):
        epub = write_epub(self.tmp / 'warnflags.epub', main_epub_files())
        cli = Cli(epub, '--allow-scripts')
        try:
            cli.get('/')
        finally:
            out, err = cli.stop()
        self.assertIn('scripts inside the book', err)
        self.assertNotIn('scripts inside the book', out)

    def test_deep_toc_warns_once_about_truncation(self):
        deep = es.MAX_TOC_DEPTH + 3
        nav = (
            '<html xmlns="http://www.w3.org/1999/xhtml"><body><nav><ol>'
            + '<li><a href="c1.xhtml">x</a><ol>' * deep
            + '</ol></li>' * deep
            + '</ol></nav></body></html>'
        )
        files = main_epub_files()
        files['OEBPS/nav.xhtml'] = nav.encode()
        _, err = load_book(write_epub(self.tmp / 'deepwarn.epub', files))
        self.assertEqual(err.count('nests deeper'), 1)


class HardeningTests(TempDirCase):
    """Hostile inputs: nothing here may hang, leak, or bypass a protection."""

    def test_scanners_stay_fast_on_pathological_input(self):
        import time

        for hostile in ('<!--' * 100000, '<body' * 100000, '<![CDATA[' * 50000, '<' * 300000):
            start = time.monotonic()
            es.first_real_element_text(hostile, 'title')
            es.first_real_tag(hostile, 'body')
            self.assertLess(time.monotonic() - start, 3, hostile[:10])

    def test_drm_cannot_be_bypassed_by_an_alternate_unicode_spelling(self):
        files = main_epub_files()
        path = write_epub(self.tmp / 'nfd.epub', files)
        book, _ = load_book(path)
        self.assertTrue(book.is_drm('OEBPS/drm.xhtml'))
        accent = 'OEBPS/café.xhtml'
        for form in ('NFC', 'NFD'):
            self.assertEqual(
                book._key(unicodedata.normalize(form, accent)), book._key(accent), form
            )

    def test_drm_chapter_in_nfd_spelling_is_still_refused(self):
        files = main_epub_files()
        enc = files['META-INF/encryption.xml'].decode()
        files['OEBPS/café2.xhtml'] = CHAPTER_DRM.encode()
        files['META-INF/encryption.xml'] = enc.replace(
            'OEBPS/drm.xhtml', unicodedata.normalize('NFC', 'OEBPS/café2.xhtml')
        ).encode()
        files.pop('OEBPS/drm.xhtml')
        book, _ = load_book(write_epub(self.tmp / 'nfd2.epub', files))
        for form in ('NFC', 'NFD'):
            self.assertTrue(book.is_drm(unicodedata.normalize(form, 'OEBPS/café2.xhtml')), form)

    def test_entity_declarations_in_xml_are_refused(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>'
        with self.assertRaises(Exception):
            es.parse_xml(bomb)
        files = main_epub_files()
        files['OEBPS/content.opf'] = bomb
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(Exception):
                es.Book(es.open_source(write_epub(self.tmp / 'bomb.epub', files)))

    def test_extracted_folder_never_serves_hidden_files(self):
        folder = self.tmp / 'hiddenbook'
        for name, data in main_epub_files().items():
            target = folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (folder / 'OEBPS' / '.secret.txt').write_text('top secret')
        (folder / '.git').mkdir()
        (folder / '.git' / 'config').write_text('token')
        book, _ = load_book(folder)
        srv = Running(quiet_handler(es.ReaderHandler, book=book, csp=es.build_csp()))
        self.addCleanup(srv.close)
        self.assertEqual(srv.get('/book/OEBPS/.secret.txt').status, 404)
        self.assertEqual(srv.get('/book/.git/config').status, 404)
        self.assertEqual(srv.get('/book/OEBPS/style.css').status, 200)

    def test_foreign_host_header_is_refused_when_hosts_are_restricted(self):
        book, _ = load_book(write_epub(self.tmp / 'host.epub', main_epub_files()))
        srv = Running(
            quiet_handler(
                es.ReaderHandler,
                book=book,
                csp=es.build_csp(),
                allowed_hosts=es.allowed_host_names('127.0.0.1'),
            )
        )
        self.addCleanup(srv.close)
        self.assertEqual(srv.get('/', {'Host': 'localhost:1'}).status, 200)
        self.assertEqual(srv.get('/', {'Host': '127.0.0.1'}).status, 200)
        self.assertEqual(srv.get('/', {'Host': 'evil.example'}).status, 403)

    def test_internal_errors_do_not_leak_details(self):
        book, _ = load_book(write_epub(self.tmp / 'boom.epub', main_epub_files()))

        def boom(*args, **kwargs):
            raise RuntimeError('SECRET-PATH /etc/shadow')

        book.read_resource = boom
        srv = Running(quiet_handler(es.ReaderHandler, book=book, csp=es.build_csp()))
        self.addCleanup(srv.close)
        with contextlib.redirect_stderr(io.StringIO()):
            r = srv.get('/book/OEBPS/style.css')
        self.assertEqual(r.status, 500)
        self.assertNotIn(b'SECRET', r.body)
        self.assertNotIn(b'Traceback', r.body)

    def test_huge_range_numbers_are_ignored_not_fatal(self):
        self.assertIsNone(es.parse_byte_range('bytes=' + '9' * 5000 + '-', 100))
        self.assertIsNone(es.parse_byte_range('bytes=0-' + '9' * 5000, 100))

    def test_deeply_nested_toc_is_capped(self):
        depth = es.MAX_TOC_DEPTH * 20
        ncx = (
            '<?xml version="1.0"?><ncx xmlns="http://www.daisy.org/z3986/2005/ncx/"><navMap>'
            + '<navPoint><navLabel><text>t</text></navLabel><content src="c1.xhtml"/>' * depth
            + '</navPoint>' * depth
            + '</navMap></ncx>'
        )
        files = main_epub_files()
        files['OEBPS/toc.ncx'] = ncx.encode()
        files['OEBPS/nav.xhtml'] = b'<html><body/></html>'
        manifest = [m for m in MAIN_MANIFEST if m[0] != 'nav'] + [
            ('ncx', 'toc.ncx', 'application/x-dtbncx+xml', '')
        ]
        files['OEBPS/content.opf'] = make_opf(manifest, MAIN_SPINE, ncx_id='ncx').encode()
        with contextlib.redirect_stderr(io.StringIO()):
            book, _ = load_book(write_epub(self.tmp / 'deep.epub', files))
        self.assertTrue(book.spine)

    def test_pdf_library_skips_symlinks_out_of_root_and_non_regular_files(self):
        root = self.tmp / 'pdflib'
        root.mkdir()
        outside = self.tmp / 'outside.pdf'
        outside.write_bytes(b'%PDF-1.4 secret')
        (root / 'ok.pdf').write_bytes(b'%PDF-1.4 fine')
        os.symlink(outside, root / 'link.pdf')
        if hasattr(os, 'mkfifo'):
            os.mkfifo(root / 'pipe.pdf')
        lib = es.PdfLibrary(root)
        names = [e.name if hasattr(e, 'name') else str(e) for e in lib.scan()]
        joined = ' '.join(names)
        self.assertIn('ok.pdf', joined)
        self.assertNotIn('link.pdf', joined)
        self.assertNotIn('pipe.pdf', joined)

    def test_pdf_handler_has_security_headers_without_corp(self):
        root = self.tmp / 'pdfhdr'
        root.mkdir()
        (root / 'a.pdf').write_bytes(b'%PDF-1.4 x')
        lib = es.PdfLibrary(root)
        srv = Running(quiet_handler(es.PdfHandler, library=lib))
        self.addCleanup(srv.close)
        page = srv.get('/')
        self.assertEqual(page.headers.get('x-content-type-options'), 'nosniff')
        self.assertNotIn('cross-origin-resource-policy', page.headers)


class CommandLineTests(TempDirCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.epub = write_epub(cls.tmp / 'book.epub', main_epub_files())

    def policy_for(self, *flags):
        cli = Cli(self.epub, *flags)
        try:
            r = cli.get('/book/OEBPS/c1.xhtml')
        finally:
            out, err = cli.stop()
        return r.headers.get('content-security-policy', ''), out, err

    def test_scripts_and_remote_content_are_blocked_by_default(self):
        policy, out, err = self.policy_for()
        self.assertEqual(policy, es.build_csp())
        self.assertNotIn('warning: scripts', out + err)

    def test_allow_scripts_flag_permits_scripts_and_warns(self):
        policy, _, err = self.policy_for('--allow-scripts')
        self.assertEqual(policy, es.build_csp(allow_scripts=True))
        self.assertNotIn("script-src 'none'", policy)
        self.assertNotIn('https:', policy)  # remote content is a separate switch
        self.assertIn('scripts inside the book are allowed', err)

    def test_allow_remote_flag_permits_https_content_and_warns(self):
        policy, _, err = self.policy_for('--allow-remote')
        self.assertEqual(policy, es.build_csp(allow_remote=True))
        self.assertIn("script-src 'none'", policy)  # still no scripts
        self.assertIn('https:// sites', err)

    def test_loopback_server_refuses_foreign_host_headers(self):
        cli = Cli(self.epub)
        try:
            ok = cli.get('/', {'Host': f'localhost:{cli.port}'})
            rebinding = cli.get('/', {'Host': f'attacker.example:{cli.port}'})
        finally:
            cli.stop()
        self.assertEqual(ok.status, 200)
        self.assertEqual(rebinding.status, 403)
        self.assertNotIn(b'Test Book', rebinding.body)

    def test_listening_on_all_interfaces_warns(self):
        cli = Cli(self.epub, '--host', '0.0.0.0')
        try:
            cli.get('/')
        finally:
            out, err = cli.stop()
        self.assertIn('anyone who can reach this machine', err)

    def test_epub_startup_output_and_no_tracebacks(self):
        cli = Cli(self.epub)
        try:
            cli.get('/')
            cli.get('/book/OEBPS/c1.xhtml')
        finally:
            out, err = cli.stop()
        self.assertIn('"Test Book" by Ann Author, Bob Writer', out)
        self.assertIn('DRM-protected', err)
        self.assertNotIn('Traceback', err)

    def test_pdf_mode_startup_message(self):
        pdf = self.tmp / 'x.pdf'
        pdf.write_bytes(b'%PDF-1.4\n%%EOF\n')
        cli = Cli(pdf)
        try:
            self.assertEqual(cli.get('/').status, 200)
        finally:
            out, err = cli.stop()
        self.assertIn('hosting 1 PDF file from', out)
        self.assertNotIn('Traceback', err)

    def test_missing_path_is_a_clean_error(self):
        r = run_script(self.tmp / 'nope')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('not found', r.stderr)

    def test_empty_folder_is_a_clean_error(self):
        empty = self.tmp / 'empty_dir'
        empty.mkdir()
        r = run_script(empty)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('could not parse EPUB', r.stderr)
        self.assertNotIn('Traceback', r.stderr)

    def test_port_in_use_is_a_clean_error(self):
        with socket.socket() as busy:
            busy.bind(('127.0.0.1', 0))
            busy.listen(1)
            r = run_script(self.epub, '--port', busy.getsockname()[1])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('could not listen', r.stderr)
        self.assertNotIn('Traceback', r.stderr)


if __name__ == '__main__':
    unittest.main()
