"""
Deteksi tech stack (rule-based) dari HTTP headers dan HTML.

Prinsip desain supaya akurat & rendah false-positive:

  1. Prioritaskan sinyal dari HTTP HEADERS di atas pola HTML -- header jauh
     lebih sulit "kebetulan cocok" dibanding teks bebas di body HTML (mis.
     third-party widget/embed yang menyebut nama platform lain).
  2. Tiap kategori (server/backend/cms/framework) HANYA diisi oleh match
     PERTAMA sesuai urutan prioritas EKSPLISIT di list `RULES`.
     Ini memperbaiki bug versi sebelumnya: loop over dict yang overwrite
     tanpa urutan prioritas jelas, jadi hasil akhirnya tergantung urutan
     insertion dict (rapuh & tidak konsisten).
  3. Sinyal "high confidence" (header eksplisit seperti X-Powered-By,
     custom header khas platform, atau nama cookie DI HEADER Set-Cookie)
     dicek duluan. Sinyal "medium confidence" (pola path aset statis di
     HTML, meta generator tag) jadi fallback.
  4. Pattern yang salah tempat/usang di versi sebelumnya sudah diperbaiki:
       - "laravel_session" & "phpsessid" SEBELUMNYA malah dicek juga di body
         HTML (`html_patterns`) padahal itu nama COOKIE -- cuma valid kalau
         muncul di header Set-Cookie. Sekarang cuma dicek di header.
       - "data-reactroot" sendirian gampang false-negative karena atribut
         ini sudah dihapus sejak React 16 (2017) -- ditambah signature
         modern (nama file bundle react-dom).
       - Pattern generik seperti "shopify" polos di header Server dihapus;
         diganti sinyal yang benar-benar unik dipakai Shopify.

Untuk deteksi jauh lebih luas (ribuan signature), pertimbangkan integrasi
`python-Wappalyzer` -- struktur `tech_stack` di sini sengaja tetap
kompatibel (dict flat per kategori) supaya gampang diganti nanti.
"""
import re
from dataclasses import dataclass
from typing import Callable

Matcher = Callable[[dict, str, str], bool]


@dataclass(frozen=True)
class Rule:
    category: str      # "server" | "backend" | "cms" | "framework"
    tech_name: str
    matcher: Matcher    # (headers_lower, html_lower, generator_value) -> bool
    confidence: str     # "high" (header/cookie eksplisit) | "medium" (pola HTML)


def _header_contains(header_name: str, *keywords: str) -> Matcher:
    def _match(headers: dict, html: str, generator: str) -> bool:
        value = headers.get(header_name, "")
        return any(kw in value for kw in keywords)
    return _match


def _header_exists(*header_names: str) -> Matcher:
    def _match(headers: dict, html: str, generator: str) -> bool:
        return any(h in headers for h in header_names)
    return _match


def _html_contains(*substrings: str) -> Matcher:
    def _match(headers: dict, html: str, generator: str) -> bool:
        return any(s in html for s in substrings)
    return _match


def _generator_contains(*keywords: str) -> Matcher:
    def _match(headers: dict, html: str, generator: str) -> bool:
        return any(kw in generator for kw in keywords)
    return _match


# Urutan list = urutan prioritas. Untuk tiap kategori, match PERTAMA yang
# cocok yang dipakai -- entri sesudahnya untuk kategori yang sama diabaikan.
RULES: list[Rule] = [
    # ---------- server (dari header Server) ----------
    # CDN/proxy dicek lebih dulu karena biasanya "menutupi" web server asli
    # di baliknya, jadi lebih informatif buat riset.
    Rule("server", "cloudflare", _header_contains("server", "cloudflare"), "high"),
    Rule("server", "vercel", _header_contains("server", "vercel"), "high"),
    Rule("server", "aws", _header_contains("server", "awselb", "amazons3", "cloudfront"), "high"),
    Rule("server", "nginx", _header_contains("server", "nginx"), "high"),
    Rule("server", "apache", _header_contains("server", "apache"), "high"),
    Rule("server", "iis", _header_contains("server", "microsoft-iis"), "high"),

    # ---------- backend (dari header X-Powered-By -- eksplisit, jarang salah) ----------
    Rule("backend", "asp.net", _header_contains("x-powered-by", "asp.net"), "high"),
    Rule("backend", "express", _header_contains("x-powered-by", "express"), "high"),
    Rule("backend", "php", _header_contains("x-powered-by", "php"), "high"),
    # Fallback: cookie PHPSESSID cuma valid & relevan di header Set-Cookie,
    # BUKAN dicari di body HTML (beda dari versi sebelumnya).
    Rule("backend", "php", _header_contains("set-cookie", "phpsessid"), "high"),

    # ---------- framework: Next.js ----------
    # Banyak app Next.js set header ini eksplisit -- high confidence.
    Rule("framework", "next.js", _header_contains("x-powered-by", "next.js"), "high"),
    # Fallback ke jejak di HTML kalau header tidak ada.
    Rule("framework", "next.js", _html_contains("/_next/static/", "__next_data__"), "medium"),

    # ---------- framework: Laravel ----------
    # laravel_session HANYA valid sebagai nama cookie (header Set-Cookie).
    # Versi sebelumnya keliru juga mencarinya di body HTML.
    Rule("framework", "laravel", _header_contains("set-cookie", "laravel_session"), "high"),

    # ---------- cms: sinyal header/cookie unik platform (high confidence) ----------
    # Header-header ini nyaris tidak pernah muncul di luar platform aslinya.
    Rule("cms", "shopify", _header_exists("x-shopify-stage", "x-sorting-hat-podid", "x-shardid"), "high"),
    Rule("cms", "wordpress", _header_contains("link", "wp-json"), "high"),
    Rule("cms", "wix", _header_contains("server", "wix"), "high"),

    # ---------- cms: meta generator tag (medium -- bisa dihapus manual,
    # tapi kalau ada, sangat spesifik & jarang dipalsukan situs lain) ----------
    Rule("cms", "wordpress", _generator_contains("wordpress"), "medium"),
    Rule("cms", "wix", _generator_contains("wix.com"), "medium"),
    Rule("cms", "shopify", _generator_contains("shopify"), "medium"),
    Rule("cms", "squarespace", _generator_contains("squarespace"), "medium"),
    Rule("cms", "drupal", _generator_contains("drupal"), "medium"),

    # ---------- cms: pola path aset statis khas platform (medium) ----------
    Rule("cms", "wordpress", _html_contains("/wp-content/", "/wp-includes/"), "medium"),
    # Diperketat: sebelumnya cuma "cdn.shopify.com" (bisa kebawa dari
    # widget/app pihak ketiga yang di-embed di situs BUKAN Shopify).
    # Sekarang wajib prefix path toko Shopify yang khas.
    Rule("cms", "shopify", _html_contains("cdn.shopify.com/s/files", "cdn.shopify.com/s/assets"), "medium"),
    Rule("cms", "drupal", _html_contains("/sites/default/files/", "drupal.settings"), "medium"),

    # ---------- framework: React ----------
    # "data-reactroot" cuma ada di React <16 (dihapus 2017) -- ditambah
    # signature modern supaya React versi terkini tidak lolos tak terdeteksi.
    Rule("framework", "react", _html_contains(
        "data-reactroot",            # React <16 (legacy)
        "react-dom.production",      # nama file bundle react-dom (prod)
        "react-dom.development",     # nama file bundle react-dom (dev)
    ), "medium"),
]


def detect_tech_stack(headers: dict, html: str) -> dict:
    """Jalankan semua rule sesuai urutan prioritas di `RULES`. Kategori yang
    sudah terisi TIDAK akan ditimpa rule berikutnya (first-match-wins
    berdasarkan prioritas eksplisit, bukan urutan dict yang implisit)."""
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    html_lower = html.lower() if html else ""

    generator_value = ""
    if html_lower:
        generator_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            html_lower,
        )
        if generator_match:
            generator_value = generator_match.group(1)

    tech: dict = {}
    for rule in RULES:
        if rule.category in tech:
            continue
        if rule.matcher(headers_lower, html_lower, generator_value):
            tech[rule.category] = rule.tech_name

    return tech