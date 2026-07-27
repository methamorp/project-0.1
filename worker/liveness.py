"""
Liveness / Zombie-page Detection
=================================
Tujuan modul ini BUKAN mendeteksi phishing/malicious, tapi menyaring domain
yang cuma "hidup secara teknis" (DNS resolve + HTTP 200) tapi sebenarnya
tidak punya konten nyata:

  - domain parking (dijual, belum dipakai)
  - halaman default server (nginx/apache/IIS/cPanel baru install)
  - halaman kosong / hampir kosong (thin content)
  - soft-404 (server jawab 200 tapi isinya "page not found")

CATATAN PENTING soal "traffic":
Traffic pengunjung asli TIDAK BISA diukur dari satu kali HTTP request.
Yang bisa dideteksi di sini cuma proxy tidak langsung: apakah halaman itu
punya struktur & konten selayaknya web yang benar-benar dipakai. Kalau
butuh sinyal traffic sungguhan, perlu integrasi data pihak ketiga
(misal Tranco top-1M list, https://tranco-list.eu -- gratis, bisa
di-download sebagai CSV lalu dicocokkan root domain-nya). Itu di luar
scope modul ini, tapi strukturnya sengaja dibuat gampang ditambah
(lihat catatan di akhir file).
"""
import re

# Frasa umum yang muncul di halaman parkir domain (Sedo, GoDaddy, Dan.com,
# HugeDomains, Bodis, ParkingCrew, Afternic, Namecheap parking, dll).
PARKING_MARKERS = [
    "domain is for sale",
    "this domain may be for sale",
    "buy this domain",
    "domain has expired",
    "this domain is parked",
    "domain parking",
    "parked free",
    "parked by",
    "inquire about this domain",
    "make an offer",
    "backorder this domain",
    "sedoparking.com",
    "parkingcrew.net",
    "bodis.com",
    "hugedomains.com",
    "dan.com",
    "afternic.com",
    "godaddy.com/domains",
]

# Halaman default bawaan web server / control panel yang belum dikonfigurasi
# situs apa pun -- artinya domain "resolve" tapi tidak ada web sungguhan.
DEFAULT_PAGE_MARKERS = [
    "welcome to nginx!",
    "apache2 ubuntu default page",
    "it works!",
    "iis windows server",
    "welcome to iis",
    "future home of something quite cool",  # default cPanel
    "if you are the owner of this website",
    "index of /",  # directory listing kosong
    "this is the default web page for this server",
]

# Frasa soft-404: server jawab HTTP 200 tapi isinya sebenarnya "tidak ada apa-apa".
SOFT_404_MARKERS = [
    "page not found",
    "404 not found",
    "the page you are looking for",
    "halaman tidak ditemukan",
    "content not found",
]

# Ambang batas panjang teks (setelah tag HTML dibuang) untuk dianggap "ada isi".
# Heuristik -- SPA client-side-rendered kadang HTML awalnya memang tipis,
# jadi ini indikasi, bukan kepastian mutlak.
MIN_TEXT_LENGTH = 60


def _visible_text(html: str) -> str:
    """Buang tag HTML & script/style, lalu rapikan whitespace, buat estimasi
    kasar teks yang benar-benar terlihat pengunjung."""
    no_script = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    no_tags = re.sub(r"(?s)<[^>]+>", " ", no_script)
    return re.sub(r"\s+", " ", no_tags).strip()


def assess_site_activity(http_status: int | None, html: str, headers: dict) -> dict:
    """Nilai apakah sebuah respons HTTP menunjukkan web yang benar-benar
    berjalan, atau cuma "zombie" (parked/default page/kosong).

    Return dict:
      {
        "status": "active" | "parked" | "default_page" | "thin_content"
                   | "soft_404" | "no_content" | "unreachable",
        "reason": str,           # penjelasan singkat kenapa
        "content_length": int,   # panjang teks terlihat (karakter)
      }
    """
    if http_status is None:
        return {"status": "unreachable", "reason": "tidak ada respons HTTP", "content_length": 0}

    if not html:
        return {
            "status": "no_content",
            "reason": "body kosong atau bukan text/html",
            "content_length": 0,
        }

    html_lower = html.lower()
    text = _visible_text(html_lower)
    content_length = len(text)

    if http_status >= 400:
        for marker in SOFT_404_MARKERS:
            if marker in html_lower:
                return {
                    "status": "soft_404",
                    "reason": f"HTTP {http_status} + pola '{marker}'",
                    "content_length": content_length,
                }
        return {
            "status": "http_error",
            "reason": f"HTTP {http_status} (status error)",
            "content_length": content_length,
        }

    for marker in DEFAULT_PAGE_MARKERS:
        if marker in html_lower:
            return {
                "status": "default_page",
                "reason": f"cocok pola halaman default server: '{marker}'",
                "content_length": content_length,
            }

    for marker in PARKING_MARKERS:
        if marker in html_lower:
            return {
                "status": "parked",
                "reason": f"cocok pola halaman parking domain: '{marker}'",
                "content_length": content_length,
            }

    if content_length < MIN_TEXT_LENGTH:
        return {
            "status": "thin_content",
            "reason": f"teks terlihat cuma {content_length} karakter (< {MIN_TEXT_LENGTH})",
            "content_length": content_length,
        }

    for marker in SOFT_404_MARKERS:
        if marker in html_lower:
            return {
                "status": "soft_404",
                "reason": f"HTTP {http_status} tapi isinya '{marker}'",
                "content_length": content_length,
            }

    return {"status": "active", "reason": "konten terlihat wajar", "content_length": content_length}


# --- Ide pengembangan lanjutan (opsional, belum diimplementasikan) ---
# Untuk sinyal traffic sungguhan, download list Tranco (top 1 juta domain
# berdasarkan traffic estimasi) dari https://tranco-list.eu/, simpan sebagai
# set() root domain, lalu tambahkan field baru mis. `has_traffic_rank: bool`
# dengan cek keanggotaan root domain di set tersebut. List perlu di-refresh
# berkala (mis. mingguan) karena rank berubah.