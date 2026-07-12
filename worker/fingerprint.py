"""
Deteksi tech stack sederhana (rule-based) dari HTTP headers dan HTML.

Ini titik awal yang cukup buat riset skala kecil-menengah. Untuk deteksi
yang jauh lebih akurat dan luas (ribuan signature), pertimbangkan integrasi
library seperti `python-Wappalyzer` di kemudian hari -- struktur data
`tech_stack` di sini sengaja dibuat kompatibel supaya gampang diganti.
"""
import re

SIGNATURES = {
    "server_header": {
        "cloudflare": ["cloudflare"],
        "nginx": ["nginx"],
        "apache": ["apache"],
        "vercel": ["vercel"],
        "aws": ["awselb", "amazons3"],
        "iis": ["microsoft-iis"],
    },
    "powered_by": {
        "php": ["php"],
        "express": ["express"],
        "asp.net": ["asp.net"],
    },
    "html_generator": {
        "wordpress": ["wordpress"],
        "wix": ["wix.com"],
        "shopify": ["shopify"],
        "squarespace": ["squarespace"],
    },
    "html_patterns": {
        "wordpress": [r"/wp-content/", r"/wp-includes/"],
        "next.js": [r"/_next/static/"],
        "react": [r"data-reactroot", r"__react_devtools"],
        "shopify": [r"cdn\.shopify\.com"],
        "drupal": [r"/sites/default/files/"],
        "laravel": [r"laravel_session"],
    },
}


def detect_tech_stack(headers: dict, html: str) -> dict:
    tech: dict = {}
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}

    server = headers_lower.get("server", "")
    for tech_name, keywords in SIGNATURES["server_header"].items():
        if any(kw in server for kw in keywords):
            tech["server"] = tech_name

    powered_by = headers_lower.get("x-powered-by", "")
    for tech_name, keywords in SIGNATURES["powered_by"].items():
        if any(kw in powered_by for kw in keywords):
            tech["backend"] = tech_name

    if html:
        html_lower = html.lower()

        generator_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            html_lower,
        )
        if generator_match:
            gen_value = generator_match.group(1)
            for tech_name, keywords in SIGNATURES["html_generator"].items():
                if any(kw in gen_value for kw in keywords):
                    tech["cms"] = tech_name

        for tech_name, patterns in SIGNATURES["html_patterns"].items():
            if any(re.search(p, html_lower) for p in patterns):
                tech.setdefault("cms", tech_name)

    cookie = headers_lower.get("set-cookie", "")
    if "phpsessid" in cookie:
        tech.setdefault("backend", "php")
    elif "laravel_session" in cookie:
        tech.setdefault("framework", "laravel")

    return tech
