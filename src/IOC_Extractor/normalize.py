from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from .patterns import COMMON_FALSE_POSITIVES

def normalize_ip(ip: str) -> str | None:
    try:
        #Valida e normaliza (ex.: remove zeros à esquerda)
        obj = ipaddress.ip_address(ip)
        if obj.version != 4:
            return None
        return str(obj)
    except ValueError:
        return None
    
def normalize_email(email: str) -> str:
    return email.strip().lower()

def normalize_hash(h: str) -> str:
    return h.strip().lower()

def normalize_url(url: str) -> str | None:
    url = url
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return None
        if not p.netloc:
            return None
        # normaliza: esquema + host + path (mantém query)
        normalized = f"{p.scheme}://{p.netloc}{p.path}"
        if p.query:
            normalized += f"?{p.query}"
        return normalized
    except Exception:
        return None
    
def normalize_domain(domain: str) -> str | None:
    d = domain.strip().lower().rstrip(".")
    if not d or d in COMMON_FALSE_POSITIVES:
        return None
    if "_" in d:
        return None
    if "://" in d:
        return None
    if d.endswith((".exe", ".dll", ".zip", ".rar", ".7z", ".pdf")):
        return None
    return d