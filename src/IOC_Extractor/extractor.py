from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable
from urllib.parse import urlparse

from .patterns import ( IPV4_RE, EMAIL_RE, MD5_RE, SHA256_RE, SHA1_RE, URL_RE, DOMAIN_RE)

from .normalize import ( normalize_ip, normalize_email, normalize_hash, normalize_url, normalize_domain)

@dataclass
class IOCFinding:
    type: str
    value: str
    line: int
    excerpt: str

def _excerpt(line: str, max_len: int = 160) -> str:
    s = line.strip().replace("\t", " ")
    return s if len(s) <= max_len else s[:max_len - 3] + "..."

def extract_iocs(lines: Iterable[str]) -> list[IOCFinding]:
    findings : list[IOCFinding] = []
    domains_from_url_or_email: set[str] = set()

    for idx, line in enumerate(lines, start = 1):
        #URLs
        for m in URL_RE .finditer(line):
            v = normalize_url(m.group(0))
            if not v:
                continue 

            findings.append(IOCFinding("url", v, idx, _excerpt(line)))

            host = urlparse(v).hostname
            if host:
                nd = normalize_domain(host)
                if nd:
                    domains_from_url_or_email.add(nd)

        #Emails
        for m in EMAIL_RE.finditer(line):
            email = normalize_email(m.group(0))
            findings.append(IOCFinding("email", email, idx, _excerpt(line)))

            if "@" in email:
                ed = email.split("@", 1)[1]
                nd = normalize_domain(ed)
                if nd:
                    domains_from_url_or_email.add(nd)

        #IPs
        for m in IPV4_RE.finditer(line):
            ip = normalize_ip(m.group(0))
            if ip:
                findings.append(IOCFinding("ipv4", ip, idx, _excerpt(line)))

        #Hashes
        for m in SHA256_RE.finditer(line):
                findings.append(IOCFinding("sha256", normalize_hash(m.group(0)), idx, _excerpt(line)))
        for m in SHA1_RE.finditer(line):
                findings.append(IOCFinding("sha1", normalize_hash(m.group(0)), idx, _excerpt(line)))
        for m in MD5_RE.finditer(line):
                findings.append(IOCFinding("md5", normalize_hash(m.group(0)), idx, _excerpt(line)))

        #Domains
        for m in DOMAIN_RE.finditer(line):
            d = normalize_domain(m.group(0))
            if not d:
                continue

            if d in domains_from_url_or_email:
                 continue
            
            findings.append(IOCFinding("domain", d, idx, _excerpt(line)))

    return findings

def finfings_to_dict(findings: list[IOCFinding]) -> list[dict]:
     return [asdict(f) for f in findings]