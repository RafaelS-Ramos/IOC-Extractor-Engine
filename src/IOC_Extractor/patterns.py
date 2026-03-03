import re

#IPv4 (boa o suficiente para MVP; depois reforçar o range 0-255)
IPV4_RE = re.compile(r"\b(?:(?:\d{1,3})\.){3}(?:\d{1,3})\b")

#Email
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")

#HASHES
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

#URL
URL_RE = re.compile(r"\bhttps?://[^\s<>\"]+\b", re.IGNORECASE)

#Domínio
DOMAIN_RE = re.compile(
    r"(?<![@\w.-])"
    r"(?:[a-zA-Z0-9-]+\.)+"
    r"[A-Za-z]{2,}"
    r"(?![\w.-])"
    )

#Algumas strings que parecem domínios mas geralmente são falso positivos
COMMON_FALSE_POSITIVES = {
    "localhost",
}