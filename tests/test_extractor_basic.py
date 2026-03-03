from IOC_Extractor.extractor import extract_iocs

def test_extract_basic():
    lines = [
        "user admin@evil.com clicked https://evil.com/path\n",
        "IP 203.0.113.10 seen\n",
        "Hash d41d8cd98f00b204e9800998ecf8427e\n",
    ]
    findings = extract_iocs(lines)
    types = {f.type for f in findings}
    assert "email" in types
    assert "url" in types
    assert "ipv4" in types
    assert "md5" in types