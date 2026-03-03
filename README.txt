# IOC Extractor Engine

A SOC-style Indicator of compromise (IOC) extraction tool built in Python.

This project parses raw text files (logs, reports, threat intel dumps) and extracts structured IOCs such as:
- IPv4 addresses
- URLs
- Domains
- Emails
- MD5, SHA1, SHA256 hashes

The engine includes normalization, de-duplication logic, filtering and multi-format output (JSON, CSV, Markdown).

    Features
- IOC extraction via regex patterns
- value normalization (hash casing, domain cleanup, etc.)
- False positive reduction
- Cross-type de-duplication (e.g., domain inside URL/email)
- CLI filtering (`--types`, `--min-count`)
- Output formats:
    - JSON,
    - CSV,
    - Markdown (incident-style report)

    Installation
- Requires Python 3.10+

Clone the repository:
(bash):
git clone https://github.com/RafaelS-Ramos/IOC-Extractor-Engine.git
cd IOC-Extractor-Engine

(bash):
python -m src.IOC_Extractor.cli -i data\sample_input.tx

    Usage Examples (cmd)
- Extract everything
python -m src.IOC_Extractor.cli -i data\sample_input.txt --json outputp\iocs.json --csv output\iocs.csv --md output\report.md

- Only network-related IOCs
python -m src.IOC_Extractor.cli -i data\sample_input.txt --type ipv4,url --json output\net.json

- Only hashes
python -m src.IOC_Extractor.cli -i data\sample_input.txt --types md5, sha1, sha256

- Only IOCs that appear more than once
python -m src.IOC_Extractor.cli -i data\sample_input.txt --min-count 2

    Design Decisions
- Two-pass extraction to avoid domain duplication from URLs/Emails
- Strict normalization to reduce false positives
- Modular architecture (separation of concerns)
- CLI-first design (SOC workflow oriented)

    Skills Demonstrated
- Python CLI development (argparse)
- Regex-based detection
- Data normalization techniques
- Structured Reporting
- Defensive Programming
- Modular architecture design
- Threat Intelligence processing concepts

    Roadmap
Future improvements may include:
- IPV6 support
- Base64 detection
- MITRE ATT&CK mapping
- Windows Event Log parsing
- STIX/TAXII export
- Unit tests (pytest)
- Packaging as pip-installable tool.