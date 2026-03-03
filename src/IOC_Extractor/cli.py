from __future__ import annotations

import argparse
from pathlib import Path

from .extractor import extract_iocs
from .report import aggregate, write_json, write_csv, write_markdown

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SOC-style IOC extractor (IPs, URLs, domains, emails, hashes) with JSON/CSV reporting."
    )
    p.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to input text/log file"
        )
    p.add_argument(
        "--json",
        help="Output JSON file path"
    )
    p.add_argument(
        "--csv",
        help="Output CSV file path"
    )
    p.add_argument(
        "--md",
        help="Output Markdown report path"
    )
    p.add_argument(
        "--types",
        default="all",
        help="Comma-separated IOC types to include (e.g. ipv4, url, sha256). Use 'all' for everything."
    )
    p.add_argument(
        "--min-count",
        type=int,
        default="1",
        help="Minimun number of occurrences to include an IOC in the report (default: 1)."
        )
    return p

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    input_path = Path(args.input)

    if not input_path.exists():
        parser.error(f"Input file not found: {input_path}")

    with input_path.open("r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    findings = extract_iocs(lines)
    agg = aggregate(findings)

    allowed = None
    if args.types.strip().lower() != "all":
        allowed = {
            t.strip().lower()
            for t in args.types.split(",")
            if t.strip()
        }

    filtered_items = []
    for item in agg["items"]:
        if allowed is not None and item["type"].lower() not in allowed:
            continue
        if item["count"] < args.min_count:
            continue
        filtered_items.append(item)

        summary = {}
        for item in filtered_items:
            summary[item["type"]] = summary.get(item["type"], 0) + 1

        agg = {"summary": summary,
        "items": filtered_items      
        }

    print(f"[+] Lines processed: {len(lines)}")
    print(f"[+] Unique IOCs: {len(agg['items'])}")
    print(f"[+] Total matches: {sum(item['count'] for item in agg['items'])}")

    if args.json:
        write_json(agg, args.json)
        print(f"[+] JSON: {args.json}")

    if args.csv:
        write_csv(agg, args.csv)
        print(f"[+] CSV: {args.csv}")

    if args.md:
        write_markdown(agg, args.md)
        print(f"[+] Markdown: {args.md}")


if __name__ == "__main__":
    main()