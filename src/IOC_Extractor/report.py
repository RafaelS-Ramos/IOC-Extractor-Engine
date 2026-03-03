from __future__ import annotations

import csv
import json
import os
from collections import defaultdict
from typing import Any

from .extractor import IOCFinding


def aggregate(findings: list[IOCFinding]) -> dict[str, Any]:
    """
    Returns:
    {
      "summary": { "ipv4": 2, "domain": 3, ... },   # unique values per type
      "items": [
        { "type": "ipv4", "value": "203.0.113.10", "count": 2, "lines": [8], "examples": [...] },
        ...
      ]
    }
    """
    buckets: dict[tuple[str, str], list[IOCFinding]] = defaultdict(list)
    for f in findings:
        buckets[(f.type, f.value)].append(f)

    items: list[dict[str, Any]] = []
    summary: dict[str, int] = defaultdict(int)

    for (t, v), fs in buckets.items():
        summary[t] += 1

        lines = sorted({x.line for x in fs})
        examples = [{"line": x.line, "excerpt": x.excerpt} for x in fs[:3]]

        items.append(
            {
                "type": t,
                "value": v,
                "count": len(fs),
                "lines": lines,
                "examples": examples,
            }
        )

    items.sort(key=lambda x: (x["type"], -x["count"], x["value"]))
    return {"summary": dict(summary), "items": items}


def write_json(data: dict[str, Any], out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def write_csv(agg: dict[str, Any], out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    fieldnames = ["type", "value", "count", "lines", "example_1", "example_2", "example_3"]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()

        for item in agg["items"]:
            ex = item["examples"]
            w.writerow(
                {
                    "type": item["type"],
                    "value": item["value"],
                    "count": item["count"],
                    "lines": ",".join(str(n) for n in item["lines"]),
                    "example_1": ex[0]["excerpt"] if len(ex) > 0 else "",
                    "example_2": ex[1]["excerpt"] if len(ex) > 1 else "",
                    "example_3": ex[2]["excerpt"] if len(ex) > 2 else "",
                }
            )
def write_markdown(agg: dict[str, Any], out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok = True)

    def esc(s: str) -> str:
        return s.replace("`", "\\`")

    lines: list[str] = []
    lines.append("# IOC Extraction Report\n")

    lines.append("## Summary\n")
    if not agg["summary"] :
        lines.append("- No IOCs found.\n")
    else:
        for t, n in sorted(agg["summary"].items()):
            lines.append(f"- **{t}**: {n}\n")

    lines.append("\n## Items\n")
    for item in agg["items"]:
        t = item["type"]
        v = item["value"]

        if t == "url":
            header_value = f"[{esc(v)}]({v})"
        else:
            header_value = f"`{esc(v)}`"

        lines.append(f"### {t}: {header_value}\n\n")
        lines.append(f"- Occurrences: **{item['count']}**\n")
        lines.append(f"- Lines: {', '.join(str(x) for x in item['lines'])}\n")

        if item ["examples"]:
            lines.append("- Examples:\n")
            for ex in item["examples"]:
                lines.append(f" - Line {ex['line']}:\n")
                lines.append(f"```text\n")
                lines.append(f" {ex['excerpt']}\n")
                lines.append(f"```\n")

        lines.append("\n---\n\n")
        
    with open(out_path, "w", encoding="utf-8") as f:
        f.writelines(lines)