"""Create a self-contained HTML test and coverage report."""

from __future__ import annotations

import argparse
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree


def _junit_totals(path: Path) -> dict[str, str]:
    root = ElementTree.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "time": 0.0}
    for suite in suites:
        for key in ("tests", "failures", "errors", "skipped"):
            totals[key] += int(suite.attrib.get(key, 0))
        totals["time"] += float(suite.attrib.get("time", 0.0))
    return {key: str(value) for key, value in totals.items()}


def _coverage_rows(path: Path) -> tuple[dict, list[dict[str, str]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for filename, result in sorted(payload["files"].items()):
        summary = result["summary"]
        rows.append(
            {
                "module": filename,
                "statements": str(summary["num_statements"]),
                "missed": str(summary["missing_lines"]),
                "coverage": f"{summary['percent_covered']:.1f}%",
            }
        )
    return payload["totals"], rows


def generate(junit_path: Path, coverage_path: Path, output_path: Path) -> None:
    """Write the HTML report from JUnit and coverage JSON files."""

    tests = _junit_totals(junit_path)
    coverage, rows = _coverage_rows(coverage_path)
    passed = (
        int(tests["tests"])
        - int(tests["failures"])
        - int(tests["errors"])
        - int(tests["skipped"])
    )
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    row_markup = "\n".join(
        "<tr>"
        f"<td>{html.escape(row['module'])}</td>"
        f"<td>{row['statements']}</td><td>{row['missed']}</td>"
        f"<td>{row['coverage']}</td></tr>"
        for row in rows
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CryptoSafe Manager test report</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 1100px; margin: 32px auto; color: #202124; }}
h1, h2 {{ color: #111827; }}
.summary {{ display: flex; gap: 18px; flex-wrap: wrap; margin: 24px 0; }}
.metric {{ border: 1px solid #d1d5db; border-radius: 8px; padding: 14px 18px; min-width: 150px; }}
.value {{ display: block; font-size: 28px; font-weight: 700; color: #166534; }}
table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
th, td {{ border: 1px solid #d1d5db; padding: 8px 10px; text-align: left; }}
th {{ background: #f3f4f6; }}
td:nth-child(n+2) {{ text-align: right; }}
.note {{ background: #f9fafb; border-left: 4px solid #4b5563; padding: 12px 16px; }}
</style>
</head>
<body>
<h1>CryptoSafe Manager test report</h1>
<p>Generated {generated} with pytest and pytest-cov.</p>
<div class="summary">
  <div class="metric"><span class="value">{passed}</span>passed</div>
  <div class="metric"><span class="value">{tests["failures"]}</span>failed</div>
  <div class="metric"><span class="value">{float(coverage["percent_covered"]):.1f}%</span>coverage</div>
  <div class="metric"><span class="value">{float(tests["time"]):.2f}s</span>test time</div>
</div>
<p class="note">Coverage measures the security, cryptographic, vault, clipboard, audit, import/export, and database layers. Native GUI rendering is verified separately because the release test environment has no display server.</p>
<h2>Coverage by module</h2>
<table>
<thead><tr><th>Module</th><th>Statements</th><th>Missed</th><th>Coverage</th></tr></thead>
<tbody>{row_markup}</tbody>
</table>
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")


def main() -> None:
    """Parse command-line arguments and generate the report."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    generate(arguments.junit, arguments.coverage, arguments.output)


if __name__ == "__main__":
    main()
