"""`python -m skillguard.cli <path>` — scan a skill and print a report."""
from __future__ import annotations

import argparse
import sys

from .pipeline import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="skillguard", description="Scan an AI-agent skill package for safety.")
    parser.add_argument("source", help="Path to a directory, .zip, .tar[.gz], or a .git URL")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of markdown")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    result = scan(args.source)
    print(result.json if args.json else result.markdown)
    return {"MALICIOUS": 2, "DANGEROUS": 2, "SUSPICIOUS": 1, "UNVERIFIED": 1, "NO_FINDINGS": 0}[result.verdict.label]


if __name__ == "__main__":
    sys.exit(main())
