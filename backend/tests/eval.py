"""Eval harness and ship gates. See spec §11.

Usage:
  python tests/eval.py                      # red + hand-written benign corpus
  python tests/eval.py --real-corpus <dir>   # also scan a directory tree of
                                              # real-world skills (unlabeled,
                                              # reported as a FP-rate proxy,
                                              # not gated)

Hard gate (blocks release): 100% recall at SUSPICIOUS-or-higher on the red
corpus. Reported-not-gated: false-positive rate at DANGEROUS+ on the benign
corpus and on the real-world sample.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from skillguard.pipeline import scan  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
RANK = {"NO_FINDINGS": 0, "UNVERIFIED": 1, "SUSPICIOUS": 2, "DANGEROUS": 3, "MALICIOUS": 4}


def _iter_top_level_targets(base: Path) -> list[Path]:
    """Each immediate child of `base` is one scan target: a directory (multi-file
    skill) or a single file."""
    return sorted(base.iterdir())


def run_red(verbose: bool) -> tuple[int, int, list[str]]:
    targets = _iter_top_level_targets(FIXTURES / "red")
    passed, failed = 0, []
    for t in targets:
        source = str(t) if t.is_dir() else str(t)
        result = scan(source)
        label = result.verdict.label
        ok = RANK[label] >= RANK["SUSPICIOUS"]
        if ok:
            passed += 1
        else:
            failed.append(f"{t.name}: got {label}")
        if verbose:
            mark = "PASS" if ok else "FAIL"
            print(f"  [{mark}] {t.name:45s} -> {label}")
    return passed, len(targets), failed


def run_benign(verbose: bool) -> tuple[int, int]:
    targets = _iter_top_level_targets(FIXTURES / "benign")
    fps = 0
    for t in targets:
        result = scan(str(t))
        label = result.verdict.label
        is_fp = RANK[label] >= RANK["DANGEROUS"]
        if is_fp:
            fps += 1
        if verbose:
            mark = "FP  " if is_fp else "ok  "
            print(f"  [{mark}] {t.name:45s} -> {label}")
    return fps, len(targets)


def run_real_corpus(corpus_dir: Path, sample_size: int, verbose: bool) -> tuple[int, int, dict[str, int]]:
    all_skill_md = sorted(corpus_dir.rglob("SKILL.md"))
    if not all_skill_md:
        all_skill_md = sorted(corpus_dir.rglob("*.md"))
    sample = all_skill_md[:sample_size]
    fps = 0
    dist: dict[str, int] = {}
    errors = 0
    for i, path in enumerate(sample):
        try:
            result = scan(str(path.parent) if (path.parent / "SKILL.md").exists() else str(path))
            label = result.verdict.label
        except Exception as e:  # noqa: BLE001 - eval harness must survive bad real-world input
            errors += 1
            if verbose:
                print(f"  [ERR ] {path} -> {e}")
            continue
        dist[label] = dist.get(label, 0) + 1
        if RANK[label] >= RANK["DANGEROUS"]:
            fps += 1
        if verbose and i < 20:
            print(f"  [{label:11s}] {path.relative_to(corpus_dir)}")
    return fps, len(sample), dist


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--real-corpus", type=Path, default=None)
    parser.add_argument("--sample-size", type=int, default=200)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    t0 = time.time()

    print("=" * 70)
    print("RED CORPUS — hard gate: 100% recall at SUSPICIOUS-or-higher")
    print("=" * 70)
    passed, total, failed = run_red(args.verbose)
    print(f"\n{passed}/{total} red fixtures reached SUSPICIOUS+.")
    hard_gate_ok = not failed
    if failed:
        print("FAILED (hard gate blocks release):")
        for f in failed:
            print(f"  - {f}")
    else:
        print("HARD GATE: PASS")

    print()
    print("=" * 70)
    print("BENIGN CORPUS (hand-written) — FP rate at DANGEROUS+ (reported, not gated)")
    print("=" * 70)
    fps, btotal = run_benign(args.verbose)
    fp_rate = 100.0 * fps / btotal if btotal else 0.0
    print(f"\n{fps}/{btotal} benign fixtures false-positived at DANGEROUS+ ({fp_rate:.1f}%). Target <10%.")

    if args.real_corpus and args.real_corpus.exists():
        print()
        print("=" * 70)
        print(f"REAL-WORLD SAMPLE ({args.real_corpus.name}) — unlabeled, FP-rate proxy only")
        print("=" * 70)
        rfps, rtotal, dist = run_real_corpus(args.real_corpus, args.sample_size, args.verbose)
        rfp_rate = 100.0 * rfps / rtotal if rtotal else 0.0
        print(f"\nScanned {rtotal} real skills. Label distribution: {dist}")
        print(f"{rfps}/{rtotal} flagged DANGEROUS+ ({rfp_rate:.1f}%). These are published, presumed-benign "
              f"skills, so this is a real-world FP-rate proxy, not a ground-truth benchmark.")

    print(f"\nTotal eval time: {time.time() - t0:.1f}s")
    return 0 if hard_gate_ok else 1


if __name__ == "__main__":
    sys.exit(main())
