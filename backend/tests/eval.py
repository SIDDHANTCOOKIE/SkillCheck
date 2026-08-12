"""Eval harness and ship gates. See spec §11 and the eval-strengthening plan.

Usage:
  python tests/eval.py                      # red gate (manifest-based) + benign FP ratchet
  python tests/eval.py --real-corpus <dir>   # also scan a directory tree of
                                              # real-world skills; ratchets its
                                              # label distribution too
  python tests/eval.py --mutate              # Phase 1.5: does SUSPICIOUS+ survive
                                              # cheap adversarial mutation? reported,
                                              # not gated — expect real gaps here.

Hard gate (blocks release): every red fixture must reach its manifest-pinned
min_label AND fire the manifest-pinned rules/capabilities/provenance —
label-only agreement is exactly the "passed for the wrong reason" failure
this harness exists to catch (LABEL_MISS vs WRONG_REASON vs PROVENANCE_MISS
are reported separately). FP rate on the benign corpus and the real-corpus
label distribution are ratchets: they fail if they get WORSE than the
checked-in baseline, not against a fixed target — precision is deliberately
traded for recall here (verdict.py), so an absolute FP ceiling would fight
the design.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from skillcheck.pipeline import scan  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BASELINE_PATH = Path(__file__).resolve().parent / "fp_baseline.json"
RANK = {"NO_FINDINGS": 0, "UNVERIFIED": 1, "SUSPICIOUS": 2, "DANGEROUS": 3, "MALICIOUS": 4}


def _iter_top_level_targets(base: Path) -> list[Path]:
    """Each immediate child of `base` is one scan target: a directory (multi-file
    skill) or a single file."""
    return sorted(p for p in base.iterdir() if p.name != "manifest.yaml")


# --------------------------------------------------------------------------
# 1.1 — manifest-pinned red corpus gate
# --------------------------------------------------------------------------

def _load_manifest() -> dict:
    path = FIXTURES / "red" / "manifest.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _check_fixture(name: str, result, spec: dict) -> list[str]:
    """Returns a list of failure strings ("" if none), each tagged with its
    failure mode so a fix can target the right thing."""
    failures = []
    findings = result.verdict.findings
    label = result.verdict.label

    min_label = spec.get("min_label", "SUSPICIOUS")
    if RANK[label] < RANK[min_label]:
        failures.append(f"LABEL_MISS: got {label}, need >= {min_label}")
        # If the label itself is wrong, checking rules/capabilities/provenance
        # against a corpus that never fired meaningfully would just be noise.
        return failures

    got_rules = {f.rule_id for f in findings}
    want_rules = set(spec.get("must_include_rules", []))
    missing_rules = want_rules - got_rules
    if missing_rules:
        failures.append(f"WRONG_REASON: label reached but rule(s) {sorted(missing_rules)} never fired "
                         f"(got rules: {sorted(got_rules)})")

    got_caps = {f.capability.value for f in findings}
    want_caps = set(spec.get("must_include_capabilities", []))
    missing_caps = want_caps - got_caps
    if missing_caps:
        failures.append(f"WRONG_REASON: capability(ies) {sorted(missing_caps)} never fired "
                         f"(got: {sorted(got_caps)})")

    want_prov = set(spec.get("must_have_provenance", []))
    if want_prov:
        got_prov: set[str] = set()
        for f in findings:
            got_prov.update(f.provenance or [])
        missing_prov = want_prov - got_prov
        if missing_prov:
            failures.append(f"PROVENANCE_MISS: provenance tag(s) {sorted(missing_prov)} never appeared "
                             f"(proves the mechanism, e.g. decode/html-comment, didn't actually fire) "
                             f"(got provenance: {sorted(got_prov)})")

    if spec.get("must_have_chain") and not result.verdict.chains:
        failures.append("WRONG_REASON: expected a capability chain (cross-file corroboration) but none formed")

    return failures


def run_red(verbose: bool) -> tuple[int, int, list[str]]:
    manifest = _load_manifest()
    targets = _iter_top_level_targets(FIXTURES / "red")
    passed, failed = 0, []
    for t in targets:
        source = str(t) if t.is_dir() else str(t)
        result = scan(source)
        spec = manifest.get(t.name, {"min_label": "SUSPICIOUS"})
        failures = _check_fixture(t.name, result, spec)
        if failures:
            for msg in failures:
                failed.append(f"{t.name}: {msg}")
        else:
            passed += 1
        if verbose:
            mark = "PASS" if not failures else "FAIL"
            print(f"  [{mark}] {t.name:45s} -> {result.verdict.label}")
            for msg in failures:
                print(f"         {msg}")
    return passed, len(targets), failed


# --------------------------------------------------------------------------
# 1.3 — FP-rate ratchet
# --------------------------------------------------------------------------

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


def _load_baseline() -> dict:
    if BASELINE_PATH.exists():
        return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    return {}


def _save_baseline(data: dict) -> None:
    BASELINE_PATH.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check_ratchet(name: str, current: int, baseline: dict, update: bool) -> bool:
    """Returns True (ok) if `current` does not exceed the checked-in baseline
    for `name`. With --update-baseline, records the new value instead of
    gating on it (use deliberately, after confirming a rise is intentional)."""
    prior = baseline.get(name)
    if update or prior is None:
        baseline[name] = current
        return True
    ok = current <= prior
    if not ok:
        print(f"RATCHET FAIL [{name}]: {current} > baseline {prior}. "
              f"Either this is a real regression, or run with --update-baseline "
              f"if the rise is intentional (e.g. deliberately widened a detector).")
    return ok


# --------------------------------------------------------------------------
# 1.5 — mutation testing (reported, not gated)
# --------------------------------------------------------------------------

_DOMAIN_ALT = "attacker-controlled-mirror.example.net"


def _mutate_variants(text: str, rng: random.Random) -> dict[str, str]:
    """Cheap, deterministic mutations that should not change verdict-worthiness
    of a genuinely malicious fixture. Each is a distinct evasion class."""
    variants = {}
    if "curl" in text and "wget" not in text:
        variants["curl_to_wget"] = text.replace("curl -sL", "wget -qO-", 1).replace("curl", "wget", 1)
    if "webhook.site" in text:
        variants["swap_domain"] = text.replace("webhook.site", _DOMAIN_ALT)
    lines = text.splitlines(keepends=True)
    if len(lines) > 3:
        shuffled = lines[:]
        idx = list(range(len(shuffled)))
        rng.shuffle(idx)
        variants["reorder_lines"] = "".join(shuffled[i] for i in idx)
    return variants


def run_mutations(verbose: bool) -> tuple[int, int, list[str]]:
    manifest = _load_manifest()
    rng = random.Random(1234)
    total = 0
    held = 0
    gaps: list[str] = []
    for t in _iter_top_level_targets(FIXTURES / "red"):
        if not t.is_file():
            continue  # multi-file mutation is out of scope for this cheap pass
        text = t.read_text(encoding="utf-8", errors="replace")
        spec = manifest.get(t.name, {"min_label": "SUSPICIOUS"})
        min_label = spec.get("min_label", "SUSPICIOUS")
        for mutation_name, mutated in _mutate_variants(text, rng).items():
            total += 1
            result = scan(text_blob=(t.name, mutated))
            ok = RANK[result.verdict.label] >= RANK["SUSPICIOUS"]
            if ok:
                held += 1
            else:
                gaps.append(f"{t.name} [{mutation_name}]: dropped to {result.verdict.label} "
                             f"(wanted >= SUSPICIOUS, fixture's normal min_label is {min_label})")
            if verbose:
                mark = "HOLD" if ok else "GAP "
                print(f"  [{mark}] {t.name:35s} [{mutation_name:16s}] -> {result.verdict.label}")
    return held, total, gaps


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--real-corpus", type=Path, default=None)
    parser.add_argument("--sample-size", type=int, default=200)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--mutate", action="store_true", help="Phase 1.5 mutation pass, reported not gated")
    parser.add_argument("--update-baseline", action="store_true", help="record current FP counts as the new ratchet baseline")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    t0 = time.time()
    baseline = _load_baseline()
    gate_ok = True

    if args.mutate:
        print("=" * 70)
        print("MUTATION PASS (Phase 1.5) — reported, not gated")
        print("=" * 70)
        held, total, gaps = run_mutations(args.verbose)
        print(f"\n{held}/{total} mutated variants still reached SUSPICIOUS+.")
        if gaps:
            print("Recall gaps found (real detector work, not a quick fix):")
            for g in gaps:
                print(f"  - {g}")
        print(f"\nTotal eval time: {time.time() - t0:.1f}s")
        return 0

    print("=" * 70)
    print("RED CORPUS — hard gate: manifest-pinned label + rule/capability/provenance")
    print("=" * 70)
    passed, total, failed = run_red(args.verbose)
    print(f"\n{passed}/{total} red fixtures passed on label AND reason.")
    hard_gate_ok = not failed
    gate_ok = gate_ok and hard_gate_ok
    if failed:
        print("FAILED (hard gate blocks release):")
        for f in failed:
            print(f"  - {f}")
    else:
        print("HARD GATE: PASS")

    print()
    print("=" * 70)
    print("BENIGN CORPUS (hand-written) — FP rate at DANGEROUS+ (ratchet, not fixed target)")
    print("=" * 70)
    fps, btotal = run_benign(args.verbose)
    fp_rate = 100.0 * fps / btotal if btotal else 0.0
    print(f"\n{fps}/{btotal} benign fixtures false-positived at DANGEROUS+ ({fp_rate:.1f}%).")
    benign_ok = check_ratchet("benign_fp_count", fps, baseline, args.update_baseline)
    gate_ok = gate_ok and benign_ok

    if args.real_corpus and args.real_corpus.exists():
        print()
        print("=" * 70)
        print(f"REAL-WORLD SAMPLE ({args.real_corpus.name}) — unlabeled, FP-rate proxy, ratcheted")
        print("=" * 70)
        rfps, rtotal, dist = run_real_corpus(args.real_corpus, args.sample_size, args.verbose)
        rfp_rate = 100.0 * rfps / rtotal if rtotal else 0.0
        print(f"\nScanned {rtotal} real skills. Label distribution: {dist}")
        print(f"{rfps}/{rtotal} flagged DANGEROUS+ ({rfp_rate:.1f}%). These are published, presumed-benign "
              f"skills, so this is a real-world FP-rate proxy, not a ground-truth benchmark.")
        real_ok = check_ratchet("real_corpus_dangerous_plus", rfps, baseline, args.update_baseline)
        gate_ok = gate_ok and real_ok

    # Always persist: check_ratchet bootstraps any missing key to the current
    # value on first run, and --update-baseline explicitly asked to record.
    _save_baseline(baseline)
    if args.update_baseline:
        print(f"\nBaseline updated: {baseline}")

    print(f"\nTotal eval time: {time.time() - t0:.1f}s")
    return 0 if gate_ok else 1


if __name__ == "__main__":
    sys.exit(main())
