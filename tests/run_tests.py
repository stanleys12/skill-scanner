#!/usr/bin/env python3
"""Assert the scanner's verdicts and findings on the sample skills in tests/skills/.

Pure stdlib, no network. Run: python3 tests/run_tests.py  (or via scripts/verify.sh).
Exit 0 only if every sample matches tests/expected.json.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCAN = os.path.join(ROOT, "scanner", "scan.py")


def scan(skill_dir):
    proc = subprocess.run([sys.executable, "-I", SCAN, skill_dir, "--no-infer", "--json"],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode not in (0, 1):
        raise SystemExit(f"scan.py failed on {skill_dir} (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)


def check(name, spec):
    d = scan(os.path.join(HERE, "skills", name))
    rules = {f["rule"] for f in d["findings"]}
    sevs = {f["severity"] for f in d["findings"]}
    errs = []
    if d["verdict"] != spec["verdict"]:
        errs.append(f"verdict {d['verdict']!r}, expected {spec['verdict']!r}")
    for r in spec.get("must_have_rules", []):
        if r not in rules:
            errs.append(f"missing expected finding {r}")
    for s in spec.get("must_not", []):
        if s in sevs:
            errs.append(f"has a {s}-severity finding it should not")
    for h in spec.get("must_contact", []):
        if h not in d["touches"]["hosts_contacted"]:
            errs.append(f"did not record contact with {h}")
    return d["verdict"], errs


def main():
    expected = json.load(open(os.path.join(HERE, "expected.json")))
    fails = 0
    for name, spec in expected.items():
        try:
            verdict, errs = check(name, spec)
        except Exception as e:  # noqa: BLE001
            print(f"[FAIL] {name}: {e}")
            fails += 1
            continue
        if errs:
            fails += 1
            print(f"[FAIL] {name} ({verdict})")
            for e in errs:
                print(f"         - {e}")
        else:
            print(f"[ok]   {name}: {verdict}")

    # Rule integrity: every rule id is unique. A duplicate id would silently shadow a finding
    # in any set keyed by rule (the scanner and this harness both key findings by rule id).
    sys.path.insert(0, ROOT)
    from scanner.rules import RULES
    ids = [r.id for r in RULES]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        fails += 1
        print(f"[FAIL] rule integrity: duplicate rule id(s): {', '.join(dupes)}")
    else:
        print(f"[ok]   rule integrity: {len(ids)} rules, all ids unique")

    # Determinism: scanning twice gives the same verdict + findings.
    a = scan(os.path.join(HERE, "skills", "malicious-backdoor"))
    b = scan(os.path.join(HERE, "skills", "malicious-backdoor"))
    if (a["verdict"], sorted((f["rule"], f["file"], f["line"]) for f in a["findings"])) != \
       (b["verdict"], sorted((f["rule"], f["file"], f["line"]) for f in b["findings"])):
        fails += 1
        print("[FAIL] determinism: two scans of the same skill disagreed")
    else:
        print("[ok]   determinism: repeated scan is identical")

    # SARIF: --sarif output parses as JSON and carries one result per finding.
    proc = subprocess.run([sys.executable, "-I", SCAN, os.path.join(HERE, "skills", "malicious-backdoor"), "--no-infer", "--sarif"],
                          capture_output=True, text=True, timeout=60)
    try:
        sarif = json.loads(proc.stdout)
        results = sarif["runs"][0]["results"]
        ok = sarif["version"] == "2.1.0" and len(results) == len(a["findings"]) and all(
            r["ruleId"] and r["level"] in ("error", "warning", "note") for r in results)
    except (ValueError, KeyError, IndexError):
        ok = False
    if ok:
        print("[ok]   sarif: valid JSON, one result per finding")
    else:
        fails += 1
        print("[FAIL] sarif: --sarif output is not a valid minimal SARIF 2.1.0 log")

    # --quiet: a single verdict line, and --fail-on still sets the exit code.
    proc = subprocess.run([sys.executable, "-I", SCAN, os.path.join(HERE, "skills", "malicious-backdoor"), "--no-infer", "--quiet", "--fail-on", "review"],
                          capture_output=True, text=True, timeout=60)
    lines = proc.stdout.strip().splitlines()
    if len(lines) == 1 and lines[0].startswith("VERDICT: ") and proc.returncode == 1:
        print("[ok]   quiet: one verdict line, --fail-on exit code kept")
    else:
        fails += 1
        print("[FAIL] quiet: --quiet should print one verdict line and still exit 1 on --fail-on")

    print()
    print("ALL TESTS PASS" if fails == 0 else f"{fails} TEST(S) FAILED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
