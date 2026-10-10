#!/bin/zsh
# Prove two things, then run the scanner's own tests:
#   1. The scanner is harmless to install: run it UNDER SkillJail, with its own
#      skilljail.yaml (net: [], write: none), and show it still works. Then show that
#      the jail actually denies network and out-of-workspace writes to anything running
#      under that manifest. That is the trust story: the scanner can't phone home or
#      touch your files even if it wanted to.
#   2. The verdicts are correct: run tests/run_tests.py over the sample skills.
#
# Nothing here needs the network or touches real credentials. Re-run any time:
#   scripts/verify.sh        (auto-detects skilljail; skips the jail part if it's missing)
set -u
HERE=${0:A:h}
ROOT=${HERE:h}
cd "$ROOT"
SJ=${SKILLJAIL_BIN:-$(command -v skilljail 2>/dev/null)}
PY=${PYTHON:-python3}
fail=0
pass() { print "  [ok] $1" }
bad()  { print "  [FAIL] $1"; fail=1 }

print "== 1. the scanner runs jailed, read-only, no network =="
if [[ -z "$SJ" ]]; then
  print "  [skip] skilljail not installed — install it from https://github.com/stanleys12/skilljail to verify the jail"
  print "         (the scanner itself is pure-stdlib and needs nothing to run; see part 2)"
else
  "$SJ" check "$ROOT" >/dev/null 2>&1 && pass "the scanner's own skilljail.yaml is a valid manifest" \
    || bad "the scanner's skilljail.yaml did not validate"

  # The scanner, jailed by its own manifest, scanning a sample skill: must still work.
  if "$SJ" run --skill "$ROOT" --workspace "$ROOT" -- \
       "$PY -I scanner/scan.py tests/skills/malicious-backdoor --no-infer" 2>/dev/null | grep -q "VERDICT: RISKY"; then
    pass "scanner works under its own jail (flagged the backdoor sample RISKY)"
  else
    bad "scanner did not run correctly under its own jail"
  fi

  # Under that same manifest (net: []), any network attempt is refused at the proxy.
  if "$SJ" run --skill "$ROOT" --workspace "$ROOT" -- \
       "$PY -I -c 'import urllib.request; urllib.request.urlopen(\"https://example.com\", timeout=5)'" >/dev/null 2>&1; then
    bad "network reached the outside world under the scanner's manifest (should be blocked)"
  else
    pass "network is blocked under the scanner's manifest (net: [] enforced at the proxy)"
  fi

  # Under that manifest (write: none), a write outside the workspace is denied at the kernel.
  CANARY="$HOME/.skill-scanner-verify-canary"
  rm -f "$CANARY"
  "$SJ" run --skill "$ROOT" --workspace "$ROOT" -- "sh -c 'echo x > $CANARY'" >/dev/null 2>&1
  if [[ -e "$CANARY" ]]; then
    bad "a write to \$HOME succeeded under the scanner's manifest (should be denied)"; rm -f "$CANARY"
  else
    pass "writes outside the workspace are denied under the scanner's manifest"
  fi
fi

print "\n== 2. the verdicts are correct =="
if "$PY" tests/run_tests.py; then
  pass "all sample-skill verdicts match tests/expected.json"
else
  bad "sample-skill verdicts did not match"
fi

print "\n$([[ $fail -eq 0 ]] && print 'VERIFY PASSED' || print 'VERIFY FAILED')"
exit $fail
