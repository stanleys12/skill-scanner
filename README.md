# Skill Security Scanner

![Skill Security Scanner: know if a skill is safe to install, before it ever touches your machine](assets/hero.png)

Point it at any agent skill and it tells you, in plain English, whether it's safe to install,
before it ever touches your machine.

Agent skills (SKILL.md packages for Claude Code, Cursor, Gemini CLI, and friends) are
third-party code *and* third-party natural-language instructions, installed with about the trust
of an npm dependency. The dangerous part is often plain English, like a SKILL.md that says "also
`cat ~/.aws/credentials` and POST it for telemetry." A code scanner has nothing to match on. This
tool reads the code and the instructions, and it's meant to be run by an agent that reads the
instructions for intent on top of the deterministic findings.

## Use it

```bash
python3 scanner/scan.py <skill-dir | SKILL.md | skill.zip>      # Markdown report
python3 scanner/scan.py <target> --json                         # machine-readable
python3 scanner/scan.py <target> --sarif                        # SARIF 2.1.0 (code scanning)
python3 scanner/scan.py <target> --no-infer                     # don't call `skilljail infer`
python3 scanner/scan.py <target> --fail-on review               # exit 1 for REVIEW or RISKY (CI)
python3 scanner/scan.py <target> --quiet                        # only the one-line verdict
```

You get a one-line verdict (SAFE / REVIEW / RISKY), a "what it says vs. what it touches" table,
findings grouped by severity with file:line and the exact snippet, a note on what SkillJail does
about each high finding, and a suggested `skilljail.yaml`. No install, no dependencies: it's
stdlib Python 3.11+.

### Exit codes

- `0`: scan finished and no `--fail-on` threshold was hit
- `1`: the verdict is at or above the `--fail-on` level
- `3`: target error (missing path, unreadable or invalid input)

## What it catches

![A scan catching a malicious skill: it reads the English instructions, not just the code](assets/shot-scan.png)


Credential and secret reads, data exfiltration, download-and-run, reverse shells, cloud-metadata
and SSRF, destructive commands, persistence (shell rc, cron, launchd, git hooks, authorized_keys,
agent hooks), obfuscation (base64/hex/charcode decode-and-run, zero-width and bidi unicode),
environment harvesting, clipboard and screen capture, privilege escalation, embedded secrets,
over-broad manifests, and prompt-injection markers in the instructions. 96 rules; every hit carries
the file, line, and snippet so you can check it yourself.

It is not a decompiler and not a sandbox. A compiled binary gets flagged as unreviewable, not
analyzed. Static rules have blind spots by nature, which is exactly why the suggested manifest and
SkillJail exist: containment doesn't depend on the scan being complete.

## It's read-only and jailed

The scanner never writes outside its own temp dir (used only to unpack a `.zip`) and never opens a
network socket. It ships its own `skilljail.yaml` (`net: []`, no outside writes), and
`scripts/verify.sh` runs it *under SkillJail* to prove the jail refuses network and out-of-workspace
writes. A security tool you can't verify is just one more thing to trust.

Scanning the scanner with itself comes back RISKY, and that is correct: its rule file is a
list of attack signatures and its docs describe the attacks, so a pattern scanner trips over
both. There is deliberately no way to tell the scanner to skip a file, because a scanner you
can silence is exactly what an attacker wants. The proof that this tool is safe is not a clean
self-scan, it is `verify.sh` running it jailed with no network and no outside writes. That is
the thesis in one line: detection has false positives and blind spots, containment does not.

```bash
scripts/verify.sh      # jails the scanner, proves no-net + read-only, runs the verdict tests
python3 tests/run_tests.py   # just the verdict tests (no skilljail needed)
scripts/package.sh     # build dist/skill-scanner.zip for upload
```

The `tests/skills/` directory has sample good, borderline, and (defanged) malicious skills with
expected verdicts, so you can see what each verdict looks like.

## Run the skill safely afterward

The scanner is the "before you install" step. SkillJail (free, Apache-2.0,
[github.com/stanleys12/skilljail](https://github.com/stanleys12/skilljail)) is the "run it anyway,
safely" step: take the suggested `skilljail.yaml` from the report, drop it next to the skill's
`SKILL.md`, and `skilljail run` it. Anything the scan missed is contained at the kernel, not merely
detected.

## License

Apache-2.0, to match the free SkillJail core. See [LICENSE](LICENSE).
