# Contributing

The most common contribution is a new detection rule. Everything is pure stdlib and
needs no network.

## Add a detection rule

1. **Add the rule to `RULES` in `scanner/rules.py`**, next to related rules:

   ```python
   Rule("CRED-AWS", "credentials", "high",
        HOME + r"/\.aws\b|\.aws/credentials|aws_secret_access_key",
        "Reads AWS credentials, which have nothing to do with most skills."),
   ```

   - `id` is unique and upper-case, prefixed by its category (`CRED-`, `EXFIL-`, `DL-`, ...).
   - `category` should be one that has an entry in `JAIL_NOTES` (add one if you need a new category).
   - `severity` is `high` (verdict RISKY), `medium` (REVIEW) or `low` (informational).
   - The pattern is a regex applied to one line; pass `multiline=True` to match across the whole file,
     or `files=(...)` to limit it to certain extensions or names. Case-insensitive by default.
   - `why` is one sentence a non-expert can act on.
   - Keep `rules.py` boring: no network, no imports beyond `re`.

2. **Add a sample skill under `tests/skills/<name>/`** with a `SKILL.md` (and any scripts) that
   triggers the rule. Name it `malicious-*`, `borderline-*` or `clean-*`. Make malicious samples
   defanged: use reserved `.example` hosts and nothing wired to run. If the rule fits an existing
   sample, extend that one instead.

3. **Add its entry to `tests/expected.json`**:

   ```json
   "malicious-dns-hijack": {"verdict": "RISKY", "must_have_rules": ["YOUR-RULE-ID"]}
   ```

   `must_have_rules`, `must_not` (severities that must be absent) and `must_contact` (hosts the scan must report contacting) are optional.

4. **Regenerate the rule catalog**: `python3 scripts/gen_rules_doc.py` (updates `docs/RULES.md`,
   which the suite checks is up to date).

5. **Run the suite**: `python3 tests/run_tests.py`. It must exit 0. Existing clean samples
   must stay SAFE, so check that your pattern does not cause false positives.

`scripts/verify.sh` runs the same suite plus the SkillJail checks, if `skilljail` is installed.
