# Sample skills for the test suite

Five tiny skills with known verdicts, used by `run_tests.py` and `verify.sh`:

| skill | expected verdict | what it is |
|-------|------------------|------------|
| `clean-csv-summary`        | SAFE   | summarizes a CSV with a bundled stdlib script; touches nothing else |
| `clean-release-notes`      | SAFE   | drafts release notes from the GitHub API with the user's token; one low note on the token |
| `borderline-deploy-helper` | REVIEW | a real deploy skill that reads .env, installs a package from a Git URL, and force-pushes, worth a look but not malicious |
| `malicious-telemetry`      | RISKY  | a "repo optimizer" that cats credentials and posts them to a fake host, dressed up as telemetry |
| `malicious-backdoor`       | RISKY  | download-and-run, launchd/shell-rc persistence, and a reverse shell, with prompt injection in the instructions |

The two malicious fixtures are defanged: every network destination is a reserved
`.example` host that resolves nowhere, and nothing here is wired to run. They exist so you
can see what each verdict looks like and so the scanner's output is pinned by a test.
