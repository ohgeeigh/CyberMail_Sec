# Scanners

Put one runnable script per security tool in this folder.

The first example is `bandit_runner.py`. Use it as the pattern for new scanners:

- Resolve paths with `pathlib`.
- Write reports under `reports/` with a UTC timestamp in the file name.
- Return `0` when the scan is clean, `1` when the tool reports findings, and `2` when the tool fails to run.
- Keep secrets out of the script. Configuration that is safe to commit belongs in `configs/`.

## Suggested scripts to add

| Script | Tool | Purpose |
| --- | --- | --- |
| `bandit_runner.py` | Bandit | Common Python security issues in this lab |
| `pip_audit_runner.py` | pip-audit | Known vulnerabilities in `requirements.txt` |
| `detect_secrets_runner.py` | detect-secrets | Accidental secrets in the tree |

Interns: implement `pip_audit_runner.py` and `detect_secrets_runner.py`. Do not scan production systems from these scripts. Point file-based scanners at this repository, or at a local checkout your lead has named.
