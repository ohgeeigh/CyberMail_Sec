# Configs

Store scanner and test settings that are safe to commit. Examples:

- A Bandit configuration that excludes `.venv` and generated reports
- `pytest` markers shared by the cybersecurity suite
- Severity thresholds the team has agreed, once those thresholds are not secret

Do not put API tokens, passwords, connection strings, or private keys in this folder. Those values belong in `.env`, which is gitignored.

Interns: add a config file when a scanner needs shared options. Document each new file with a short comment at the top explaining why the setting exists.
