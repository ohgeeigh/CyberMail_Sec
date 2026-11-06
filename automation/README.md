# Automation

Put repeatable security tasks here. `generate_security_report.py` is the example. It builds a Markdown report from scanner output already saved in `reports/`.

When you add a script:

- Give it a docstring and a `main` function.
- Load any required settings from the environment.
- Stamp the report with the UTC time it was created.
- Omit tokens, passwords, and personal data from the file you write.
- Use an exit code of `0` for success and a non-zero code with a clear message when the task cannot finish.

Interns: extend the report generator so it groups findings by severity. Add new automation only after the matching scanner or test exists.
