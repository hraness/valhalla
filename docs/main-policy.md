# Checked-PR enforcement

The repository custom property `main_policy=checked-pr` describes intent; it
does not enforce a branch rule. On 23 September 2026, the audit found no
repository rulesets and no effective rules on `main`. The organization rulesets
then observed were scoped to Soundfish. No shared reconciliation workflow was
found in the organization guidance repository.

The repository-owned source is [main-ruleset.json](../.github/main-ruleset.json).
It requires a pull request, resolved review threads, the complete Rust `check`
and all five current CodeQL analysis checks, bound to the GitHub Actions app.
It separately requires the managed `CodeQL` security verdict, bound to the
GitHub Advanced Security app (57789), as observed on prior PR heads. Successful
analysis jobs alone do not establish that this security verdict passed.
Strict checks require the candidate to include current main. It forbids branch
deletion and force pushes and has no bypass actors. Independent agent review
remains the source-review gate; no additional human-approval count was added.

After independent review, the exact configuration was created as
[ruleset 23889123](https://github.com/hraness/valhalla/rules/23889123). The
[administrative readback](evidence/main-policy-20260923.json) records the full
rule, effective branch rules, protected status and source-config digest.
Subsequent changes require source review, an authorized administrator applying
the exact reviewed JSON to that ID, and a fresh full readback. Never delete or
disable the rule to work around a failing check.

Run the full read-only administrative audit with:

```console
python3 .github/scripts/check_main_policy.py --gh /absolute/path/to/gh
```

The required Rust aggregate also includes a read-only `main-policy` job.
GitHub's read-only API view [omits bypass actors](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset).
CI therefore uses explicit `--public-view`: it checks disclosed rule fields and
reports that hidden bypasses still require an administrative audit. Missing
bypass disclosure is never treated as an empty list by the default full audit.
Neither mode changes GitHub settings or needs a stored personal token.
