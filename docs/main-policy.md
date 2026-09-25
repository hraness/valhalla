# Checked-PR enforcement

The repository custom property `main_policy=checked-pr` selects the delivery
mode; the enforced rule is the repository-owned ruleset
[Protect main delivery](https://github.com/hraness/valhalla/rules/23970698).
It requires a pull request on the default branch, forbids branch deletion and
force pushes, and has no bypass actors. The pull request rule counts no
approvals and does not require resolved review threads; it does require an
extra approval for changes that carry no author attribution. Independent
agent review remains the source-review gate.

The required checks are the Rust `check` aggregate, the managed `CodeQL`
security verdict, and the five `Analyze` language jobs. The `CodeQL` context
is the code-scanning verdict, so a green `Analyze` job alone does not satisfy
it. Checks are non-strict: the candidate does not have to include current
main, so auto-merge does not stall behind another merge.

The reviewed source is [main-ruleset.json](../.github/main-ruleset.json). The
organization's shared delivery baseline (`hraness/.github`,
`scripts/apply-delivery-policy.py`) applies and maintains the live rule, so
the ruleset name and review-thread settings follow that baseline rather than
a repository-specific shape. Subsequent changes go through a reviewed source
change and a fresh administrative readback under `docs/evidence/`. Never
delete or disable the rule to work around a failing check.

On 23 September 2026 the repository ran the reviewed ruleset
[23889123](https://github.com/hraness/valhalla/rules/23889123) with strict
checks and required thread resolution
([readback](evidence/main-policy-20260923.json)). On 25 September 2026 the
shared baseline replaced it with the current ruleset
([readback](evidence/main-policy-20260925.json)).

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
