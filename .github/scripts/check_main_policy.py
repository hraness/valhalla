#!/usr/bin/env python3
"""Read-only audit of the repository-owned checked-PR rule. Never mutates GitHub."""
import argparse
import json
from pathlib import Path
import subprocess


def canonical(value):
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in value.items()}
    if isinstance(value, list):
        return sorted((canonical(item) for item in value),
                      key=lambda item: json.dumps(item, sort_keys=True))
    return value


def check_rule(expected, observed, public_view=False):
    """Ignore response metadata, but require every owned policy field exactly."""
    errors = []
    for key in ("name", "target", "enforcement", "bypass_actors", "conditions"):
        # GitHub omits bypass actors unless the caller may write the ruleset.
        # An explicit public audit cannot prove their absence; the default
        # administrative audit still refuses missing disclosure.
        if key == "bypass_actors" and public_view and key not in observed:
            continue
        if canonical(observed.get(key)) != canonical(expected[key]):
            errors.append(f"ruleset {key} differs from the reviewed policy")
    actual_rules = {rule.get("type"): rule for rule in observed.get("rules", [])}
    if len(actual_rules) != len(observed.get("rules", [])):
        errors.append("duplicate rule types")
    for rule in expected["rules"]:
        actual = actual_rules.get(rule["type"], {})
        required_parameters = rule.get("parameters", {})
        observed_parameters = actual.get("parameters", {})
        owned_parameters = {key: observed_parameters.get(key) for key in required_parameters}
        if canonical(owned_parameters) != canonical(required_parameters):
            errors.append(f"{rule['type']} parameters differ from the reviewed policy")
        if actual.get("type") != rule["type"]:
            errors.append(f"required {rule['type']} rule is absent")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--public-view", action="store_true",
                        help="audit disclosed rules only; does not attest absence of hidden bypasses")
    args = parser.parse_args()
    expected = json.loads((Path(__file__).resolve().parents[1] / "main-ruleset.json").read_text())

    def get(endpoint):
        return json.loads(subprocess.check_output(
            [args.gh, "api", endpoint], text=True, timeout=30))

    # This policy cannot be used to inspect or mutate an inferred repository.
    base = "repos/hraness/valhalla"
    rows = get(base + "/rulesets?includes_parents=false&per_page=100")
    matches = [row for row in rows if row.get("name") == expected["name"]]
    if len(matches) != 1:
        parser.exit(1, "expected exactly one repository-owned Valhalla checked-PR ruleset\n")
    observed = get(base + "/rulesets/" + str(matches[0]["id"]))
    errors = check_rule(expected, observed, args.public_view)
    properties = get(base + "/properties/values")
    if not any(row.get("property_name") == "main_policy" and row.get("value") == "checked-pr"
               for row in properties):
        errors.append("main_policy property does not select checked-pr")
    if errors:
        parser.exit(1, "\n".join(errors) + "\n")
    if args.public_view and "bypass_actors" not in observed:
        print("Valhalla main: reviewed public rules match; hidden bypass actors require administrative audit")
    else:
        print("Valhalla main: reviewed checked-PR ruleset active, no bypass actors, required checks bound")


if __name__ == "__main__":
    main()
