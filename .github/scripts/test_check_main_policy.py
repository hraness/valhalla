import copy
import json
from pathlib import Path
import unittest

from check_main_policy import check_rule


class MainPolicyTests(unittest.TestCase):
    def setUp(self):
        self.expected = json.loads((Path(__file__).resolve().parents[1] / "main-ruleset.json").read_text())

    def test_response_metadata_and_order_do_not_change_policy(self):
        actual = copy.deepcopy(self.expected)
        actual["id"] = 12
        actual["rules"].reverse()
        actual["rules"][0]["parameters"]["required_status_checks"].reverse()
        actual["rules"][1]["parameters"]["allowed_merge_methods"] = ["merge", "squash", "rebase"]
        self.assertEqual(check_rule(self.expected, actual), [])

    def test_disabled_or_bypassed_policy_refuses(self):
        for field, value in [("enforcement", "disabled"),
                             ("bypass_actors", [{"actor_type": "RepositoryRole", "actor_id": 5}]),
                             ("conditions", {"ref_name": {"include": ["refs/heads/test"], "exclude": []}})]:
            with self.subTest(field=field):
                actual = copy.deepcopy(self.expected)
                actual[field] = value
                self.assertTrue(check_rule(self.expected, actual))

    def test_hidden_bypasses_are_never_a_full_audit(self):
        actual = copy.deepcopy(self.expected)
        del actual["bypass_actors"]
        self.assertTrue(check_rule(self.expected, actual))
        self.assertEqual(check_rule(self.expected, actual, public_view=True), [])
        actual["bypass_actors"] = [{"actor_type": "OrganizationAdmin", "bypass_mode": "always"}]
        self.assertTrue(check_rule(self.expected, actual, public_view=True))

    def test_missing_pr_check_app_binding_or_strictness_refuses(self):
        for mutation in ("pr", "check", "app", "strict"):
            with self.subTest(mutation=mutation):
                actual = copy.deepcopy(self.expected)
                checks = actual["rules"][-1]["parameters"]
                if mutation == "pr":
                    actual["rules"] = [r for r in actual["rules"] if r["type"] != "pull_request"]
                elif mutation == "check":
                    checks["required_status_checks"].pop(0)
                elif mutation == "app":
                    checks["required_status_checks"][0]["integration_id"] = None
                else:
                    checks["strict_required_status_checks_policy"] = False
                self.assertTrue(check_rule(self.expected, actual))


if __name__ == "__main__":
    unittest.main()
