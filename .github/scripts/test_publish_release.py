"""Failure paths must leave public releases untouched."""

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from publish_release import (
    CODEQL_ANALYSIS_KEY, CODEQL_CHECKS, CODEQL_CATEGORIES, MAX_ANALYSIS_PAGES,
    asset_names, publish,
)


TAG = "v0.1.7"
SHA = "a" * 40
REPO = "hraness/valhalla"


class FakeGitHub:
    def __init__(self, assets):
        self.assets = assets
        self.calls = []
        self.main = SHA
        self.tag = {"type": "commit", "sha": SHA}
        self.annotated = None
        self.release = None
        self.upload_fails = False
        self.corrupt_download = False
        self.advance_main_after_upload = False
        self.fail_security_after_upload = False
        self.open_alert_after_upload = False
        self.alert_pages = [[], []]
        self.analysis_pages = None
        self.analyses = [dict(id=index, category=category, commit_sha=SHA,
                              analysis_key=CODEQL_ANALYSIS_KEY,
                              ref="refs/heads/main", error="", tool={"name": "CodeQL"})
                         for index, category in enumerate(sorted(CODEQL_CATEGORIES), 1)]
        self.checks = [dict(id=index, name=name, head_sha=SHA, status="completed",
                            conclusion="success", app={"slug": CODEQL_CHECKS[name]})
                       for index, name in enumerate(sorted(CODEQL_CHECKS), 1)]

    def __call__(self, *args):
        self.calls.append(args)
        if args[0] == "api":
            path = args[1].removeprefix(f"repos/{REPO}/")
            if path == "git/ref/heads/main":
                return json.dumps({"object": {"sha": self.main}})
            if path == f"git/ref/tags/{TAG}":
                return json.dumps({"object": self.tag})
            if path.startswith("git/tags/"):
                return json.dumps({"object": self.annotated})
            if path.startswith("commits/"):
                # Required checks span pages, as on an actual busy CI commit.
                assert args[-2:] == ("--paginate", "--slurp")
                return json.dumps([{"check_runs": self.checks[:2]}, {"check_runs": self.checks[2:]}])
            if path.startswith("code-scanning/analyses?"):
                assert "ref=refs%2Fheads%2Fmain" in path and "tool_name=CodeQL" in path
                assert "sort=created&direction=desc" in path
                number = int(path.rsplit("&page=", 1)[1])
                if self.analysis_pages is not None:
                    return json.dumps(self.analysis_pages[number - 1]
                                      if number <= len(self.analysis_pages) else [])
                start = (number - 1) * 100
                return json.dumps(self.analyses[start:start + 100])
            if path.startswith("code-scanning/alerts?"):
                assert "ref=refs%2Fheads%2Fmain" in path and "state=open" in path
                assert args[-2:] == ("--paginate", "--slurp")
                return json.dumps(self.alert_pages)
            if path == "releases?per_page=100":
                return json.dumps([[self.release] if self.release else []])
            raise AssertionError(f"unexpected API request: {args}")
        if args[:2] == ("release", "upload"):
            if self.upload_fails:
                raise subprocess.CalledProcessError(1, args)
            if self.advance_main_after_upload:
                self.main = "b" * 40
            if self.fail_security_after_upload:
                next(check for check in self.checks if check["name"] == "CodeQL")["conclusion"] = "failure"
            if self.open_alert_after_upload:
                self.alert_pages[-1].append({"number": 42, "state": "open"})
        elif args[:2] == ("release", "download"):
            destination = Path(args[args.index("--dir") + 1])
            for path in self.assets.iterdir():
                shutil.copy2(path, destination / path.name)
            if self.corrupt_download:
                next(destination.glob("*.tar.gz")).write_bytes(b"incomplete upload")
        return ""

    def mutations(self):
        return [args[1] for args in self.calls
                if args[0] == "release" and args[1] in {"create", "upload", "edit"}]


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.assets = Path(self.temporary.name)
        for name in asset_names(TAG):
            if name.endswith(".tar.gz"):
                content = name.encode()
                (self.assets / name).write_bytes(content)
                (self.assets / (name + ".sha256")).write_text(
                    f"{hashlib.sha256(content).hexdigest()}  {name}\n")
        self.gh = FakeGitHub(self.assets)

    def run_publish(self):
        with contextlib.redirect_stdout(io.StringIO()):
            publish(self.assets, TAG, SHA, REPO, self.gh)

    def test_complete_release_is_verified_before_publication(self):
        self.run_publish()
        self.assertEqual(self.gh.mutations(), ["create", "upload", "edit"])
        commands = [args[:2] for args in self.gh.calls]
        self.assertLess(commands.index(("release", "download")), commands.index(("release", "edit")))
        self.assertIn("--draft", next(args for args in self.gh.calls if args[:2] == ("release", "create")))

    def test_missing_artifact_blocks_all_network_access(self):
        next(self.assets.glob("*.tar.gz")).unlink()
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.calls, [])

    def test_native_only_release_cannot_omit_the_qualified_browser(self):
        for suffix in (".tar.gz", ".tar.gz.sha256"):
            (self.assets / f"valhalla-browser-{TAG}{suffix}").unlink()
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.calls, [])

    def test_checksum_mismatch_blocks_all_network_access(self):
        next(self.assets.glob("*.tar.gz")).write_bytes(b"corrupt")
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.calls, [])

    def test_non_main_or_moved_tag_blocks_mutations(self):
        for field in ("main", "tag"):
            with self.subTest(field=field):
                gh = FakeGitHub(self.assets)
                setattr(gh, field, "b" * 40 if field == "main" else {"type": "commit", "sha": "b" * 40})
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])

    def test_annotated_tag_is_peeled(self):
        self.gh.tag = {"type": "tag", "sha": "b" * 40}
        self.gh.annotated = {"type": "commit", "sha": SHA}
        self.run_publish()
        self.assertEqual(self.gh.mutations()[-1], "edit")

    def test_missing_failed_foreign_stale_or_pending_codeql_blocks_mutations(self):
        for change in ("missing", "failure", "foreign", "stale", "pending"):
            with self.subTest(change=change):
                gh = FakeGitHub(self.assets)
                check = gh.checks[0]
                if change == "missing":
                    gh.checks.pop(0)
                elif change == "failure":
                    check["conclusion"] = "failure"
                elif change == "foreign":
                    check["app"]["slug"] = "third-party"
                elif change == "stale":
                    check["head_sha"] = "b" * 40
                else:
                    check["status"] = "in_progress"
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])

    def test_new_failed_codeql_retry_overrides_older_success(self):
        newer = copy.deepcopy(self.gh.checks[0])
        newer.update(id=100, conclusion="failure")
        self.gh.checks.insert(0, newer)
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), [])

    def test_c_cpp_check_is_required_and_must_be_authentic_complete_and_current(self):
        # The four previously configured languages and empty alert inventory
        # cannot substitute for coverage of the newly merged C source.
        for change in ("missing", "pending", "failure", "stale", "foreign"):
            with self.subTest(change=change):
                gh = FakeGitHub(self.assets)
                check = next(c for c in gh.checks if c["name"] == "Analyze (c-cpp)")
                if change == "missing":
                    gh.checks.remove(check)
                elif change == "pending":
                    check.update(status="in_progress", conclusion=None)
                elif change == "failure":
                    check["conclusion"] = "failure"
                elif change == "stale":
                    check["head_sha"] = "b" * 40
                else:
                    check["app"]["slug"] = "third-party"
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])

    def test_c_cpp_configuration_test_success_does_not_replace_main_analysis(self):
        for change in ("missing", "failed", "stale", "wrong_ref", "foreign_key"):
            with self.subTest(change=change):
                gh = FakeGitHub(self.assets)
                row = next(a for a in gh.analyses if a["category"] == "/language:c-cpp")
                if change == "missing":
                    gh.analyses.remove(row)
                elif change == "failed":
                    row["error"] = "extraction failed"
                elif change == "stale":
                    row["commit_sha"] = "b" * 40
                elif change == "wrong_ref":
                    row["ref"] = "refs/pull/91/head"
                else:
                    row["analysis_key"] = ".github/workflows/other.yml:analyze"
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])

    def test_new_c_cpp_pending_or_failed_check_overrides_older_success(self):
        for status, conclusion in (("in_progress", None), ("completed", "failure")):
            with self.subTest(status=status):
                gh = FakeGitHub(self.assets)
                check = copy.deepcopy(next(c for c in gh.checks
                                           if c["name"] == "Analyze (c-cpp)"))
                check.update(id=100, status=status, conclusion=conclusion)
                gh.checks.append(check)
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])

    def test_c_cpp_security_change_during_upload_leaves_draft(self):
        for change in ("missing_analysis", "failed_analysis", "failed_check"):
            with self.subTest(change=change):
                gh = FakeGitHub(self.assets)

                def change_after_upload(*args):
                    result = gh(*args)
                    if args[:2] == ("release", "upload"):
                        row = next(a for a in gh.analyses if a["category"] == "/language:c-cpp")
                        if change == "missing_analysis":
                            gh.analyses.remove(row)
                        elif change == "failed_analysis":
                            row["error"] = "replacement failed"
                        else:
                            next(c for c in gh.checks if c["name"] == "Analyze (c-cpp)")["conclusion"] = "failure"
                    return result

                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, change_after_upload)
                self.assertEqual(gh.mutations(), ["create", "upload"])

    def test_new_managed_language_requires_explicit_release_policy_update(self):
        for key in (CODEQL_ANALYSIS_KEY, "dynamic/github-code-scanning/codeql:upload"):
            with self.subTest(key=key):
                gh = FakeGitHub(self.assets)
                gh.analyses.insert(0, dict(
                    id=100, category="/language:go", commit_sha=SHA,
                    analysis_key=key, ref="refs/heads/main", error="",
                    tool={"name": "CodeQL"},
                ))
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])

    def test_unknown_current_analysis_job_blocks_before_results_exist(self):
        for status, conclusion in (("in_progress", None), ("completed", "success"),
                                   ("completed", "failure")):
            with self.subTest(status=status, conclusion=conclusion):
                gh = FakeGitHub(self.assets)
                gh.checks.append(dict(id=100, name="Analyze (go)", head_sha=SHA,
                                      status=status, conclusion=conclusion,
                                      app={"slug": "github-actions"}))
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])
                self.assertFalse(any("code-scanning/analyses?" in args[1]
                                     for args in gh.calls if args[0] == "api"))

    def test_foreign_or_old_unknown_jobs_neither_poison_nor_supply_coverage(self):
        for change in ("historical", "foreign"):
            for missing_required in (False, True):
                with self.subTest(change=change, missing_required=missing_required):
                    gh = FakeGitHub(self.assets)
                    row = dict(id=100, name="Analyze (go)", head_sha=SHA,
                               status="completed", conclusion="success",
                               app={"slug": "github-actions"})
                    if change == "historical":
                        row["head_sha"] = "b" * 40
                    else:
                        row["app"]["slug"] = "third-party"
                    gh.checks.append(row)
                    if missing_required:
                        gh.checks = [c for c in gh.checks if c["name"] != "Analyze (c-cpp)"]
                        with self.assertRaises(ValueError):
                            publish(self.assets, TAG, SHA, REPO, gh)
                        self.assertEqual(gh.mutations(), [])
                    else:
                        with contextlib.redirect_stdout(io.StringIO()):
                            publish(self.assets, TAG, SHA, REPO, gh)
                        self.assertEqual(gh.mutations(), ["create", "upload", "edit"])

    def test_unknown_job_appearing_during_upload_leaves_draft(self):
        def change_after_upload(*args):
            result = self.gh(*args)
            if args[:2] == ("release", "upload"):
                self.gh.checks.append(dict(id=100, name="Analyze (go)", head_sha=SHA,
                                          status="in_progress", conclusion=None,
                                          app={"slug": "github-actions"}))
            return result

        with self.assertRaises(ValueError):
            publish(self.assets, TAG, SHA, REPO, change_after_upload)
        self.assertEqual(self.gh.mutations(), ["create", "upload"])

    def test_managed_promotion_upload_key_establishes_exact_main_coverage(self):
        for all_upload in (False, True):
            with self.subTest(all_upload=all_upload):
                gh = FakeGitHub(self.assets)
                for index, row in enumerate(gh.analyses):
                    if all_upload or index % 2 == 0:
                        row["analysis_key"] = "dynamic/github-code-scanning/codeql:upload"
                with contextlib.redirect_stdout(io.StringIO()):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), ["create", "upload", "edit"])

    def test_managed_key_prefix_or_suffix_cannot_establish_coverage(self):
        for key in ("dynamic/github-code-scanning/codeql:upload-other",
                    "dynamic/github-code-scanning/codeql:upload/",
                    "other/dynamic/github-code-scanning/codeql:analyze"):
            with self.subTest(key=key):
                gh = FakeGitHub(self.assets)
                next(a for a in gh.analyses if a["category"] == "/language:c-cpp")["analysis_key"] = key
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])

    def test_unknown_current_managed_category_on_second_page_blocks(self):
        self.gh.analyses *= 20  # Complete first page already has the required five.
        self.gh.analyses.append(dict(
            id=1000, category="/language:go", commit_sha=SHA,
            analysis_key="dynamic/github-code-scanning/codeql:upload",
            ref="refs/heads/main", error="", tool={"name": "CodeQL"},
        ))
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), [])
        self.assertTrue(any(args[1].endswith("&page=2") for args in self.gh.calls))

    def test_complete_paginated_history_does_not_override_newest_required_analyses(self):
        self.gh.analyses *= 20
        old = copy.deepcopy(self.gh.analyses[0])
        old.update(commit_sha="b" * 40, error="old failure")
        self.gh.analyses.append(old)
        self.run_publish()
        self.assertEqual(self.gh.mutations(), ["create", "upload", "edit"])
        self.assertEqual(sum(args[1].endswith("&page=2") for args in self.gh.calls), 2)

    def test_full_analysis_inventory_cap_refuses_even_with_known_successes(self):
        self.gh.analyses *= 20 * MAX_ANALYSIS_PAGES
        with self.assertRaisesRegex(ValueError, "complete-review bound"):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), [])
        calls = [args for args in self.gh.calls if "code-scanning/analyses?" in args[1]]
        self.assertEqual(len(calls), MAX_ANALYSIS_PAGES)

    def test_malformed_first_or_later_analysis_pages_refuse(self):
        for malformed in (None, {}, [None], [{}] * 101):
            for number in (1, 2):
                with self.subTest(malformed=malformed, number=number):
                    gh = FakeGitHub(self.assets)
                    gh.analysis_pages = ([gh.analyses * 20] if number == 2 else []) + [malformed]
                    with self.assertRaisesRegex(ValueError, "inventory is malformed"):
                        publish(self.assets, TAG, SHA, REPO, gh)
                    self.assertEqual(gh.mutations(), [])

    def test_later_analysis_api_failure_blocks_before_mutation_or_publication(self):
        for after_upload in (False, True):
            with self.subTest(after_upload=after_upload):
                gh = FakeGitHub(self.assets)
                gh.analyses *= 20

                def fail_later_page(*args):
                    if (args[0] == "api" and "code-scanning/analyses?" in args[1]
                            and args[1].endswith("&page=2")
                            and (not after_upload or "upload" in gh.mutations())):
                        raise subprocess.CalledProcessError(1, args)
                    return gh(*args)

                with self.assertRaises(subprocess.CalledProcessError):
                    publish(self.assets, TAG, SHA, REPO, fail_later_page)
                self.assertEqual(gh.mutations(), ["create", "upload"] if after_upload else [])

    def test_historical_or_unmanaged_categories_neither_poison_nor_supply_coverage(self):
        for change in ("historical", "unmanaged"):
            for missing_required in (False, True):
                with self.subTest(change=change, missing_required=missing_required):
                    gh = FakeGitHub(self.assets)
                    row = dict(id=100, category="/language:go", commit_sha=SHA,
                               analysis_key=CODEQL_ANALYSIS_KEY, ref="refs/heads/main",
                               error="", tool={"name": "CodeQL"})
                    if change == "historical":
                        row["commit_sha"] = "b" * 40
                    else:
                        row["analysis_key"] = ".github/workflows/other.yml:analyze"
                    gh.analyses.insert(0, row)
                    if missing_required:
                        gh.analyses = [a for a in gh.analyses if a["category"] != "/language:c-cpp"]
                        with self.assertRaises(ValueError):
                            publish(self.assets, TAG, SHA, REPO, gh)
                        self.assertEqual(gh.mutations(), [])
                    else:
                        with contextlib.redirect_stdout(io.StringIO()):
                            publish(self.assets, TAG, SHA, REPO, gh)
                        self.assertEqual(gh.mutations(), ["create", "upload", "edit"])

    def test_successful_analysis_jobs_do_not_override_security_verdict(self):
        for change in ("failure", "foreign", "stale", "pending"):
            with self.subTest(change=change):
                gh = FakeGitHub(self.assets)
                check = next(check for check in gh.checks if check["name"] == "CodeQL")
                if change == "failure":
                    check["conclusion"] = "failure"
                elif change == "foreign":
                    # A workflow with the same name cannot impersonate GitHub's verdict.
                    check["app"]["slug"] = "github-actions"
                elif change == "stale":
                    check["head_sha"] = "b" * 40
                else:
                    check["status"] = "in_progress"
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])

    def test_main_without_pr_verdict_requires_exact_analysis_and_empty_alerts(self):
        self.gh.checks = [c for c in self.gh.checks if c['name'] != 'CodeQL']
        self.run_publish()
        self.assertEqual(self.gh.mutations(), ["create", "upload", "edit"])

    def test_missing_failed_stale_foreign_or_wrong_ref_analysis_blocks(self):
        for change in ("missing", "failure", "foreign", "stale", "wrong_ref",
                       "missing_analysis_key", "foreign_analysis_key"):
            with self.subTest(change=change):
                gh = FakeGitHub(self.assets)
                row = gh.analyses[0]
                if change == "missing":
                    gh.analyses.pop(0)
                elif change == "failure":
                    row['error'] = 'extraction failed'
                elif change == "foreign":
                    row['tool']['name'] = 'other'
                elif change == "stale":
                    row['commit_sha'] = 'b' * 40
                elif change == "wrong_ref":
                    row['ref'] = 'refs/pull/85/head'
                elif change == "missing_analysis_key":
                    row.pop('analysis_key')
                else:
                    row['analysis_key'] = '.github/workflows/other.yml:analyze'
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])

    def test_new_failed_analysis_overrides_success(self):
        row = copy.deepcopy(self.gh.analyses[0])
        row.update(id=100, error='replacement failed')
        self.gh.analyses.insert(0, row)
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), [])

    def test_new_foreign_analysis_cannot_fall_back_to_managed_success(self):
        row = copy.deepcopy(self.gh.analyses[0])
        row.update(id=100, analysis_key='.github/workflows/other.yml:analyze')
        self.gh.analyses.insert(0, row)
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), [])

    def test_newest_created_analysis_wins_even_with_a_smaller_identifier(self):
        row = copy.deepcopy(self.gh.analyses[0])
        row.update(id=0, error='newest replacement failed')
        self.gh.analyses.insert(0, row)
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), [])

    def test_code_scanning_api_failure_blocks_before_mutation_or_publication(self):
        for endpoint in ('analyses', 'alerts'):
            for after_upload in (False, True):
                with self.subTest(endpoint=endpoint, after_upload=after_upload):
                    gh = FakeGitHub(self.assets)

                    def fail_api(*args):
                        if (args[0] == 'api' and f'/code-scanning/{endpoint}?' in args[1]
                                and (not after_upload or 'upload' in gh.mutations())):
                            # Includes a failed later page: run_gh checks the
                            # process exit status before parsing partial stdout.
                            raise subprocess.CalledProcessError(1, args, output='[[]]')
                        return gh(*args)

                    with self.assertRaises(subprocess.CalledProcessError):
                        publish(self.assets, TAG, SHA, REPO, fail_api)
                    self.assertEqual(gh.mutations(), ['create', 'upload'] if after_upload else [])

    def test_open_alert_on_later_page_blocks_despite_all_successful_checks(self):
        self.gh.alert_pages[-1] = [{"number": 42, "state": "open"}]
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), [])

    def test_malformed_or_missing_alert_pages_refuse(self):
        for pages in ([], {}, [None], [{}]):
            with self.subTest(pages=pages):
                self.gh.alert_pages = pages
                with self.assertRaises(ValueError):
                    self.run_publish()
                self.assertEqual(self.gh.mutations(), [])

    def test_alert_reopened_during_upload_leaves_draft(self):
        self.gh.open_alert_after_upload = True
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), ["create", "upload"])

    def test_new_failed_security_verdict_overrides_older_success(self):
        check = next(check for check in self.gh.checks if check["name"] == "CodeQL")
        newer = copy.deepcopy(check)
        newer.update(id=100, conclusion="failure")
        self.gh.checks.insert(0, newer)
        # A later workflow check called CodeQL must not hide the actual failure.
        foreign = copy.deepcopy(check)
        foreign.update(id=101, app={"slug": "github-actions"})
        self.gh.checks.append(foreign)
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), [])

    def test_partial_upload_never_publishes(self):
        self.gh.upload_fails = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), ["create", "upload"])

    def test_corrupt_download_never_publishes(self):
        self.gh.corrupt_download = True
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertNotIn("edit", self.gh.mutations())

    def test_main_moving_during_upload_leaves_draft(self):
        self.gh.advance_main_after_upload = True
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), ["create", "upload"])

    def test_security_failure_during_upload_leaves_draft(self):
        self.gh.fail_security_after_upload = True
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), ["create", "upload"])

    def test_existing_draft_is_completed(self):
        self.gh.release = {"tag_name": TAG, "draft": True}
        self.run_publish()
        self.assertEqual(self.gh.mutations(), ["upload", "edit"])

    def test_published_release_retry_is_read_only(self):
        self.gh.release = {"tag_name": TAG, "draft": False}
        self.run_publish()
        self.assertEqual(self.gh.mutations(), [])

    def test_published_release_with_different_bytes_is_never_overwritten(self):
        self.gh.release = {"tag_name": TAG, "draft": False}
        self.gh.corrupt_download = True
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), [])


if __name__ == "__main__":
    unittest.main()
