"""Fail-closed inventory and real-format TLC evidence contract tests."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from run_tlc import (
    EvidenceError, ROOT, assess_result, check_copied_inputs, checked_path,
    config_declarations, digest, load_inventory, model_variables, parse_trace, read_json,
)

STATS = "4 states generated, 3 distinct states found, 0 states left on queue.\n"
FINISH = "Finished in 1s at (2026-09-23 12:00:00)\n"
SUCCESS = "Model checking completed. No error has been found.\n" + STATS + FINISH
STATES = (
    "State 1: <Initial predicate>\n/\\ x = 0\n/\\ y = {}\n\n"
    "State 2: <Next line 8, col 1 to line 8, col 20 of module Example>\n"
    "/\\ x = 1\n/\\ y = {1}\n\n"
)
SAFETY = (
    "Error: Invariant Safe is violated.\n"
    "Error: The behavior up to this point is:\n" + STATES + STATS + FINISH
)
TEMPORAL = (
    "Error: Temporal properties were violated.\n"
    "Error: The following behavior constitutes a counter-example:\n"
    + STATES + "State 3: Stuttering\nFinished checking temporal properties in 00s at 2026-09-23 12:00:00\n" + STATS + FINISH
)


def case(kind="success", property_name=None):
    expected = {"kind": kind}
    if property_name:
        expected["property"] = property_name
    return {"expected": expected, "variables": {"x", "y"}}


class CompletedEvidenceTests(unittest.TestCase):
    def test_positive_requires_success_exit_complete_counts_and_nonempty_states(self):
        self.assertEqual(assess_result(0, SUCCESS, case())[0]["distinct"], 3)
        for code, output in (
            (-9, SUCCESS), (-15, SUCCESS), (1, SUCCESS), (0, "Starting...\n"),
            (0, SUCCESS.replace(FINISH, "")), (0, SUCCESS.replace(STATS, "")),
            (0, SUCCESS.replace("3 distinct", "0 distinct")),
            (0, SUCCESS.replace("4 states", "2 states")),
            (0, SUCCESS + "Error: unexpected failure\n"),
        ):
            with self.subTest(code=code, output=output):
                with self.assertRaises(EvidenceError):
                    assess_result(code, output, case())

    def test_safety_requires_exact_named_diagnostic_and_completed_trace(self):
        observed = assess_result(12, SAFETY, case("invariant", "Safe"))[1]
        self.assertEqual([state["action"] for state in observed["states"]], ["Init", "Next"])
        self.assertIsNone(observed["loop"])
        for code, output in (
            (0, SAFETY), (-9, SAFETY), (-15, SAFETY), (1, SAFETY), (13, SAFETY), (150, SAFETY),
            (12, SAFETY.replace("Invariant Safe", "Invariant Other")),
            (12, SAFETY.replace(STATES, "")), (12, SAFETY.replace(FINISH, "")),
            (12, SAFETY + "Error: Out of memory\n"),
        ):
            with self.subTest(code=code, output=output):
                with self.assertRaises(EvidenceError):
                    assess_result(code, output, case("invariant", "Safe"))

    def test_temporal_requires_real_liveness_diagnostic_and_loop(self):
        observed = assess_result(13, TEMPORAL, case("temporal", "EventuallyDone"))[1]
        self.assertEqual(observed["loop"], {"kind": "stuttering", "state": 2})
        for code, output in (
            (12, TEMPORAL), (-9, TEMPORAL),
            (13, TEMPORAL.replace("Temporal properties were violated.", "Evaluating action property EventuallyDone failed.")),
            (13, TEMPORAL.replace("State 3: Stuttering\n", "")),
        ):
            with self.subTest(code=code, output=output):
                with self.assertRaises(EvidenceError):
                    assess_result(code, output, case("temporal", "EventuallyDone"))
        loop = TEMPORAL.replace("State 3: Stuttering", "Back to state 1: <Next line 8, col 1 of module Example>")
        self.assertEqual(assess_result(13, loop, case("temporal", "EventuallyDone"))[1]["loop"],
                         {"kind": "back-edge", "state": 1})

    def test_safety_cannot_borrow_a_temporal_loop(self):
        with self.assertRaises(EvidenceError):
            assess_result(12, SAFETY.replace(STATS, "State 3: Stuttering\n" + STATS),
                          case("invariant", "Safe"))

    def test_earlier_temporal_progress_does_not_masquerade_as_trace_completion(self):
        progress = ("Checking temporal properties for the current state space...\n"
                    "Finished checking temporal properties in 00s at 2026-09-23 11:59:59\n")
        _, trace = assess_result(13, progress + TEMPORAL, case("temporal", "EventuallyDone"))
        self.assertEqual(trace["loop"], {"kind": "stuttering", "state": 2})

    def test_mutant_trace_must_precede_ordered_statistics_and_completion(self):
        diagnostic = SAFETY[:SAFETY.index("State 1:")]
        for suffix in (
            STATS + FINISH + STATES,
            FINISH + STATS + STATES,
            STATES + FINISH + STATS,
            STATES + STATS + STATS + FINISH,
            STATES + STATS + FINISH + FINISH,
        ):
            with self.subTest(suffix=suffix):
                with self.assertRaises(EvidenceError):
                    assess_result(12, diagnostic + suffix, case("invariant", "Safe"))

    def test_thousands_separators_and_multiline_values_remain_opaque(self):
        output = SAFETY.replace(STATS, "1,234 states generated, 1,000 distinct states found, 0 states left on queue.\n")
        output = output.replace("/\\ y = {1}", "/\\ y =\n  [left |-> {1},\n   right |-> <<2, 3>>]")
        stats, trace = assess_result(12, output, case("invariant", "Safe"))
        self.assertEqual(stats, {"generated": 1234, "distinct": 1000})
        self.assertIn("right |-> <<2, 3>>", trace["states"][1]["tlc_text"])


class TraceFramingTests(unittest.TestCase):
    def test_plain_single_record_variable_matches_tlc_host_recovery_format(self):
        text = ("State 1: <Initial predicate>\ns = [pc |-> \"backup\", live |-> [a |-> 0]]\n\n"
                "State 2: <Cleanup line 20, col 1 of module HostRecovery>\n"
                "s = [pc |-> \"done\",\n     live |-> [a |-> 1]]\n\n" + STATS + FINISH)
        trace = parse_trace(text, {"s"})
        self.assertEqual(trace["states"][1]["action"], "Cleanup")
        with self.assertRaises(EvidenceError):
            parse_trace(text.replace("s =", "/\\ s ="), {"s"})

    def test_malformed_or_incomplete_trace_never_supplies_a_witness(self):
        malformed = [
            "", "State 1: partial trace\n", STATES.replace("State 1:", "State 0:"),
            STATES.replace("State 2:", "State 3:"),
            STATES.replace("State 2:", "State 1:"),
            STATES + "State broken: partial\n",
            STATES.replace("<Initial predicate>", "<Next>"),
            STATES.replace("<Next line 8, col 1 to line 8, col 20 of module Example>", "<1>"),
            STATES.replace("/\\ y = {1}\n", ""),
            STATES.replace("/\\ y = {1}", "/\\ x = 2"),
            STATES.replace("/\\ y = {1}", "/\\ y ="),
            STATES.replace("/\\ y = {1}", "y = {1}"),
            STATES + "Back to state 0\n", STATES + "Back to state 3\n",
            STATES + "Back to state 1\nunexpected text\n",
            STATES + STATS + "State 3: <Next>\n/\\ x = 2\n/\\ y = {}\n",
            STATES + "State 3: Stuttering\nState 4: <Next>\n/\\ x = 2\n/\\ y = {}\n",
            "State 1: Stuttering\n",
            STATES + "State 3: Stuttering\nunexpected content\n",
        ]
        for output in malformed:
            with self.subTest(output=output):
                with self.assertRaises(EvidenceError):
                    parse_trace(output + STATS + FINISH, {"x", "y"})


class ConfigDeclarationTests(unittest.TestCase):
    def test_comments_strings_and_multiple_declaration_forms(self):
        text = ('SPECIFICATION Spec\nCONSTANT note = "PROPERTY Fake"\n'
                '\\* PROPERTY Commented\n(* PROPERTY Outer (* inner *) *)\n'
                'INVARIANT TypeOK\nINVARIANTS Safe Bound\nPROPERTIES Done\nCHECK_DEADLOCK FALSE\n')
        self.assertEqual(config_declarations(text),
                         {"invariants": ["TypeOK", "Safe", "Bound"], "properties": ["Done"]})
        self.assertEqual(model_variables('VARIABLES x,\n y\nvars == <<x, y>>\n'), {"x", "y"})
        self.assertEqual(model_variables('VARIABLE s\nvars == <<s>>\n'), {"s"})

    def test_duplicate_empty_malformed_or_unterminated_declarations_refuse(self):
        for text in ("PROPERTY", "PROPERTY Done PROPERTY Done", "INVARIANT A INVARIANTS A",
                     'PROPERTY Done(1)', 'CONSTANT x = "unfinished', "(* unfinished"):
            with self.subTest(text=text):
                with self.assertRaises(EvidenceError):
                    config_declarations(text)


class CopiedInputTests(unittest.TestCase):
    def test_every_copied_model_and_config_remains_exact_regular_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("Model.tla", "normal.cfg"):
                (root / name).write_text("retained " + name)
            expected = {name: digest(root / name) for name in ("Model.tla", "normal.cfg")}
            self.assertEqual(check_copied_inputs(root, expected), expected)
            for name in expected:
                path = root / name
                original = path.read_bytes()
                path.write_bytes(original + b" changed")
                with self.assertRaisesRegex(EvidenceError, "copied verification inputs changed"):
                    check_copied_inputs(root, expected)
                path.write_bytes(original)
            original = (root / "Model.tla").read_bytes()
            (root / "Model.tla").unlink()
            with self.assertRaises(OSError):
                check_copied_inputs(root, expected)
            (root / "other.tla").write_bytes(original)
            (root / "Model.tla").symlink_to(root / "other.tla")
            with self.assertRaises(EvidenceError):
                check_copied_inputs(root, expected)


class ManifestInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.verify = self.repo / "verify"
        self.suite_dir = self.verify / "example"
        self.suite_dir.mkdir(parents=True)
        (self.verify / "run_tlc.py").write_text("# test runner\n")
        (self.verify / "tools.json").write_text("{}")
        (self.repo / "source.rs").write_text("fn production() {}\n")
        (self.suite_dir / "Example.tla").write_text(
            "---- MODULE Example ----\nVARIABLES x, y\nvars == <<x, y>>\n")
        (self.suite_dir / "normal.cfg").write_text(
            "SPECIFICATION Spec\nINVARIANTS TypeOK Safe\nPROPERTY Done\nCHECK_DEADLOCK FALSE\n")
        self.manifest = {"schema_version": 1, "suites": [{
            "id": "example", "module": "verify/example/Example.tla",
            "claim": "A bounded test claim.", "status": "implementation-correspondence",
            "bounds": "Two states.", "assumptions": ["Successful atomic storage."],
            "sources": [{"path": "source.rs", "symbols": ["production"], "role": "production"}],
            "cases": [{"id": "normal", "config": "verify/example/normal.cfg",
                       "expected": {"kind": "success"}}],
        }]}
        self.save()

    def save(self):
        (self.verify / "cases.json").write_text(json.dumps(self.manifest))

    def load(self):
        self.save()
        return load_inventory(self.repo)

    def test_complete_inventory_collects_all_attribution_inputs(self):
        manifest, cases, snapshot = self.load()
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(cases[0]["declarations"]["properties"], ["Done"])
        self.assertEqual(set(snapshot), {
            "verify/cases.json", "verify/tools.json", "verify/run_tlc.py",
            "verify/example/Example.tla", "verify/example/normal.cfg", "source.rs"})

    def test_unlisted_module_or_config_fails(self):
        for name in ("extra.cfg", "Extra.tla"):
            with self.subTest(name=name):
                extra = self.suite_dir / name
                extra.write_text("unexpected")
                with self.assertRaisesRegex(EvidenceError, "unlisted"):
                    self.load()
                extra.unlink()

    def test_missing_model_config_or_source_fails(self):
        for path in (self.suite_dir / "Example.tla", self.suite_dir / "normal.cfg", self.repo / "source.rs"):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.unlink()
                with self.assertRaises(OSError):
                    self.load()
                path.write_bytes(original)

    def test_duplicate_suite_case_source_or_unknown_fields_fail(self):
        baseline = copy.deepcopy(self.manifest)
        variants = []
        duplicate_suite = copy.deepcopy(baseline)
        duplicate_suite["suites"].append(copy.deepcopy(duplicate_suite["suites"][0]))
        variants.append(duplicate_suite)
        for field in ("cases", "sources"):
            duplicate = copy.deepcopy(baseline)
            duplicate["suites"][0][field].append(copy.deepcopy(duplicate["suites"][0][field][0]))
            variants.append(duplicate)
        unknown = copy.deepcopy(baseline)
        unknown["suites"][0]["cases"][0]["disabled"] = True
        variants.append(unknown)
        for version in (0, 2, True, "1"):
            variant = copy.deepcopy(baseline)
            variant["schema_version"] = version
            variants.append(variant)
        for variant in variants:
            with self.subTest(variant=variant):
                self.manifest = variant
                with self.assertRaises(EvidenceError):
                    self.load()
        with self.assertRaises(EvidenceError):
            read_json('{"schema_version":1,"schema_version":2}')

    def test_expected_property_must_be_declared_and_temporal_attribution_unique(self):
        expectation = self.manifest["suites"][0]["cases"][0]
        expectation["expected"] = {"kind": "invariant", "property": "Safe"}
        self.load()
        expectation["expected"] = {"kind": "temporal", "property": "Done"}
        self.load()
        for invalid in (
            {"kind": "invariant", "property": "Absent"},
            {"kind": "temporal", "property": "Other"},
            {"kind": "success", "property": "Done"},
            {"kind": "typo"}, {"kind": []},
        ):
            with self.subTest(expected=invalid):
                expectation["expected"] = invalid
                with self.assertRaises(EvidenceError):
                    self.load()
        expectation["expected"] = {"kind": "temporal", "property": "Done"}
        (self.suite_dir / "normal.cfg").write_text("PROPERTY Done Other\nINVARIANT Safe\n")
        with self.assertRaisesRegex(EvidenceError, "exactly"):
            self.load()

    def test_paths_cannot_escape_alias_or_hide_symlinks(self):
        for path in ("../source.rs", "/tmp/source.rs", "./source.rs", "verify//example/normal.cfg",
                     "verify/../source.rs", "verify\\example\\normal.cfg", ""):
            with self.subTest(path=path):
                with self.assertRaises(EvidenceError):
                    checked_path(self.repo, path)
        (self.repo / "alias.rs").symlink_to(self.repo / "source.rs")
        with self.assertRaises(EvidenceError):
            checked_path(self.repo, "alias.rs")
        (self.verify / "hidden").symlink_to(self.suite_dir, target_is_directory=True)
        with self.assertRaises(EvidenceError):
            self.load()

    def test_historical_trace_is_hashed_but_not_interpreted_as_current_evidence(self):
        history = self.suite_dir / "counterexamples"
        history.mkdir()
        (history / "normal.json").write_text("deliberately not a current trace")
        self.manifest["suites"][0]["cases"][0]["historical_trace"] = "verify/example/counterexamples/normal.json"
        _, _, snapshot = self.load()
        self.assertIn("verify/example/counterexamples/normal.json", snapshot)

    def test_repository_inventory_is_complete_and_declared_properties_match(self):
        _, cases, _ = load_inventory(ROOT.parent)
        self.assertGreaterEqual(len(cases), 20)
        self.assertTrue(any(c["expected"]["kind"] == "temporal" for c in cases))


if __name__ == "__main__":
    unittest.main()
