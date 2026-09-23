import unittest

from run_tlc import accepted_result


class CheckerCompletionTests(unittest.TestCase):
    def test_killed_or_failed_checker_cannot_reuse_partial_counterexample(self):
        text = "Error: Invariant NoLostWork is violated.\nState 1: partial trace"
        self.assertTrue(accepted_result(12, text, "NoLostWork", True))
        for code in (-9, -15, 1, 150, 0):
            with self.subTest(code=code):
                self.assertFalse(accepted_result(code, text, "NoLostWork", True))

    def test_named_violation_and_trace_both_required(self):
        self.assertFalse(accepted_result(12, "Invariant Other is violated.", "NoLostWork", True))
        self.assertFalse(accepted_result(12, "Invariant NoLostWork is violated.", "NoLostWork", False))

    def test_positive_requires_successful_completion_not_just_exit(self):
        success = "Model checking completed. No error has been found."
        self.assertTrue(accepted_result(0, success, None, False))
        self.assertFalse(accepted_result(0, "Starting...", None, False))
        self.assertFalse(accepted_result(-9, success, None, False))


if __name__ == "__main__":
    unittest.main()
