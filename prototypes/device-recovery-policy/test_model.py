import unittest

from model import View, decide, explore


class RecoveryPolicyTests(unittest.TestCase):
    def test_loss_and_partition_remain_indistinguishable_under_all_bounded_orders(self):
        count, witness = explore(6)
        self.assertEqual(count, sum(4**n for n in range(7)))
        self.assertEqual(witness, ("account-backup", "timeout", "timeout"))

    def test_archive_and_relay_claim_never_activate_old_custody(self):
        view = View(account_backup=True, archive=True, missed_heartbeats=100,
                    relay_says_retired=True)
        decision = decide(view)
        self.assertEqual(decision.mode, "read-only-history")
        self.assertFalse(decision.clone_old_ratchet)
        self.assertFalse(decision.globally_fences_old_device)

    def test_live_authorized_rejoin_uses_new_device_not_saved_ratchet(self):
        decision = decide(View(account_backup=True, archive=True),
                          live_predecessor=True, fresh_device="new-device")
        self.assertEqual((decision.room, decision.device, decision.mode),
                         ("original-room", "new-device", "fresh-admission"))
        self.assertFalse(decision.clone_old_ratchet)
        self.assertFalse(decision.globally_fences_old_device)

    def test_migration_is_distinct_authority_and_does_not_fence_partition(self):
        view = View(account_backup=True, archive=True)
        for room in ("", "original-room"):
            with self.assertRaises(ValueError):
                decide(view, fresh_device="new-device", new_room=room)
        decision = decide(view, fresh_device="new-device", new_room="new-room")
        self.assertEqual(decision.mode, "new-room-migration")
        self.assertFalse(decision.clone_old_ratchet)
        self.assertFalse(decision.globally_fences_old_device)

    def test_missing_account_authority_cannot_be_replaced_by_archive_or_timeout(self):
        self.assertIsNone(decide(View(archive=True, missed_heartbeats=100),
                                 live_predecessor=True, fresh_device="new-device"))


if __name__ == "__main__":
    unittest.main()
