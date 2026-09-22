"""Finite authority experiment. No keys, MLS, disk state, or production API."""

from dataclasses import dataclass, replace
from itertools import product


@dataclass(frozen=True)
class View:
    """Everything the recovering client can observe in this experiment."""

    anchor: str = "original-room"
    account_backup: bool = False
    archive: bool = False
    missed_heartbeats: int = 0
    relay_says_retired: bool = False


EVENTS = ("account-backup", "archive", "timeout", "relay-retired")


def observe(view, event):
    if event == "account-backup":
        return replace(view, account_backup=True)
    if event == "archive":
        return replace(view, archive=True)
    if event == "timeout":
        return replace(view, missed_heartbeats=view.missed_heartbeats + 1)
    if event == "relay-retired":
        return replace(view, relay_says_retired=True)
    raise ValueError("unknown observation")


def timeout_recovery(view):
    """Deliberately unsafe proposal used to obtain a counterexample."""
    return view.account_backup and view.missed_heartbeats >= 2


@dataclass(frozen=True)
class Decision:
    room: str
    device: str
    mode: str
    clone_old_ratchet: bool = False
    globally_fences_old_device: bool = False


def decide(view, *, live_predecessor=False, fresh_device=None, new_room=None):
    """Existing-anchor policy, not a proposed unilateral recovery protocol.

    `live_predecessor` abstracts an actually authenticated committed admission.
    It is NOT a boolean accepted from an agent, relay, backup, or user interface.
    A different room abstracts a new anchor requiring independent acceptance.
    """
    if not view.account_backup:
        return None
    if new_room is not None:
        if not new_room or new_room == view.anchor or not fresh_device:
            raise ValueError("migration requires a distinct room and fresh device")
        return Decision(new_room, fresh_device, "new-room-migration")
    if live_predecessor and fresh_device:
        return Decision(view.anchor, fresh_device, "fresh-admission")
    return Decision(view.anchor, "", "read-only-history") if view.archive else None


def explore(depth=6):
    """Check indistinguishable loss and partition histories, including reorder."""
    checked = 0
    first_counterexample = None
    for length in range(depth + 1):
        for events in product(EVENTS, repeat=length):
            lost = partitioned = View()
            for event in events:
                lost = observe(lost, event)
                partitioned = observe(partitioned, event)
            # In one world the old device is gone; in the other it still signs
            # in a partition. These observations cannot distinguish the worlds.
            assert lost == partitioned
            assert decide(lost) == decide(partitioned)
            decision = decide(lost)
            assert decision is None or decision.mode == "read-only-history"
            if timeout_recovery(partitioned) and first_counterexample is None:
                first_counterexample = events
            checked += 1
    assert first_counterexample is not None
    return checked, first_counterexample


if __name__ == "__main__":
    count, counterexample = explore()
    print(f"Checked {count} bounded observation histories.")
    print("Timeout-based recovery counterexample: " + ", ".join(counterexample))
    print("No unilateral existing-anchor recovery follows from these observations.")
