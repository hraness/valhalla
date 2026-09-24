vhalla tests its ledger by restarting it after every step of a random history: save to bytes, restore, and check that the restored copy is the same ledger and still refuses an old event replayed as new. The ledger is a small crate, an ordered, size-limited list of events in which each event names the one before it and is identified by a hash of its contents. It is a foundation piece that is not yet wired into rooms, storage or the host; its README says durable recovery and signed checkpoints must come first. The rule it has to keep is the one any shared record needs, because programs crash, laptops lose power and processes get killed. A ledger reloaded from its saved bytes has to lose nothing from the saved part, count nothing twice, and give no way to replay an old event.

## The bug that only shows up on the third step

Most people have met software that works in the demo and breaks in use. It is easy to produce now: a model writes a feature in an afternoon, the happy path passes, and everything looks finished. The trouble hides in sequences. It only breaks if you save, add one more thing, then reopen. Nobody tries that order by hand, and a test written by the same person who wrote the feature usually checks the order they already had in mind.

For a shared record, that kind of bug is worse than a crash. A crash is loud. A ledger that reloads slightly wrong is quiet: an event that appears twice, a checkpoint that points at the wrong place, a message that can be sent again under an old number. Every feature built on top inherits the flaw, which is how a fragile foundation spreads.

The alternative is to stop guessing which orders matter. A program plays many random orders against the real code, reloads at every step, and checks a short list of rules each time. When a rule breaks, it shrinks the failing history to a shorter one that still fails and hands that back as a replay. Proof tools cover a few core rules for every input a test might never try. The claim this supports is narrow: one class of failure, searched for in named places, on every pull request.

## Three tools, three components

vhalla uses three tools, each on a different part.

| Tool | What it checks | Component |
| --- | --- | --- |
| Hegel | Random histories with a restart after every step, compared against a small model | The ledger's save and restore, and the spent-invitation file |
| Verus | A proof that the append rule keeps the ledger's invariants for every input | A reference model of the ledger's append step |
| Kani | Every possible value within stated sizes for the spent set's format and refusal rule | The spent-invitation file's decoder, encoder and refusal decision |

## Replaying random histories with Hegel

[Hegel](https://hraness.com/reference/correctness/hegel-stateful-testing) is a stateful property testing library. A test draws each operation while the history runs, so the next choice can depend on what has already happened.

The ledger's recovery test works like this. It creates an empty ledger that holds up to 32 events, draws a number of steps (up to 23), and at each step picks one of four actors, appends that actor's next event with a random payload, and sometimes takes a checkpoint. Then it saves the ledger to bytes, restores a fresh ledger from those bytes, and checks the restored copy. The loop, written out for a reader, looks like this:

```rust
for _ in 0..steps {
    let actor = draw_actor();
    append_next_event(&mut ledger, actor);
    if draw_bool() {
        take_checkpoint(&mut ledger);
    }

    let saved = ledger.snapshot();
    let mut restored = Ledger::restore(&saved, 32)?;

    // Restart law: the restored copy is the same ledger.
    assert_eq!(restored.snapshot(), saved);
    assert_eq!(restored.head(), ledger.head());
    assert_eq!(restored.checkpoint(), ledger.checkpoint());

    // No-replay law: the actor's last number cannot be used again.
    assert!(restored.append(same_sequence_again(actor)).is_err());

    ledger = restored;
}
```

The model is deliberately small: an array holding the last sequence number each actor used. The laws it checks are the ones a user cares about after a crash:

- **Restart law.** Saving and restoring gives back the same bytes, the same newest event and the same checkpoint.
- **No-replay law.** After a restore, an event that reuses an actor's last sequence number is refused.
- **Carry-on law.** The restored ledger becomes the working ledger, so every later step runs on a copy that has already been through a restart.

A second version of the test picks actors differently. Once someone has written, each step flips a coin between reusing an actor who has already written and drawing any of the four. That choice depends on the history so far, which is the case Hegel's draw-as-you-go style is built for. This version checks the restart law: the same bytes and the same checkpoint after every restore. Each property runs 64 random histories on every test run.

The test file also keeps one short history as a plain, named test: append and take a checkpoint, restore, then append one more event and restore again. An earlier version of this property, written with the proptest library, once shrank a failure to that two-step order: the checkpoint position was lost after a restore. The fix shipped, and the two-step replay stays so the bug cannot quietly return.

The spent-invitation file, described below, has its own Hegel property with real files on disk. It interleaves redeeming invitations with reopening the file, replacing it with corrupted bytes, a directory or a link, and leaving behind the half-written temporary file a crash would leave. After each step, the reopened set must match the model, or the open must refuse the file.

## Proving the append rule with Verus

Random testing samples histories. For the rule that decides whether an event may join the ledger, vhalla also has a proof. [Verus](https://github.com/verus-lang/verus) checks Rust code against written specifications and proves they hold for every input.

The proof covers a reference model of the ledger's append step. The model applies the production code's checks in the same order and rejects anything that fails. The one check it leaves out is recomputing the event's hash id, because the model uses plain numbers for ids. Verus proves these invariants hold after every call, with no limit on history length:

- **Append only.** The saved history only grows at the end.
- **One chain.** Every event's parent is the event just before it.
- **No double entry.** No two events in the history share an id.
- **Numbers only go up.** Each actor's sequence numbers strictly increase along the history.
- **Stays within its limit.** The history never exceeds the configured size.
- **All or nothing.** A rejected event leaves the ledger exactly as it was.

The model is a proof-friendly stand-in for the production type. It uses small integers in place of 32-byte hashes, and it scans a list where the production code uses lookup tables. What carries over is the decision: which events are accepted, which are refused, and in what order the checks run.

## Checking the spent set with Kani

vhalla's experimental command-line pairing for direct chat can accept an owner-signed invitation that is meant to work once. Before dialing, vhalla records the invitation's code in a small file next to the user's identity, so the same local identity cannot redeem it twice, even across restarts. Each redemption rewrites the whole file through a temporary copy, syncs it to disk, renames it into place and syncs the folder. The design aim is that a crash leaves either the old file or the new one; the proofs below do not cover that part.

[Kani](https://hraness.com/reference/correctness/kani-bounded-proofs) checks Rust functions against every possible input within sizes you choose. vhalla uses it on three pieces of the spent set:

- **The refusal rule.** For every possible 32-byte code, every count and both answers to "already used", the check returns one verdict in a fixed order: the all-zero code is invalid, then a used code is refused, then a full file is refused, and otherwise the code is accepted.
- **The file size rule.** For every possible length, a length is valid exactly when it is the four-byte header plus a whole number of 32-byte entries, up to 1024 entries.
- **The file format.** At chosen lengths from 0 to 68 bytes, every possible byte string is either decoded to its entries or refused as malformed, and encoding zero, one or two valid entries decodes back to the same entries.

Written as a law a reader can check:

```rust
// For any code, any count and any membership answer:
match refusal(code, already_used, count) {
    Invalid      => code == [0; 32],
    AlreadyUsed  => code != [0; 32] && already_used,
    Full         => code != [0; 32] && !already_used && count >= 1024,
    Accept       => code != [0; 32] && !already_used && count < 1024,
}
```

Kani runs in continuous integration on every pull request and every push to main, and the final aggregate check requires it to pass. The Verus proof and the Hegel tests run in that same set of required checks.

## Limits

vhalla is in development, and there is no public network yet.

The ledger's recovery test models a restart as saving to bytes and restoring from them. It does not kill a process halfway through a disk write; the ledger code sits below storage, and its saved bytes are not signed, so whatever stores them has to protect them. The Verus proof covers a reference model of the append rule, not the production data structures, snapshots or checkpoints. The Kani checks cover the spent set's format and refusal decision, not the underlying set type, the full 1024-entry file, filesystem safety, crash durability or two redemptions racing at once; those are left to the unit tests and the Hegel property on real files. The spent set works per machine and per identity, so it does not stop two different machines from each redeeming the same invitation.
