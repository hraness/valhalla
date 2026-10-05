# Menu bar to command line

Valhalla's macOS menu bar is retired. Everything it showed and did is now a `vhalla` command that runs, answers and exits, so nothing keeps running in the background. Each command also prints one JSON line with `--json` for agents and scripts.

This page maps every menu bar action and every state it could show to the command that replaces it. A test in `crates/vhalla-cli/tests/status.rs` fails when an action or state is missing here.

## Actions

| Menu action | What it did | Command now |
| --- | --- | --- |
| `status` | The top row: rooms in sync, sends waiting or that didn't go through | `vhalla status`; save fresh counts with `vhalla status refresh SOCIAL_STORE REPLICA_HOME REALM NODE_HOME --config FILE` (the released `vhalla menubar refresh` spelling still works and runs it, with a note on stderr) |
| `outputs.open.<file>` | Opened one of the newest outputs | `vhalla outputs open NAME` |
| `outputs.reveal.<file>` | Showed that file in Finder | `vhalla outputs reveal NAME` |
| `outputs.folder` | Opened the outputs folder ("Show all N outputs") | `vhalla outputs open`; `vhalla outputs list` lists every file |
| `login` | "Open at login" | Nothing opens at login any more. `vhalla doctor` shows a login item an earlier release left, and `vhalla doctor retire` sets it aside |
| `support` | "Updates & support" in the browser | `vhalla support`; `vhalla support --json` prints the same links as one envelope |
| `support.diagnostics` | "Copy diagnostics" | `vhalla doctor --json` |
| `quit` | Quit the menu bar | n/a: no process stays running |

## States

Each state the menu bar had a fixture for has a golden in `crates/vhalla-cli/tests/fixtures/status/`: the status text at widths 40, 80 and 120 (`NAME.w40.txt` and so on) and the `status --json` envelope (`NAME.json`).

| Fixture | `status` shows |
| --- | --- |
| `first-run` | No room status yet, and the refresh command to run |
| `empty` | No rooms yet |
| `error` | Couldn't read your rooms, with the reason |
| `in-sync` | N rooms in sync |
| `out-of-date` | Room status is out of date (older than an hour) |
| `send-failed` | N sends didn't go through |
| `sends-waiting` | N sends waiting |
| `login-not-ours` | A login item with Valhalla's name that doesn't start the menu bar, left alone |
| `action-error` | The error `vhalla outputs open NAME` returns for a file that isn't there |

## Retiring the login item

`vhalla doctor retire` looks for the two login items earlier releases wrote, `~/Library/LaunchAgents/app.hraness.valhalla.plist` and `~/Library/LaunchAgents/com.hraness.valhalla.menubar.plist`. It sets one aside only when all of these hold:

- it is a regular file, not a symlink;
- your account owns it (if `vhalla` can't tell which account is running, it renames nothing);
- it is UTF-8 and at most 64 KiB;
- it starts a program named `vhalla-menubar`, or `Valhalla.app/Contents/MacOS/Valhalla`, the local app that `HRANESS_LOCAL_APP=1 vhalla menubar install` built in v0.2.8.

It first checks that `NAME.plist.retired-TIME` is free, then asks launchd to unload that label and renames the file to that name. It never deletes the file and never signals a process. The output includes the command that puts the item back. Anything that fails a check is reported and left alone. If a later item can't be set aside, the error still lists the items already renamed and the command that puts each back.

The copy of `vhalla-menubar` that `vhalla menubar install` kept in the Valhalla folder stays where it is. So does `~/Applications/Hraness/Valhalla.app`, if v0.2.8 built one. `vhalla doctor` shows both paths so you can remove them yourself.
