"""The release page is the CHANGELOG section plus generated install and verify text."""

import json
from pathlib import Path
import unittest

from publish_release import asset_names
from release_notes import (
    CHANGELOG, IDENTITY_PREFIX, changelog_section, parse_identity, render_body,
    render_notes, title, verify_body,
)


TAG = "v0.2.5"
SHA = "c" * 40
REPO = "hraness/valhalla"
ASSETS = {name: f"{index:064x}" for index, name in enumerate(asset_names(TAG))}
TEXT = """# Changelog

## 0.2.6 - Unreleased

Not yet.

- Pending.

## v0.2.5 - 2026-09-26

Rooms rotate their validator set in protocol.

- `rooms rotate` schedules a replacement set.
- `node-init --discovery true` turns on peer discovery,
  seeded by the configured peers.

## 0.2.3

Older.

- Older change.
"""


class ChangelogSectionTests(unittest.TestCase):
    def test_heading_forms(self):
        for heading in ("## 0.2.5", "## v0.2.5", "## 0.2.5 - 2026-09-26", "## v0.2.5 - 2026-09-26"):
            with self.subTest(heading=heading):
                summary, bullets = changelog_section(f"{heading}\n\nSummary.\n\n- Change.\n", TAG)
                self.assertEqual((summary, bullets), ("Summary.", "- Change."))

    def test_selects_only_the_tagged_version(self):
        summary, bullets = changelog_section(TEXT, TAG)
        self.assertEqual(summary, "Rooms rotate their validator set in protocol.")
        self.assertTrue(bullets.startswith("- `rooms rotate`"))
        self.assertTrue(bullets.endswith("seeded by the configured peers."))
        self.assertNotIn("Older", bullets)

    def test_missing_empty_unreleased_or_malformed_sections_fail(self):
        cases = {
            "missing": "## 0.2.4\n\nOther.\n\n- Other.\n",
            "prefix only": "## 0.2.55\n\nOther.\n\n- Other.\n",
            "empty": "## 0.2.5\n\n## 0.2.4\n\nOther.\n\n- Other.\n",
            "blank at end": "## 0.2.5\n\n\n",
            "unreleased heading": "## 0.2.5 - Unreleased\n\nSoon.\n\n- Soon.\n",
            "unreleased body": "## 0.2.5\n\nUnreleased.\n\n- Soon.\n",
            "no bullets": "## 0.2.5\n\nOnly a summary.\n",
            "no summary": "## 0.2.5\n\n- Only bullets.\n",
            "trailing prose": "## 0.2.5\n\nSummary.\n\n- Change.\n\nMore prose.\n",
            "duplicate": "## 0.2.5\n\nA.\n\n- A.\n\n## v0.2.5\n\nB.\n\n- B.\n",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    changelog_section(text, TAG)

    def test_repository_changelog_has_the_published_and_tagged_versions(self):
        text = CHANGELOG.read_text(encoding="utf-8")
        for tag in ("v0.2.3", "v0.2.5"):
            with self.subTest(tag=tag):
                summary, bullets = changelog_section(text, tag)
                self.assertTrue(summary and bullets.startswith("- "))


class RenderedPageTests(unittest.TestCase):
    def test_title_is_product_and_tag(self):
        self.assertEqual(title(TAG), "Valhalla v0.2.5")

    def test_body_shape(self):
        body = render_body(TEXT, REPO, TAG, SHA, ASSETS)
        headings = [line for line in body.split("\n") if line.startswith("## ")]
        self.assertEqual(headings, ["## Changes", "## Install", "## Verify"])
        self.assertTrue(body.startswith("Rooms rotate their validator set in protocol.\n\n## Changes\n\n- "))
        self.assertIn(f"/releases/download/{TAG}/valhalla-{TAG}-aarch64-apple-darwin.tar.gz\n", body)
        self.assertIn(f"`valhalla-browser-{TAG}.tar.gz`", body)
        self.assertIn(f"`{SHA}`", body)
        self.assertIn(f"/blob/{TAG}/crates/vhalla-cli/README.md#releases", body)
        self.assertNotIn("latest", body.lower())
        for banned in ("What's Changed", "Full Changelog", "Generated with",
                       "Automated release", "Canonical GitHub release for"):
            self.assertNotIn(banned, body)
        self.assertTrue(body.endswith("-->"))
        self.assertEqual(body.count("<!--"), 1)

    def test_identity_parses_from_the_end(self):
        body = render_body(TEXT, REPO, TAG, SHA, ASSETS)
        notes, record = parse_identity(body)
        self.assertEqual(notes, render_notes(TEXT, REPO, TAG, SHA, ASSETS))
        self.assertEqual(record, {"assets": ASSETS, "commit": SHA, "repository": REPO, "tag": TAG})
        verify_body(body, TEXT, REPO, TAG, SHA, ASSETS)

    def test_an_identity_lookalike_in_the_notes_does_not_win(self):
        forged = json.dumps({"assets": {}, "commit": "d" * 40, "repository": REPO, "tag": TAG})
        text = TEXT.replace("Rooms rotate", f"{IDENTITY_PREFIX}{forged} --> Rooms rotate")
        body = render_body(text, REPO, TAG, SHA, ASSETS)
        self.assertEqual(parse_identity(body)[1]["commit"], SHA)

    def test_tampering_is_detected(self):
        body = render_body(TEXT, REPO, TAG, SHA, ASSETS)
        notes, _ = parse_identity(body)
        other = dict(ASSETS, **{next(iter(ASSETS)): "f" * 64})
        tampered = {
            "notes": body.replace("schedules a replacement set", "schedules a set"),
            "appended text": body + "\n",
            "trailing prose": body + "\nThanks!",
            "identity removed": notes,
            "identity commit": body.replace(f'"commit":"{SHA}"', f'"commit":"{"d" * 40}"'),
            "identity assets": notes + "\n" + render_body(TEXT, REPO, TAG, SHA, other).rsplit("\n", 1)[1],
            "identity json": body.replace('"tag":', '"tag"'),
            "glued identity": notes + render_body(TEXT, REPO, TAG, SHA, ASSETS).rsplit("\n", 1)[1],
        }
        for name, candidate in tampered.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    verify_body(candidate, TEXT, REPO, TAG, SHA, ASSETS)

    def test_changelog_edit_after_publication_is_detected(self):
        body = render_body(TEXT, REPO, TAG, SHA, ASSETS)
        with self.assertRaises(ValueError):
            verify_body(body, TEXT.replace("in protocol", "on chain"), REPO, TAG, SHA, ASSETS)

    def test_short_commit_or_missing_checksum_refuses(self):
        with self.assertRaises(ValueError):
            render_body(TEXT, REPO, TAG, "abc1234", ASSETS)
        partial = {name: digest for name, digest in ASSETS.items()
                   if name != f"valhalla-browser-{TAG}.tar.gz.sha256"}
        with self.assertRaises(ValueError):
            render_body(TEXT, REPO, TAG, SHA, partial)


if __name__ == "__main__":
    unittest.main()
