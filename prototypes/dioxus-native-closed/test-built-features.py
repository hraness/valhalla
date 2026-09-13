#!/usr/bin/env python3
"""Selected compiled variants govern admission, including transitive library edges."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('built', Path(__file__).with_name('audit-built-features.py'))
built = importlib.util.module_from_spec(spec)
spec.loader.exec_module(built)
NATIVE = ['blitz-paint', 'svg', 'system-fonts']
DOM = ['accessibility', 'accesskit', 'svg', 'system_fonts']
NATIVE_DOM = ['accessibility', 'default', 'svg', 'system-fonts']
ROOT = ['native', 'renderer']


class Graph:
    """Synthetic Cargo-format references; numeric keys are fixture values, not hashes."""
    def __init__(self, temporary):
        self.base = Path(temporary) / '.fingerprint'
        self.base.mkdir()
        self.paths = {}
        self.shell = self.library('blitz_shell', 1, [])
        self.dom = self.library('blitz_dom', 2, DOM)
        self.traits = self.library('blitz_traits', 3, [])
        self.winit = self.library('winit', 4, ['default'])
        self.dioxus = self.library('dioxus', 5, ['lib', 'router'])
        self.ui = self.library('vhalla_dioxus_ui_spike', 6, [], [self.dioxus])
        self.native_dom = self.library('dioxus_native_dom', 7, NATIVE_DOM, [self.dom, self.traits])
        self.native = self.library('dioxus_native', 8, NATIVE, [self.native_dom, self.shell, self.dom, self.traits, self.winit])
        self.direct = [self.native, self.shell, self.dom, self.traits, self.dioxus, self.ui, self.winit]
        self.own = self.library('vhalla_dioxus_native_closed_spike', 9, ROOT, self.direct)
        self.deps = [self.own, *self.direct]
        directory = self.base / 'root'
        directory.mkdir()
        self.root = directory / 'bin-vhalla-native-closed.json'
        self.save_root()

    def library(self, name, key, features, deps=()):
        directory = self.base / (name + '-' + str(key))
        directory.mkdir()
        stamp = directory / ('lib-' + name)
        stamp.write_text(key.to_bytes(8, 'little').hex())
        path = stamp.with_name(stamp.name + '.json')
        path.write_text(json.dumps({'features': json.dumps(features), 'deps': list(deps)}))
        self.paths[key] = path
        return [0, name, False, key]

    def replace(self, dependency, **fields):
        path = self.paths[dependency[3]]
        data = json.loads(path.read_text())
        data.update(fields)
        path.write_text(json.dumps(data))

    def save_root(self, **fields):
        data = {'features': json.dumps(ROOT), 'deps': self.deps}
        data.update(fields)
        self.root.write_text(json.dumps(data))


class Fingerprints(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='vhalla-fingerprint-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.graph = Graph(self.temporary.name)

    def test_direct_selected_variant_controls_verdict(self):
        g = self.graph
        built.audit(g.root)
        bad = g.library('dioxus_native', 19, ['default', 'net', 'svg'], [g.native_dom])
        built.audit(g.root)  # Unselected broad cache state must not poison the closed graph.
        g.deps[1] = bad
        g.save_root()
        with self.assertRaisesRegex(AssertionError, 'features widened'):
            built.audit(g.root)

    def test_selected_native_transitively_reaches_broad_shell(self):
        g = self.graph
        bad = g.library('blitz_shell', 20, ['clipboard'])
        g.replace(g.native, deps=[g.native_dom, bad, g.dom, g.traits, g.winit])
        with self.assertRaisesRegex(AssertionError, 'features widened'):
            built.audit(g.root)

    def test_own_library_transitively_reaches_broad_native(self):
        g = self.graph
        bad = g.library('dioxus_native', 21, ['default', 'net', 'svg'], [g.native_dom])
        g.replace(g.own, deps=[bad, *g.direct[1:]])
        with self.assertRaisesRegex(AssertionError, 'features widened'):
            built.audit(g.root)

    def test_transitive_native_dom_cannot_hide_broad_dom(self):
        g = self.graph
        bad = g.library('blitz_dom', 22, [*DOM, 'autofocus'])
        g.replace(g.native_dom, deps=[bad, g.traits])
        with self.assertRaisesRegex(AssertionError, 'features widened'):
            built.audit(g.root)

    def test_unknown_numeric_reference_has_no_cached_fallback(self):
        g = self.graph
        g.replace(g.own, deps=[[0, 'dioxus_native', False, 999], *g.direct[1:]])
        with self.assertRaisesRegex(AssertionError, 'missing compiled fingerprint'):
            built.audit(g.root)

    def test_same_numeric_reference_with_different_json_is_ambiguous(self):
        g = self.graph
        bad = g.library('dioxus_native', 23, ['default', 'net', 'svg'], [g.native_dom])
        stamp = g.paths[bad[3]].with_suffix('')
        stamp.write_text(g.native[3].to_bytes(8, 'little').hex())
        with self.assertRaisesRegex(AssertionError, 'ambiguous compiled fingerprint'):
            built.audit(g.root)

    def test_root_must_select_own_library_and_expected_alias(self):
        g = self.graph
        g.deps = g.direct
        g.save_root()
        with self.assertRaises(AssertionError):
            built.audit(g.root)
        g.deps = [g.own, *g.direct]
        g.save_root(features=json.dumps(['renderer']))
        with self.assertRaises(AssertionError):
            built.audit(g.root)
        g.save_root()
        wrong = g.root.with_name('bin-unrelated.json')
        wrong.write_bytes(g.root.read_bytes())
        with self.assertRaises(AssertionError):
            built.audit(wrong)

    def test_feature_objects_and_duplicate_features_are_not_valid_arrays(self):
        g = self.graph
        for malformed in [dict.fromkeys(NATIVE, True), [*NATIVE, 'svg'], ['svg', 7]]:
            with self.subTest(features=malformed):
                g.replace(g.native, features=json.dumps(malformed))
                with self.assertRaises(AssertionError):
                    built.audit(g.root)

    def test_dependency_tuple_shape_types_names_and_uniqueness_are_checked(self):
        g = self.graph
        cases = [
            [[0, 'dioxus_native', False]], [[True, 'dioxus_native', False, 8]],
            [[0, 'dioxus_native', 0, 8]], [[0, 'dioxus_native', False, -1]],
            [[0, 'unsafe*name', False, 8]], [g.native, g.native],
        ]
        for deps in cases:
            with self.subTest(deps=deps):
                g.replace(g.own, deps=deps)
                with self.assertRaises(AssertionError):
                    built.audit(g.root)

    def test_bad_or_oversized_stamp_cannot_supply_a_selected_variant(self):
        g = self.graph
        stamp = g.paths[g.native[3]].with_suffix('')
        for content in ['0' * 17, 'z' * 16, '0' * 4096]:
            with self.subTest(stamp=content[:20]):
                stamp.write_text(content)
                with self.assertRaises((AssertionError, ValueError)):
                    built.audit(g.root)


if __name__ == '__main__':
    unittest.main()
