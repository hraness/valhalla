import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("browser_package", Path(__file__).with_name("package.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class Packaging(unittest.TestCase):
    def test_generated_bytes_preserved_with_restrictive_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generated = '\nimport init from "/generated.js";\nawait init();\n'
            (root / "index.html").write_text('<html><script type="module">' + generated + '</script></html>')
            package.package(root)
            boot = list(root.glob("bootstrap-*.js"))
            self.assertEqual(len(boot), 1)
            self.assertEqual(boot[0].read_text(), generated)
            html = (root / "index.html").read_text()
            self.assertNotIn(generated, html)
            self.assertIn('src="/' + boot[0].name + '"', html)
            config = json.loads((root / "vercel.json").read_text())
            headers = {h["key"]: h["value"] for h in config["headers"][0]["headers"]}
            self.assertNotIn("'unsafe-inline'", headers["Content-Security-Policy"])
            self.assertNotIn("'unsafe-eval'", headers["Content-Security-Policy"])
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertIn(boot[0].name, json.loads((root / "artifact.json").read_text())["assets"])

    def test_local_routes_cannot_be_packaged_for_production(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            html = '<script type="module">generated</script>'
            (root / "index.html").write_text(html)
            (root / "app.wasm").write_bytes(b"\0asm/__qualification/")
            with self.assertRaises(ValueError):
                package.package(root)
            self.assertEqual((root / "index.html").read_text(), html)
            self.assertFalse((root / "artifact.json").exists())
            package.package(root, allow_local_qualification=True)
            self.assertEqual(json.loads((root / "artifact.json").read_text())["purpose"], "local-qualification")

    def test_unexpected_bootstrap_and_inline_handlers_fail_closed(self):
        for html in ['<html></html>', '<script type="module">a</script><script src="external"></script>', '<button onclick="bad()">x</button><script type="module">a</script>']:
            with self.subTest(html=html), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "index.html").write_text(html)
                with self.assertRaises(ValueError):
                    package.package(root)


if __name__ == "__main__":
    unittest.main()
