# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""The deterministic analyzer: planted issues are found, look-alikes are not."""

from __future__ import annotations

import json
import unittest

from helpers import EXAMPLES, fake_aws_key, make_repo

from omniseek.model import LENSES
from omniseek.render import render
from omniseek.scan import ScanError, parse_lenses, run_scan

PLANTED = {
    "security/sql-string-building",
    "security/shell-injection",
    "security/unsafe-deserialization",
    "security/dangerous-eval",
    "security/weak-hash",
    "security/xss-sink",
    "security/container-runs-as-root",
    "security/unpinned-base-image",
    "security/unpinned-dependency",
    "performance/io-in-loop",
    "performance/blocking-call-in-async",
    "performance/sequential-await",
    "performance/async-foreach",
    "performance/json-deep-clone",
    "product/missing-license",
    "product/readme-missing-quickstart",
}


def rule_ids(document: dict) -> set[str]:
    return {f["rule_id"] for f in document["findings"]}


class DemoAppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = run_scan(str(EXAMPLES / "vulnerable_app"))

    def test_every_planted_issue_is_found(self):
        self.assertTrue(PLANTED <= rule_ids(self.document), PLANTED - rule_ids(self.document))

    def test_every_citation_verifies(self):
        verification = self.document["verification"]
        self.assertEqual(verification["grounding_score"], 1.0)
        self.assertEqual(verification["citations_by_status"]["verified"], verification["citations_total"])

    def test_output_is_deterministic(self):
        again = run_scan(str(EXAMPLES / "vulnerable_app"))
        self.assertEqual([f["id"] for f in again["findings"]], [f["id"] for f in self.document["findings"]])

    def test_lens_filter(self):
        document = run_scan(str(EXAMPLES / "vulnerable_app"), lenses=["performance"])
        self.assertEqual({f["lens"] for f in document["findings"]}, {"performance"})


class PrecisionTest(unittest.TestCase):
    def test_code_in_strings_and_comments_is_ignored(self):
        repo = make_repo(
            {
                "lib.py": (
                    '"""Never call eval(user_input) or os.system(cmd)."""\n'
                    "# subprocess.run(cmd, shell=True)\n"
                    'HELP = "pickle.loads(blob) is unsafe"\n'
                    "def ok():\n"
                    '    return eval("1 + 1")\n'
                ),
            }
        )
        with repo:
            document = run_scan(repo.name, lenses=["security"])
        self.assertFalse({"security/dangerous-eval", "security/shell-injection",
                          "security/unsafe-deserialization"} & rule_ids(document))

    def test_aliases_are_resolved(self):
        repo = make_repo({"run.py": "import subprocess as sp\n\ndef go(name):\n    sp.call('ls ' + name, shell=True)\n"})
        with repo:
            document = run_scan(repo.name, lenses=["security"])
        self.assertIn("security/shell-injection", rule_ids(document))

    def test_safe_yaml_and_constant_shell_are_not_flagged(self):
        repo = make_repo(
            {
                "cfg.py": (
                    "import subprocess\nimport yaml\n\n"
                    "def load(f):\n    return yaml.load(f, Loader=yaml.SafeLoader)\n\n"
                    "def run():\n    subprocess.run('make build', shell=True)\n"
                )
            }
        )
        with repo:
            document = run_scan(repo.name, lenses=["security"])
        self.assertFalse({"security/unsafe-deserialization", "security/shell-injection"} & rule_ids(document))

    def test_sql_built_in_a_variable(self):
        repo = make_repo(
            {
                "db.py": (
                    "def find(conn, name):\n"
                    "    query = 'SELECT * FROM users WHERE name = %s' % name\n"
                    "    return conn.execute(query)\n"
                )
            }
        )
        with repo:
            document = run_scan(repo.name, lenses=["security"])
        finding = next(f for f in document["findings"] if f["rule_id"] == "security/sql-string-building")
        self.assertEqual([c["start_line"] for c in finding["citations"]], [2, 3])

    def test_test_code_is_not_held_to_structure_rules(self):
        body = "def test_long():\n" + "".join(f"    x{i} = {i}\n" for i in range(120))
        repo = make_repo({"tests/test_big.py": body, "src/app.py": body.replace("test_long", "long_job")})
        with repo:
            document = run_scan(repo.name, lenses=["architecture"])
        paths = {f["citations"][0]["path"] for f in document["findings"] if f["rule_id"] == "architecture/long-function"}
        self.assertEqual(paths, {"src/app.py"})


class SecretsTest(unittest.TestCase):
    def test_secret_is_found_but_never_copied(self):
        key = fake_aws_key()
        repo = make_repo({"settings.py": f'AWS_ACCESS_KEY_ID = "{key}"\n'})
        with repo:
            document = run_scan(repo.name, lenses=["security"])
        self.assertIn("security/hardcoded-secret", rule_ids(document))
        self.assertEqual(document["verification"]["grounding_score"], 1.0)
        outputs = [json.dumps(document)] + [render(document, fmt) for fmt in ("html", "md", "sarif")]
        for output in outputs:
            self.assertNotIn(key, output)

    def test_placeholders_and_env_names_are_not_secrets(self):
        repo = make_repo(
            {
                # Split literals keep the repository's own credential scanners quiet.
                "config.py": (
                    "API_" + 'KEY = "OPENAI_API_KEY"\n'
                    "pass" + 'word = "changeme-please-123"\n'
                    'token = "${{ secrets.DEPLOY }}"\n'
                )
            }
        )
        with repo:
            document = run_scan(repo.name, lenses=["security"])
        self.assertNotIn("security/hardcoded-secret", rule_ids(document))


class StructureTest(unittest.TestCase):
    def test_python_import_cycle(self):
        repo = make_repo(
            {
                "pkg/__init__.py": "",
                "pkg/a.py": "from pkg import b\n",
                "pkg/b.py": "from typing import TYPE_CHECKING\nfrom . import a\n",
                "pkg/c.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from pkg import a\n",
            }
        )
        with repo:
            document = run_scan(repo.name, lenses=["architecture"])
        cycles = [f for f in document["findings"] if f["rule_id"] == "architecture/import-cycle"]
        self.assertEqual(len(cycles), 1)
        self.assertEqual(sorted(cycles[0]["evidence"]["modules"]), ["pkg/a.py", "pkg/b.py"])

    def test_typescript_import_cycle_ignores_type_imports(self):
        repo = make_repo(
            {
                "src/a.ts": "import { b } from './b';\nexport const a = 1;\n",
                "src/b.ts": "import { a } from './a.js';\nexport const b = a;\n",
                "src/c.ts": "import type { a } from './a';\nexport const c = 1;\n",
                "src/d.ts": "import { c } from './c';\n",
            }
        )
        with repo:
            document = run_scan(repo.name, lenses=["architecture"])
        cycles = [f for f in document["findings"] if f["rule_id"] == "architecture/import-cycle"]
        self.assertEqual([sorted(f["evidence"]["modules"]) for f in cycles], [["src/a.ts", "src/b.ts"]])

    def test_broken_markdown_link(self):
        repo = make_repo({"README.md": "# X\n\n## Install\n\nSee [guide](docs/guide.md) and [ok](README.md).\n"})
        with repo:
            document = run_scan(repo.name, lenses=["product"])
        links = [f for f in document["findings"] if f["rule_id"] == "product/broken-doc-link"]
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["citations"][1], {"kind": "absence", "paths": ["docs/guide.md"], "globs": []})


class ArgumentsTest(unittest.TestCase):
    def test_parse_lenses(self):
        self.assertEqual(parse_lenses(None), list(LENSES))
        self.assertEqual(parse_lenses("security, architecture"), ["architecture", "security"])
        with self.assertRaises(ScanError):
            parse_lenses("vibes")


if __name__ == "__main__":
    unittest.main()
