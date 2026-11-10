"""Exercise the release workflow's rules-copy step without building the platform matrix."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


REPO = Path(__file__).resolve().parents[1]


def rules_copy_step():
    """Read this literal shell block so the tests execute the actual packaging commands."""
    lines = (REPO / ".github/workflows/release.yml").read_text().splitlines()
    start = lines.index("      - name: Use one complete rules snapshot")
    if lines[start + 1] != "        run: |":
        raise AssertionError("The rules packaging step must use a literal shell block")
    body = []
    for line in lines[start + 2 :]:
        if line.strip() and not line.startswith("          "):
            break
        body.append(line)
    if not body:
        raise AssertionError("Missing rules packaging commands")
    return textwrap.dedent("\n".join(body))


class ReleaseRulesPackagingTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="hayabusa-package-test-")
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.seed = self.root / "source"
        self.canonical = self.root / "one-package/rules"
        self.merged = self.root / "all-packages/rules"
        self.git(self.root, "init", "-b", "main", self.seed)
        self.git(self.seed, "config", "user.name", "Packaging test")
        self.git(self.seed, "config", "user.email", "packaging@example.invalid")
        self.git(self.seed, "config", "commit.gpgsign", "false")
        self.git(self.seed, "config", "core.hooksPath", "/dev/null")
        (self.seed / "active.yml").write_text("title: Original rule\n")
        self.commit("Initial rule")
        (self.seed / "config").mkdir()
        (self.seed / "config/mapping.yml").write_text("version: canonical\n")
        self.commit("Canonical rules snapshot")
        self.canonical.parent.mkdir()
        self.git(self.root, "clone", "--depth", "1", self.seed.as_uri(), self.canonical)
        self.merged.parent.mkdir()
        self.binary = self.merged.parent / "hayabusa-platform-binary"
        self.binary.write_bytes(b"platform binary must survive rules replacement")

    def git(self, cwd, *args):
        result = subprocess.run(
            ["git", *(str(arg) for arg in args)], cwd=cwd, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout.strip()

    def commit(self, message):
        self.git(self.seed, "add", "--all")
        self.git(self.seed, "commit", "-m", message)

    def package(self):
        return subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", rules_copy_step()],
            cwd=self.root,
            capture_output=True,
            text=True,
        )

    def assert_canonical(self):
        self.assertEqual(
            self.git(self.merged, "rev-parse", "HEAD"),
            self.git(self.canonical, "rev-parse", "HEAD"),
        )
        self.assertEqual(self.git(self.merged, "rev-parse", "--is-shallow-repository"), "true")
        self.assertEqual(self.git(self.merged, "rev-list", "--count", "HEAD"), "1")
        self.assertEqual(self.git(self.merged, "status", "--porcelain"), "")
        self.assertEqual(
            (self.merged / "config/mapping.yml").read_bytes(),
            (self.canonical / "config/mapping.yml").read_bytes(),
        )
        self.assertEqual(self.binary.read_bytes(), b"platform binary must survive rules replacement")

    def test_mixed_revisions_do_not_leave_untracked_rules_after_an_update(self):
        shutil.copytree(self.canonical, self.merged)
        # Simulate another matrix artifact contributing different files and a newly added rule.
        (self.merged / "active.yml").write_text("title: Another matrix revision\n")
        (self.merged / "config/mapping.yml").write_text("version: another revision\n")
        (self.merged / "retired.yml").write_text("title: Rule later removed upstream\n")
        result = self.package()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_canonical()

        # Upstream adds and later removes the other artifact's rule. An untracked copy would
        # survive the reset/fetch/fast-forward sequence used by update-rules.
        (self.seed / "retired.yml").write_text("title: Rule later removed upstream\n")
        self.commit("Add temporary rule")
        (self.seed / "retired.yml").unlink()
        (self.seed / "active.yml").write_text("title: Current rule\n")
        self.commit("Retire temporary rule")
        self.git(self.merged, "reset", "--hard", "main")
        self.git(self.merged, "fetch", "origin", "main")
        self.git(self.merged, "merge", "--ff-only", "FETCH_HEAD")
        self.assertEqual(
            self.git(self.merged, "rev-parse", "HEAD"),
            self.git(self.seed, "rev-parse", "HEAD"),
        )
        self.assertFalse((self.merged / "retired.yml").exists())
        self.assertEqual(self.git(self.merged, "status", "--porcelain"), "")

    def test_complete_snapshot_can_be_copied_without_a_merged_rules_directory(self):
        result = self.package()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_canonical()

    def test_missing_source_metadata_preserves_existing_package(self):
        shutil.copytree(self.canonical, self.merged)
        (self.canonical / ".git").rename(self.root / "source-metadata-backup")
        result = self.package()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.merged / ".git/HEAD").is_file())
        self.assertEqual(self.git(self.merged, "status", "--porcelain"), "")


if __name__ == "__main__":
    unittest.main()
