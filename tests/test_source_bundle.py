"""Source packages exclude untracked and generated workspace files."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import build


class SourceBundleTests(unittest.TestCase):
    def test_git_workspace_uses_tracked_inputs_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            source = root / "apps" / "api"
            source.mkdir(parents=True)
            tracked = source / "tracked.py"
            tracked.write_text("print('tracked')\n")
            (source / "untracked.py").write_text("print('untracked')\n")
            generated = root / "apps" / "fleet" / "web" / "dist"
            generated.mkdir(parents=True)
            (generated / "output.js").write_text("generated")
            linked = source / "linked.py"
            linked.symlink_to(tracked)
            subprocess.run(["git", "add", "apps/api/tracked.py", "apps/api/linked.py"],
                           cwd=root, check=True)
            with patch.object(build, "ROOT", root):
                self.assertEqual(build.source_files(), [tracked])


if __name__ == "__main__":
    unittest.main()
