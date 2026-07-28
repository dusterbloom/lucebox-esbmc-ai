from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from lucebox_formal.security import (
    BundleError,
    extract_bundle,
    safe_repo_path,
    validate_patch_paths,
)


class SecurityTests(unittest.TestCase):
    def test_safe_repo_path_rejects_parent(self) -> None:
        with self.assertRaises(BundleError):
            safe_repo_path(Path("/workspace"), "../secret")

    def test_patch_may_touch_only_declared_files(self) -> None:
        patch = """\
--- a/server/src/state.h
+++ b/server/src/state.h
@@ -1 +1 @@
-old
+new
"""
        validate_patch_paths(patch, {"server/src/state.h"})
        with self.assertRaises(BundleError):
            validate_patch_paths(patch, {"server/src/other.h"})

    def test_rejects_archive_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp) / "bundle.tar.gz"
            with tarfile.open(bundle, "w:gz") as archive:
                info = tarfile.TarInfo("../escape")
                payload = b"no"
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            with self.assertRaises(BundleError):
                extract_bundle(bundle, Path(temp) / "out")


if __name__ == "__main__":
    unittest.main()
