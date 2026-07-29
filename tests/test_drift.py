from __future__ import annotations

import unittest

from lucebox_formal.drift import DriftError, changed_paths, parse_name_status


class DriftTests(unittest.TestCase):
    def test_parses_nul_delimited_rename_without_losing_either_path(self) -> None:
        changes = parse_name_status("R087\0old name.h\0new name.h\0")
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].status, "renamed")
        self.assertEqual(changes[0].score, 87)
        self.assertEqual(
            changed_paths(changes),
            ("old name.h", "new name.h"),
        )

    def test_rejects_truncated_rename(self) -> None:
        with self.assertRaisesRegex(DriftError, "truncated"):
            parse_name_status("R100\0old.h\0")

    def test_rejects_parent_traversal_path(self) -> None:
        with self.assertRaisesRegex(DriftError, "inside the repository"):
            parse_name_status("A\0../outside.h\0")


if __name__ == "__main__":
    unittest.main()
