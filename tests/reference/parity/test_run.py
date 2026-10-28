import tempfile
import unittest
from pathlib import Path
from run import compare_artifacts


class ArtifactTests(unittest.TestCase):
    def test_complete_file_bytes_and_missing_files_are_checked(self):
        with tempfile.TemporaryDirectory() as root:
            left, right = Path(root) / 'zero', Path(root) / 'reference'
            left.mkdir()
            right.mkdir()
            self.assertEqual(compare_artifacts(left, right), [])
            (left / 'empty.elf').write_bytes(b'')
            (right / 'empty.elf').write_bytes(b'')
            self.assertFalse(compare_artifacts(left, right)[0]['passed'])
            (left / 'empty.elf').unlink()
            (right / 'empty.elf').unlink()
            (left / 'module.elf').write_bytes(b'ELF payload')
            self.assertFalse(compare_artifacts(left, right)[0]['passed'])
            (right / 'module.elf').write_bytes(b'ELF payload')
            self.assertTrue(compare_artifacts(left, right)[0]['passed'])
            (right / 'module.elf').write_bytes(b'ELF changed')
            self.assertFalse(compare_artifacts(left, right)[0]['passed'])
            (right / 'extra.elf').write_bytes(b'extra')
            records = compare_artifacts(left, right)
            self.assertEqual(len(records), 2)
            self.assertTrue(any(r['zero_sha256'] is None for r in records))
