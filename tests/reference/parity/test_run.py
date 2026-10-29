import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from run import compare_artifacts, digest, run
from inventory import COMMIT


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


class ExecutableIdentityTests(unittest.TestCase):
    def test_rebuild_during_native_execution_invalidates_entire_batch(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            binary, image = root / 'zero', root / 'image'
            binary.write_bytes(b'first build')
            image.write_bytes(b'synthetic memory')
            config = {'samples': [{'id': 'fixture', 'image': str(image),
                                  'image_sha256': digest(image), 'symbol_files': [],
                                  'zero_symbols': str(root / 'symbols')}],
                      'cases': [{'sample': 'fixture', 'zero_plugin': 'test'}]}
            output = root / 'result'
            def rebuilt(*_args):
                binary.write_bytes(b'rebuilt during execution')
                return {'status': 'completed', 'exit_code': 0}
            with patch('run.subprocess.check_output', side_effect=[COMMIT + '\n', '']), \
                 patch('run.execute', side_effect=rebuilt) as execute:
                with self.assertRaisesRegex(ValueError, 'executable changed'):
                    run(config, output, binary, root, root / 'python', 10)
                self.assertEqual(execute.call_count, 1)
            self.assertFalse((output / 'summary.json').exists())
