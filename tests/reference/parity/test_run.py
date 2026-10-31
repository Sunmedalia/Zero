import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from run import compare_artifacts, digest, run, verify_native_symbol
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


    def test_symbolic_links_cannot_supply_artifact_evidence(self):
        for kind in ['file', 'directory', 'dangling', 'root']:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                left, right, outside = root / 'zero', root / 'reference', root / 'outside'
                right.mkdir()
                outside.mkdir()
                (outside / 'module.elf').write_bytes(b'ELF payload')
                if kind == 'root':
                    left.symlink_to(outside, target_is_directory=True)
                else:
                    left.mkdir()
                    target = {'file': outside / 'module.elf', 'directory': outside,
                              'dangling': root / 'missing'}[kind]
                    (left / 'linked').symlink_to(target, target_is_directory=kind == 'directory')
                for native, reference in [(left, right), (right, left)]:
                    with self.assertRaisesRegex(ValueError, 'symbolic link'):
                        compare_artifacts(native, reference)


class ComparisonFailureTests(unittest.TestCase):
    def test_post_comparison_io_failure_cannot_preserve_success(self):
        for failure_stage in ['artifacts', 'output_digest']:
            with self.subTest(stage=failure_stage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary, image = root / 'zero', root / 'image'
                binary.write_bytes(b'frozen build')
                image.write_bytes(b'synthetic memory')
                config = {'samples': [{'id': 'fixture', 'image': str(image),
                                      'image_sha256': digest(image), 'symbol_files': [],
                                      'zero_symbols': str(root / 'symbols'),
                                      'reference_symbols': str(root / 'symbols')}],
                          'cases': [{'sample': 'fixture', 'zero_plugin': 'test',
                                     'reference_plugin': 'test', 'mapping': str(root / 'mapping.json'),
                                     'artifact_dump': failure_stage == 'artifacts'}]}
                (root / 'mapping.json').write_text('{}')
                output = root / 'result'
                original_digest = digest

                def checked_digest(path):
                    if failure_stage == 'output_digest' and path.name == 'zero.json':
                        raise OSError('output became unreadable')
                    return original_digest(path)

                def completed(_command, stdout, _stderr, _timeout):
                    stdout.write_text('{}')
                    (output / '000' / 'zero.json').write_text('{}')
                    return {'status': 'completed', 'exit_code': 0}

                with patch('run.subprocess.check_output', side_effect=[COMMIT + '\n', '']), \
                     patch('run.execute', side_effect=completed), \
                     patch('run.verify_native_symbol', return_value=None), \
                     patch('run.compare', return_value={'passed': True}), \
                     patch('run.compare_artifacts', side_effect=OSError('artifact unreadable')), \
                     patch('run.digest', side_effect=checked_digest):
                    report = run(config, output, binary, root, root / 'python', 10)
                self.assertFalse(report['passed'])
                self.assertFalse(report['cases'][0]['passed'])
                self.assertIn('unreadable', report['cases'][0]['error'])


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


class NativeSymbolSourceTests(unittest.TestCase):
    def test_actual_cached_fallback_with_different_bytes_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory) / 'requested.json'
            actual = Path(directory) / 'cached.json'
            expected.write_text('{"metadata":{"converter":"old"}}')
            actual.write_text('{"metadata":{"converter":"new"}}')
            with self.assertRaisesRegex(ValueError, 'different ISF'):
                verify_native_symbol({'zero_symbols': str(expected)}, {'symbol': str(actual)})

    def test_same_bytes_at_another_path_preserve_actual_and_configured_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory) / 'requested.json.xz'
            actual = Path(directory) / 'cached.json.xz'
            expected.write_bytes(b'same frozen input bytes')
            actual.write_bytes(expected.read_bytes())
            proof = verify_native_symbol({'zero_symbols': str(expected)}, {'symbol': str(actual)})
            self.assertEqual(proof['path'], str(actual.resolve()))
            self.assertEqual(proof['configured_path'], str(expected.resolve()))
            self.assertEqual(proof['sha256'], proof['configured_sha256'])

    def test_unreadable_actual_symbol_cannot_be_certified(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                verify_native_symbol({'zero_symbols': str(Path(directory) / 'input.json')},
                                     {'symbol': str(Path(directory) / 'missing.json')})

    def test_directory_and_archive_selection_are_outside_explicit_isf_guard(self):
        for source in ['symbols', 'symbols.zip']:
            self.assertIsNone(verify_native_symbol({'zero_symbols': source}, {}))
