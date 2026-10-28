import unittest
from audit import audit
from inventory import COMMIT, VERSION


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {'reference_version': VERSION, 'reference_commit': COMMIT,
                         'plugins': [{'reference': 'linux.pslist.PsList', 'replacement': None,
                                      'source_sha256': 'a' * 64, 'platform': 'linux'}]}
        self.case = {'reference_plugin': 'linux.pslist.PsList', 'reference_commit': COMMIT,
                     'case_id': 'default', 'passed': True, 'sample_source': 'https://example.com/sample',
                     'image_sha256': 'b' * 64,
                     'comparison': {'passed': True, 'positive_evidence': True, 'all_columns_mapped': True}}
        self.contract = {'linux.pslist.PsList': {'source_sha256': 'a' * 64,
                         'requirements_reviewed': True, 'failure_cases_reviewed': True,
                         'required_cases': ['default', 'threads']}}

    def test_default_success_does_not_claim_plugin_parity(self):
        result = audit(self.manifest, [self.case])
        self.assertEqual(result['passed_cases'], 1)
        self.assertEqual(result['verified_plugins'], 0)
        self.assertFalse(result['complete'])
        self.assertFalse(audit(self.manifest, [self.case], self.contract)['complete'])

    def test_every_reviewed_case_is_required(self):
        thread = dict(self.case, case_id='threads')
        self.assertTrue(audit(self.manifest, [self.case, thread], self.contract)['complete'])
        self.contract['linux.pslist.PsList']['requirements_reviewed'] = False
        self.assertFalse(audit(self.manifest, [self.case, thread], self.contract)['complete'])

    def test_empty_or_unmapped_or_changed_reference_cannot_pass(self):
        self.case['comparison']['positive_evidence'] = False
        with self.assertRaises(ValueError):
            audit(self.manifest, [self.case])
        self.case['comparison']['positive_evidence'] = True
        self.contract['linux.pslist.PsList']['source_sha256'] = 'c' * 64
        with self.assertRaises(ValueError):
            audit(self.manifest, [self.case], self.contract)

    def test_module_extraction_requires_binary_evidence(self):
        name = 'linux.module_extract.ModuleExtract'
        self.manifest['plugins'][0]['reference'] = name
        self.case['reference_plugin'] = name
        with self.assertRaises(ValueError):
            audit(self.manifest, [self.case])
        self.case['artifacts'] = [{'name': 'module.elf', 'passed': True,
                                  'zero_sha256': 'a' * 64, 'reference_sha256': 'a' * 64,
                                  'zero_bytes': 64, 'reference_bytes': 64}]
        self.assertEqual(audit(self.manifest, [self.case])['passed_cases'], 1)
        self.case['artifacts'][0]['reference_sha256'] = 'b' * 64
        with self.assertRaises(ValueError):
            audit(self.manifest, [self.case])


if __name__ == '__main__':
    unittest.main()
