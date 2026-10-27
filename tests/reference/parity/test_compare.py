"""Regression tests for evidence gates, independently of both engines."""
import copy
import unittest
from compare import compare, normalize


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.native = {'columns': ['PID', 'Address'], 'rows': [['1', '0xffffffffb4810940']],
                       'complete': True, 'diagnostics': []}
        self.reference = [{'Pid': 1, 'Offset': 0xffffffffb4810940}]
        self.mapping = {'version': 1, 'keys': ['pid'], 'fields': {
            'pid': {'zero': 'PID', 'reference': 'Pid', 'type': 'integer'},
            'address': {'zero': 'Address', 'reference': 'Offset', 'type': 'address'}}}

    def check(self):
        return compare(self.native, self.reference, self.mapping)

    def test_timestamps_preserve_microseconds_and_require_timezone(self):
        self.assertEqual(normalize('2024-01-01T08:00:00.000001+08:00', 'timestamp'),
                         normalize('2024-01-01T00:00:00.000001Z', 'timestamp'))
        self.assertNotEqual(normalize('2024-01-01T00:00:00.000002Z', 'timestamp'),
                            normalize('2024-01-01T00:00:00.000001Z', 'timestamp'))
        with self.assertRaises(ValueError):
            normalize('2024-01-01T00:00:00', 'timestamp')

    def test_full_fields_agree(self):
        self.assertTrue(self.check()['passed'])

    def test_missing_extra_and_conflicting_records_fail(self):
        self.reference.append({'Pid': 2, 'Offset': 0})
        self.native['rows'].append(['3', '0x0'])
        self.reference[0]['Offset'] += 1
        result = self.check()
        self.assertEqual(result['missing'], [[2]])
        self.assertEqual(result['extra'], [[3]])
        self.assertEqual(len(result['conflicts']), 1)
        self.assertFalse(result['passed'])

    def test_duplicates_are_not_silently_collapsed(self):
        self.native['rows'] *= 2
        self.assertFalse(self.check()['passed'])
        self.assertEqual(self.check()['duplicates'][0]['count'], 2)

    def test_null_cannot_prove_equality(self):
        self.reference[0]['Offset'] = None
        self.assertFalse(self.check()['passed'])
        self.assertEqual(len(self.check()['unverifiable']), 1)

    def test_high_address_bits_cannot_be_masked_away(self):
        self.reference[0]['Offset'] &= (1 << 48) - 1
        self.assertFalse(self.check()['passed'])
        self.mapping['fields']['address']['reference_type'] = 'address48'
        self.assertTrue(self.check()['passed'])
        self.native['rows'][0][1] = '0x1234ffffb4810940'
        self.assertFalse(self.check()['passed'])

    def test_empty_and_unmapped_columns_do_not_prove_parity(self):
        self.reference[0]['Extra'] = 'unmapped'
        self.assertFalse(self.check()['passed'])
        self.reference = []
        self.native['rows'] = []
        self.assertFalse(self.check()['passed'])
        self.mapping['allow_empty'] = True
        self.assertTrue(self.check()['passed'])
        self.assertFalse(self.check()['positive_evidence'])

    def test_partial_warnings_and_tree_children_are_preserved(self):
        self.native['complete'] = False
        self.native['diagnostics'] = ['missing page elsewhere']
        self.reference = [{'Pid': 2, 'Offset': 0, '__children': self.reference}]
        self.native['rows'].append(['2', '0'])
        self.assertFalse(self.check()['passed'])
        self.mapping['allow_partial'] = True
        result = self.check()
        self.assertTrue(result['passed'])
        self.assertFalse(result['zero_complete'])
        self.assertEqual(result['zero_diagnostics'], self.native['diagnostics'])

    def test_missing_column_and_invalid_type_are_errors(self):
        broken = copy.deepcopy(self.mapping)
        broken['fields']['pid']['zero'] = 'not-present'
        with self.assertRaises(ValueError):
            compare(self.native, self.reference, broken)
        self.reference[0]['Pid'] = True
        with self.assertRaises(ValueError):
            self.check()


if __name__ == '__main__':
    unittest.main()
