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

    def test_scoped_comparison_records_excluded_counts_and_preserves_strict_default(self):
        self.reference.append({'Pid': 2, 'Offset': 0})
        self.native['rows'].append(['2', '1'])
        self.assertFalse(self.check()['passed'])
        self.mapping['record_selection'] = {'field': 'pid', 'include': [1], 'scope': 'PID 1 only'}
        result = self.check()
        self.assertTrue(result['passed'])
        self.assertEqual(result['record_selection']['zero_excluded'], 1)
        self.assertEqual(result['record_selection']['reference_excluded'], 1)
        self.assertEqual(result['zero_records'], 1)
        self.native['rows'][0][1] = '0'
        self.assertFalse(self.check()['passed'])
        del self.mapping['record_selection']['scope']
        with self.assertRaises(ValueError):
            self.check()

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

    def test_declared_optional_absence_requires_both_sides_to_be_absent(self):
        self.native['columns'].append('Size')
        self.native['rows'][0].append('')
        self.reference[0]['Size'] = None
        self.mapping['fields']['size'] = {'zero': 'Size', 'reference': 'Size', 'type': 'integer'}
        self.assertFalse(self.check()['passed'])
        self.mapping['fields']['size']['allow_absent'] = True
        result = self.check()
        self.assertTrue(result['passed'])
        self.assertEqual(result['matched_absent'], {'size': 1})
        self.reference[0]['Size'] = 12
        self.assertFalse(self.check()['passed'])


class OptionalTextTests(unittest.TestCase):
    def test_na_marker_requires_explicit_mapping_and_preserves_empty_text(self):
        self.assertEqual(normalize('N/A', 'text'), 'N/A')
        self.assertIsNone(normalize('N/A', 'na_text'))
        self.assertIsNone(normalize(None, 'na_text'))
        self.assertEqual(normalize('', 'na_text'), '')
        self.assertEqual(normalize('0', 'na_text'), '0')
        with self.assertRaises(ValueError):
            normalize(0, 'na_text')

    def test_empty_text_requires_explicit_mapping(self):
        self.assertIsNone(normalize(None, 'text'))
        self.assertEqual(normalize(None, 'empty_text'), '')
        self.assertEqual(normalize('PROPRIETARY_MODULE', 'empty_text'), 'PROPRIETARY_MODULE')
        with self.assertRaises(ValueError):
            normalize(0, 'empty_text')


if __name__ == '__main__':
    unittest.main()
