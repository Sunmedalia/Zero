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

    def test_optional_timestamp_is_explicit_and_still_strict(self):
        self.assertIsNone(normalize('N/A', 'na_timestamp'))
        self.assertIsNone(normalize(None, 'na_timestamp'))
        self.assertEqual(normalize('2026-10-29T08:00:00+08:00', 'na_timestamp'),
                         normalize('2026-10-29T00:00:00Z', 'timestamp'))
        for value in ('n/a', '2026-10-29T00:00:00', 'invalid'):
            with self.assertRaises(ValueError):
                normalize(value, 'na_timestamp')

    def test_optional_boolean_retains_false_and_rejects_unknown_values(self):
        for item in (None, 'N/A'):
            self.assertIsNone(normalize(item, 'na_boolean'))
        for item in (False, 'false'):
            self.assertIs(normalize(item, 'na_boolean'), False)
        for item in (True, 'true'):
            self.assertIs(normalize(item, 'na_boolean'), True)
        for item in ('False', 'unknown', 0, 1, ''):
            with self.assertRaises(ValueError):
                normalize(item, 'na_boolean')

    def test_strings_owners_compare_members_not_randomized_set_order(self):
        first = 'kernel:0x1000, Process 4:0x2000'
        second = 'Process 4:0x2000, kernel:0x1000'
        self.assertEqual(normalize(first, 'strings_owners'), normalize(second, 'strings_owners'))
        self.assertNotEqual(normalize(first, 'strings_owners'), normalize('kernel:0x1000', 'strings_owners'))
        self.assertEqual(normalize('FREE MEMORY', 'strings_owners'), ('FREE MEMORY',))
        for value in ('', None, 'kernel:0x1, kernel:0x1', 'kernel:0x1, garbage'):
            with self.assertRaises(ValueError):
                normalize(value, 'strings_owners')

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

    def test_multiset_requires_exact_multiplicity_and_all_fields(self):
        self.mapping['duplicate_keys'] = 'multiset'
        self.native['rows'] *= 2
        self.assertFalse(self.check()['passed'])
        self.reference += copy.deepcopy(self.reference)
        self.assertTrue(self.check()['passed'])
        self.reference[1]['Offset'] += 1
        self.assertFalse(self.check()['passed'])
        self.native['rows'].reverse()
        self.assertFalse(self.check()['passed'])
        self.native['rows'][0] = ['1', hex(self.reference[1]['Offset'])]
        self.assertTrue(self.check()['passed'])

    def test_multiset_absence_is_explicit_and_one_sided_absence_fails(self):
        self.mapping['duplicate_keys'] = 'multiset'
        self.mapping['fields']['address']['allow_absent'] = True
        self.native['rows'] = [['1', ''], ['1', '']]
        self.reference = [{'Pid': 1, 'Offset': None}] * 2
        self.assertEqual(self.check()['matched_absent'], {'address': 2})
        self.assertTrue(self.check()['passed'])
        self.reference[1] = {'Pid': 1, 'Offset': 123}
        self.assertFalse(self.check()['passed'])
        self.mapping['duplicate_keys'] = 'ignore'
        with self.assertRaises(ValueError):
            self.check()

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
    def test_optional_integer_preserves_zero_and_rejects_text_and_boolean(self):
        self.assertIsNone(normalize("N/A", "na_integer"))
        self.assertIsNone(normalize(None, "na_integer"))
        self.assertEqual(normalize("0", "na_integer"), 0)
        self.assertEqual(normalize(1234, "na_integer"), 1234)
        for value in (True, "unknown"):
            with self.assertRaises(ValueError):
                normalize(value, "na_integer")

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
