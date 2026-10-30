import tempfile
from pathlib import Path
import unittest
from strings_input import generate

class StringsInputTests(unittest.TestCase):
    def test_records_come_from_the_capture_and_duplicate_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            image=Path(directory)/'sample.raw'
            output=Path(directory)/'strings.txt'
            data=bytes(17)+b'Actual image bytes'+bytes(8000)
            image.write_bytes(data)
            first=generate(image,output)
            second=generate(image,output)
            self.assertEqual(first,second)
            rows=output.read_bytes().splitlines()
            self.assertEqual(rows[0],rows[-1])
            for row in rows:
                number,text=row.split(b' ',1)
                address=int(number)
                self.assertEqual(data[address:address+len(text)],text)

if __name__=='__main__':
    unittest.main()
