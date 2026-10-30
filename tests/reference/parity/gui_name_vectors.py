#!/usr/bin/env python3
"""Generate name decoding vectors with the pinned reference utility (VSL 1.0)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
PIN='881e970121c16f0932fb9d16fbd5fb258cbcbf75'
def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    from volatility3.framework.objects import utility
    samples=[('ascii',b'window.exe\0tail'),('invalid-first',b'\xa8\x0c\x0a\xadname'),('invalid-tail',b'win.exe\xfftail'),('literal-replacement','win\ufffdtail'.encode()),('truncated-multibyte',b'name\xe2\x82'),('controls',b'name\tfoo'),('utf8','caf\u00e9.exe'.encode()),('nul',b'\0tail')]
    return {'reference_commit':PIN,'source_sha256':hashlib.sha256((checkout/'volatility3/framework/objects/utility.py').read_bytes()).hexdigest(),'scope':'Synthetic process-name decoding only, no recovered sample strings','cases':[{'id':name,'hex':data.hex(),'expected':utility.bytes_to_decoded_string(data,'utf-8','replace')} for name,data in samples]}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/gui-process-names.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
