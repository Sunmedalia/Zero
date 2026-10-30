#!/usr/bin/env python3
"""Synthetic procedure classification through the pinned Windows generator (VSL 1.0)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
PIN='881e970121c16f0932fb9d16fbd5fb258cbcbf75'
def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    from volatility3.plugins.windows.windows import Windows
    from volatility3.framework.objects import utility
    from volatility3.framework.interfaces import renderers
    original=utility.array_to_string
    cases=[]
    try:
        # The fake process name is outside this test's scope; classification runs
        # in the actual generator, including skip-vs-absent handling.
        utility.array_to_string=lambda array: 'test.exe'
        for value in [None,0,1,0xfff,0x1000,0x1001,0x7ff900001234,0xfffff80012345678]:
            window=SimpleNamespace(vol=SimpleNamespace(offset=0x1000),get_process=lambda:SimpleNamespace(ImageFileName=None,UniqueProcessId=8),get_session_id=lambda:1,get_window_procedure=lambda:value)
            harness=SimpleNamespace(context=None,config_path='synthetic',config={'kernel':'test'},list_windows=lambda *args:[('WinSta0','Default',window,'test')])
            rows=list(Windows._generator(harness));result=None
            if rows:
                procedure=rows[0][1][5];result='N/A' if isinstance(procedure,renderers.BaseAbsentValue) else hex(procedure)
            cases.append({'value':value,'expected':result,'retained':bool(rows)})
    finally:utility.array_to_string=original
    return {'reference_commit':PIN,'source_sha256':hashlib.sha256((checkout/'volatility3/framework/plugins/windows/windows.py').read_bytes()).hexdigest(),'scope':'Synthetic actual-generator procedure classification only; fake process identity','cases':cases}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/gui-window-procedures.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
