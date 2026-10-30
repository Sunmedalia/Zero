#!/usr/bin/env python3
"""Generate synthetic skeleton-key semantic vectors using the fixed reference.
Volatility reference wrappers are VSL 1.0; no recovered image content is embedded.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    import capstone
    from volatility3.framework import exceptions
    from volatility3.plugins.windows.malware.skeleton_key_check import Skeleton_Key_Check as Ref
    assert capstone.__version__=='5.0.6'
    vectors=[]
    # mov ecx,[rip+0x20]; lea rdx,[rip+0x40], starting at 0x1000.
    standard=bytes.fromhex('8b0d20000000 488d1540000000 c3')
    cases=[('standard',standard,3),('unreadable-count',standard,None),('zero-count',standard,0),
           ('first-mov-register',bytes.fromhex('89d1 488d1540000000'),None),
           ('lea-before-count',bytes.fromhex('488d1540000000 8b0d20000000'),3),
           ('non-rip-first-lea',bytes.fromhex('8b0d20000000 488d14c0 488d1540000000'),3),
           ('trap-before-lea',bytes.fromhex('8b0d20000000 cc 488d1540000000'),3),
           ('signed-rip',bytes.fromhex('8b0de0ffffff 488d15c0ffffff'),7)]
    for name,code,count in cases:
        count_address=0xfe6 if name=='signed-rip' else 0x1026
        class Layer:
            def read(self,at,size):
                if count is not None and at==count_address and size==4:return count.to_bytes(4,'little')
                raise exceptions.InvalidAddressException('synthetic',at)
        class Harness:
            context=SimpleNamespace(layers={'synthetic':Layer()})
            _get_rip_relative_target=Ref._get_rip_relative_target
            def _construct_ecrypt_array(self,start,count,types):return {'start':start,'count':count}
        expected=Ref._analyze_cdlocatecsystem(Harness(),code,0x1000,None,'synthetic')
        vectors.append({'id':name,'start':0x1000,'code':code.hex(),'count_address':count_address,'count':count,'expected':expected})
    hooks=[]
    for initialize,decrypt,expected in [(0x1000,0x2000,None),(0xfff,0x1800,None),(0x1800,0x2001,None),(0x1100,0x1200,(0x1100,0x1200)),(0x1101,0x1200,(0x1100,0x1200)),(0,0,None)]:
        record=SimpleNamespace(Initialize=initialize,Decrypt=decrypt)
        found=Ref._check_for_skeleton_key_symbols(None,record,*expected) if expected else Ref._check_for_skeleton_key_vad(None,record,0x1000,0x1000)
        hooks.append({'initialize':initialize,'decrypt':decrypt,'expected':{'initialize':expected[0],'decrypt':expected[1]} if expected else None,'hooked':found})
    source=checkout/'volatility3/framework/plugins/windows/malware/skeleton_key_check.py'
    layout=checkout/'volatility3/framework/symbols/windows/kerb_ecrypt.json'
    return {'reference_commit':PIN,'reference_source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'reference_layout_sha256':hashlib.sha256(layout.read_bytes()).hexdigest(),'scope':'Synthetic export analysis and hook boundary vectors; not whole-plugin evidence','export_cases':vectors,'hook_cases':hooks}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/skeleton-key.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
