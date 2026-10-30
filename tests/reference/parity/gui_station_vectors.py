#!/usr/bin/env python3
"""Fixed-reference UTF-16 string and station-info vectors; VSL 1.0 wrappers."""
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
    from volatility3.framework import contexts,objects,interfaces
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.windows.extensions.gui import GUIExtensions
    strings=[]
    for name,data in [('plain','station'.encode('utf-16le')),('nul','ab\0tail'.encode('utf-16le')),('control','ab\x01'.encode('utf-16le')),('odd',b'a\0b\0x'),('replacement',b'\0\xd8a\0'),('le-bom',b'\xff\xfea\0b\0'),('be-bom',b'\xfe\xff\0a\0b'),('long',('X'*129).encode('utf-16le'))]:
        ctx=contexts.Context();ctx.layers.add_layer(BufferDataLayer(ctx,'test','synthetic',buffer=data))
        info=interfaces.objects.ObjectInformation(layer_name='synthetic',offset=0,native_layer_name='synthetic')
        value=objects.String(ctx,'synthetic!string',info,max_length=len(data),encoding='utf16',errors='replace')
        strings.append({'id':name,'hex':data.hex(),'expected':str(value)})
    info_cases=[]
    for name,sid in [('ab',0),('a',0),('',0),('ab\x01',0),('X'*129,2),('😀',1),('ab',255),('ab',256),('ab',None)]:
        harness=SimpleNamespace(get_name=lambda _:name,get_session_id=lambda:sid)
        value=GUIExtensions.tagWINDOWSTATION.get_info(harness,'kernel')
        info_cases.append({'name':name,'session':sid,'expected':list(value)})
    return {'reference_commit':PIN,'source_sha256':hashlib.sha256((checkout/'volatility3/framework/symbols/windows/extensions/gui.py').read_bytes()).hexdigest(),'scope':'Synthetic real String constructor and get_info semantics; no real station names','strings':strings,'info':info_cases}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/gui-stations.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
