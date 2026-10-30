#!/usr/bin/env python3
"""Synthetic top-down object padding through pinned POOL_HEADER.get_object (VSL 1.0)."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
from types import SimpleNamespace
PIN='881e970121c16f0932fb9d16fbd5fb258cbcbf75'
def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    from volatility3.framework.symbols.windows.extensions.pool import POOL_HEADER
    cases=[]
    for encoded in [0,2,4,128]:
        data=bytearray(128);data[28:32]=encoded.to_bytes(4,'little');data[58]=2
        class Layer:
            def read(self,at,size,pad=False):return bytes(data[at:at+size]).ljust(size,b'\0')
        header_type=SimpleNamespace(size=8,relative_child_offset=lambda name:{'Body':48,'InfoMask':26,'PointerCount':0}[name],members={'PointerCount':(0,SimpleNamespace(size=8))})
        ctx=SimpleNamespace(symbol_space=SimpleNamespace(get_type=lambda name:header_type),layers={'synthetic':Layer()},object=lambda *args,**kw:SimpleNamespace(vol=SimpleNamespace(offset=kw['offset']),is_valid=lambda:True))
        header=SimpleNamespace(_context=ctx,vol=SimpleNamespace(type_name='nt!_POOL_HEADER',size=16,offset=0,layer_name='synthetic'),BlockSize=8,_calculate_optional_header_lengths=lambda context,table:(['CREATOR_INFO','PADDING_INFO'],[32,4]))
        constraint=SimpleNamespace(type_name='gui!tagWINDOWSTATION',object_type='WindowStation')
        found=[obj.vol.offset for obj in POOL_HEADER.get_object(header,constraint,True,kernel_symbol_table='nt',native_layer_name='synthetic')]
        cases.append({'encoded_padding':encoded,'expected_bodies':found})
    reads=[]
    class MissingTailLayer:
        def read(self,at,size,pad=False):
            reads.append({'offset':at,'length':size,'pad':pad})
            assert pad, 'the pinned carving window must request padded reads'
            return bytes(size)
    ctx.layers={'synthetic':MissingTailLayer()}
    header.vol.offset=0x1fc0
    padded=[obj.vol.offset for obj in POOL_HEADER.get_object(header,constraint,True,kernel_symbol_table='nt',native_layer_name='synthetic')]
    return {'reference_commit':PIN,'source_sha256':hashlib.sha256((checkout/'volatility3/framework/symbols/windows/extensions/pool.py').read_bytes()).hexdigest(),'scope':'Synthetic actual top-down padding branch; object is_valid stubbed true to isolate carving. Missing-tail read is a synthetic padded layer; verifies get_object requests padding and keeps candidates, not object validity.','cases':cases,'missing_tail':{'reads':reads,'expected_bodies':padded}}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/gui-pool-padding.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
