#!/usr/bin/env python3
"""Actual NameInfo + UNICODE_STRING.String + DRIVER_OBJECT name chain (VSL 1.0)."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
from types import SimpleNamespace
PIN='881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    from volatility3.framework import objects,interfaces,contexts,exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.windows.extensions import DRIVER_OBJECT,UNICODE_STRING
    from volatility3.framework.symbols.windows.extensions.pool import OBJECT_HEADER
    cases=[]
    inputs=[('plain',{}),('odd',{'hex':'6100620078'}),('be-bom',{'hex':'feff00610062'}),('le-bom',{'hex':'fffe61006200'}),('nul',{'hex':'610000006200'}),('bad-surrogate',{'hex':'00d86100'}),('maximum-zero',{'maximum':0}),('maximum-short',{'maximum':1}),('zero-name-length',{'hex':'','buffer':0xffffffffffffffff}),('zero-old-offset',{'old_offset':0}),('old-takes-priority',{'old_offset':32,'mask':0,'table_delta':0}),('no-name-bit',{'old_offset':None,'mask':1,'table_delta':32}),('zero-table-delta',{'old_offset':None,'mask':2,'table_delta':0}),('bad-buffer',{'buffer':0x30000}),('masked-buffer',{'buffer':0xd100000000002100})]
    for case_id,overrides in inputs:
        c=dict(id=case_id,hex='640072007600',maximum=6,buffer=0x2100,old_offset=32,mask=2,table_delta=32)
        c.update(overrides)
        data=bytearray(0x4000);payload=bytes.fromhex(c['hex']);data[0x2100:0x2100+len(payload)]=payload
        ctx=contexts.Context();ctx.layers.add_layer(BufferDataLayer(ctx,'virtual','virtual',buffer=bytes(data)))
        class Pointer(int):
            @property
            def vol(self):return SimpleNamespace(native_layer_name='virtual')
        class Unicode:
            def __init__(self):self.Length=len(payload);self.MaximumLength=c['maximum'];self.Buffer=Pointer(c['buffer']&((1<<48)-1));self.vol=SimpleNamespace(type_name='nt!_UNICODE_STRING')
            @property
            def String(self):return UNICODE_STRING.get_string(self)
        value=Unicode()
        class StringContext:
            def object(self,type_name,**kw):
                info=interfaces.objects.ObjectInformation(layer_name=kw['layer_name'],native_layer_name=kw['layer_name'],offset=kw['offset'])
                return objects.String(ctx,type_name,info,max_length=kw['max_length'],encoding=kw['encoding'],errors=kw['errors'])
        value._context=StringContext()
        calls=[]
        def module_object(ty,**kw):
            calls.append(dict(type=ty,layer=kw['layer_name'],offset=int(kw['offset'])))
            return c['table_delta'] if ty=='unsigned char' else SimpleNamespace(Name=value)
        module=SimpleNamespace(get_symbol=lambda _:SimpleNamespace(address=0x500),object=module_object)
        class Header:
            def __init__(self):
                self._context=SimpleNamespace(modules={'nt':module});self.vol=SimpleNamespace(type_name='nt!_OBJECT_HEADER',offset=0x1100,layer_name='physical',native_layer_name='virtual');self.InfoMask=c['mask']
                if c['old_offset'] is not None:self.NameInfoOffset=c['old_offset']
            @property
            def NameInfo(self):return OBJECT_HEADER.NameInfo.fget(self)
        try:
            name=str(DRIVER_OBJECT.get_driver_name(SimpleNamespace(get_object_header=lambda:Header())))
            error=None
        except (ValueError,exceptions.InvalidAddressException) as exc:
            name=None;error=type(exc).__name__
        c.update(expected=name,error=error,calls=calls);cases.append(c)
    return dict(reference_commit=PIN,pool_sha256=hashlib.sha256((checkout/'volatility3/framework/symbols/windows/extensions/pool.py').read_bytes()).hexdigest(),unicode_sha256=hashlib.sha256((checkout/'volatility3/framework/symbols/windows/extensions/__init__.py').read_bytes()).hexdigest(),scope='Actual NameInfo property, DRIVER_OBJECT name method, UNICODE_STRING.String method and String constructor. Synthetic scalar/field adapter isolates location and decoding; native tests separately read physical/virtual descriptors on real fixture page tables. Does not validate pool carving or every NameInfo fault.',cases=cases)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/driver-names.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
