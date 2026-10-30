#!/usr/bin/env python3
"""Actual DriverIrp handler gate and Modules kernel start (VSL 1.0)."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
PIN='881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    from volatility3.plugins.windows import driverirp,ssdt,driverscan,modules
    from volatility3.framework import symbols,exceptions
    from volatility3.framework.objects import Pointer,DataFormatInfo
    cases=[]
    for width in [4,8]:
        default=0x80000000 if width==4 else 0xffff800000000000
        mask=(1<<(32 if width==4 else 48))-1
        for case_id,start in [('default',default),('missing-start',None),('raised-start',default+0x10000),('zero-start',0)]:
            def scalar(**kw):
                if start is None:raise exceptions.InvalidAddressException('virtual',0x1000)
                return start
            module=SimpleNamespace(symbol_table_name='nt',layer_name='virtual',get_symbol=lambda _:SimpleNamespace(address=0x1000),object=scalar)
            class Layers(dict):
                def read(self,layer,at,length):return raw.to_bytes(width,'little')
            context=SimpleNamespace(modules={'kernel':module},layers=Layers(virtual=SimpleNamespace(address_mask=mask)))
            raw_values=[0,default-1,default,default+0x10000,(1<<(width*8))-1]
            if width==8:raw_values.extend([0x1234800000000000,0x1234000000001000])
            values=[]
            for raw in raw_values:
                pointer=Pointer._unmarshall(context,DataFormatInfo(width,'little',False),SimpleNamespace(native_layer_name='virtual',layer_name='virtual',offset=0))
                values.append(pointer)
            class Handlers:
                def __len__(self):return len(values)+2
                def __getitem__(self,index):
                    if index==len(values):raise exceptions.InvalidAddressException('virtual',index)
                    if index==len(values)+1:return values[-1]
                    return values[index]
            driver=SimpleNamespace(vol=SimpleNamespace(offset=0x2000),get_driver_name=lambda:'synthetic',MajorFunction=Handlers())
            collection=SimpleNamespace(get_module_symbols_by_absolute_location=lambda target:[])
            harness=SimpleNamespace(context=context,config={'kernel':'kernel'})
            with patch.object(symbols,'symbol_table_is_64bit',lambda **kw:width==8),patch.object(ssdt.SSDT,'build_module_collection',lambda **kw:collection),patch.object(driverscan.DriverScan,'scan_drivers',lambda *args:[driver]):
                boundary=modules.Modules.get_kernel_space_start(context,'kernel')
                result=[dict(irp=row[1][2],target=int(row[1][3])) for row in driverirp.DriverIrp._generator(harness)]
            cases.append(dict(id=f'{width}-{case_id}',width=width,start=start,raw_values=raw_values,expected_start=boundary,expected=result))
    return dict(reference_commit=PIN,driverirp_sha256=hashlib.sha256((checkout/'volatility3/framework/plugins/windows/driverirp.py').read_bytes()).hexdigest(),modules_sha256=hashlib.sha256((checkout/'volatility3/framework/plugins/windows/modules.py').read_bytes()).hexdigest(),scope='Actual kernel-space start, actual Pointer unmarshalling and actual DriverIrp generator. Synthetic driver/array/module collection isolates scalar gate, pointer domain, endpoint inclusion and continuation after one missing handler; not full pool/name/symbol behavior.',cases=cases)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/driver-targets.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
