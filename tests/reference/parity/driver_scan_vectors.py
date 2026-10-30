#!/usr/bin/env python3
"""Pinned DriverScan post-carving DriverStart checks (VSL 1.0)."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
PIN='881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    from volatility3.plugins.windows import driverscan,poolscanner
    from volatility3.framework import symbols
    cases=[]
    for width in [4,8]:
        mask=(1<<(32 if width==4 else 48))-1
        threshold=0x80000000 if width==4 else 0xffff800000000000
        for name,raw,available in [('zero',0,8),('below',threshold-1,8),('equal',threshold,8),('above',threshold+1,8),('last-pointer',(1<<(width*8))-1,8),('four-readable',threshold+1,4),('no-bytes',threshold+1,0)]:
            module=SimpleNamespace(symbol_table_name='nt',layer_name='virtual',get_type=lambda _:SimpleNamespace(relative_child_offset=lambda _:16),get_symbol=lambda _:SimpleNamespace(address=0x1000),object=lambda **kw:threshold)
            layer=SimpleNamespace(address_mask=mask,is_valid=lambda at,length:at==0x2010 and length<=available)
            context=SimpleNamespace(modules={'kernel':module},layers={'virtual':layer,'scanned':layer})
            obj=SimpleNamespace(vol=SimpleNamespace(offset=0x2000,layer_name='scanned'),DriverStart=raw&mask)
            constraints=[]
            def scan(*args):constraints.extend(args[-1]);yield None,obj,None
            with patch.object(symbols,'symbol_table_is_64bit',lambda **kw:width==8),patch.object(poolscanner.PoolScanner,'generate_pool_scan',scan):
                found=[int(driver.vol.offset) for driver in driverscan.DriverScan.scan_drivers(context,'kernel')]
            cases.append(dict(id=f'{width}-{name}',width=width,raw=raw,available_bytes=available,threshold=threshold&mask,expected=bool(found),tags=[c.tag.hex() for c in constraints]))
    return dict(reference_commit=PIN,source_sha256=hashlib.sha256((checkout/'volatility3/framework/plugins/windows/driverscan.py').read_bytes()).hexdigest(),scope='Actual DriverScan.scan_drivers, builtin driver constraints and kernel-space-start helper. Synthetic carved objects/scanned-layer validity isolate eight-byte accessibility, pointer mask and strict DriverStart comparison. Does not prove full candidate recovery or name parsing.',cases=cases)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/driver-scan.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
