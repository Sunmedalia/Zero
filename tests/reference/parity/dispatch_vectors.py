#!/usr/bin/env python3
"""Pinned SSDT SizedModule collection used by DriverIrp (VSL 1.0)."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
PIN='881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    from volatility3.framework import contexts
    from volatility3.plugins.windows import ssdt,modules
    cases=[]
    for name,entries,queries in [
        ('external-rva-aliases',[('nt.exe',0x1000,32),('driver.sys',0x2000,32)],[0x1010,0x2010,0x2020,0x2021]),
        ('overlap-inclusive',[('nt.exe',0x1000,32),('driver.sys',0x1010,32)],[0x1020,0x1030,0x1031]),
        ('zero-size',[('empty.sys',0x2000,0)],[0x2000,0x2001]),
        ('numeric-names',[('srv2.sys',0x1000,32),('srv.sys',0x2000,32),('srv.sys',0x3000,32)],[0x1010,0x2010,0x3010]),
    ]:
        context=contexts.Context()
        aliases={0:['Zero'],16:['AliasA','AliasB'],32:['End']}
        context._symbol_space=SimpleNamespace(get_symbols_by_location=lambda offset,size,table_name:(table_name+'!'+name for name in aliases.get(offset,[])))
        kernel=contexts.SizedModule.create(context,'kernel','virtual',0x1000,size=32,symbol_table_name='nt')
        def driver(name,base,size):return SimpleNamespace(BaseDllName=SimpleNamespace(get_string=lambda:name),DllBase=base,SizeOfImage=size)
        with patch.object(modules.Modules,'list_modules',lambda *args:[driver(*entry) for entry in entries]):
            collection=ssdt.SSDT.build_module_collection(context,'kernel')
        expected=[]
        for query in queries:
            rows=[]
            for module,names in collection.get_module_symbols_by_absolute_location(query):
                names=list(names)
                rows.extend([[module,symbol.split('!')[1]] for symbol in names] or [[module,'']])
            expected.append(dict(query=query,rows=rows or [['','']]))
        cases.append(dict(id=name,modules=entries,expected=expected))
    return dict(reference_commit=PIN,ssdt_sha256=hashlib.sha256((checkout/'volatility3/framework/plugins/windows/ssdt.py').read_bytes()).hexdigest(),contexts_sha256=hashlib.sha256((checkout/'volatility3/framework/contexts/__init__.py').read_bytes()).hexdigest(),scope='Actual SSDT build_module_collection and SizedModule/ModuleCollection queries. Synthetic loaded-module fields and a synthetic exact symbol-space query isolate shared table binding, aliases, names and endpoint behavior; no real driver names or PDB acquisition.',cases=cases)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/dispatch-collection.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
