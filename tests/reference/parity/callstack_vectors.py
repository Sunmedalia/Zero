#!/usr/bin/env python3
"""Pinned kallsyms global/ELF module gates and first-module routing (VSL 1.0)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
PIN='881e970121c16f0932fb9d16fbd5fb258cbcbf75'
MASK=(1<<48)-1


def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    from volatility3.framework.symbols.linux.kallsyms import Kallsyms
    from volatility3.plugins.linux.pscallstack import PsCallStack
    from volatility3.framework import exceptions
    from volatility3.framework.symbols.linux import extensions
    globals=[]
    for name,tree,minimum,maximum in [('symbol-locations',False,0xffffffff8161dae8,0xffffffff817adf48),('tree-values',True,0xffffffffa0000000,0xffffffffa0010000),('inverted',False,0x2000,0x1000)]:
        class Harness: pass
        harness=Harness()
        harness._kas_config=SimpleNamespace(mod_tree=0x3000 if tree else None,module_addr_min=minimum,module_addr_max=maximum)
        module=SimpleNamespace(object=lambda **kw:SimpleNamespace(addr_min=minimum,addr_max=maximum))
        harness._context=SimpleNamespace(layers={'virtual':SimpleNamespace(address_mask=MASK)},modules={'kernel':module})
        harness._module_name='kernel';harness._layer_name='virtual'
        bounds=Kallsyms._get_modules_memory_boundaries(harness)
        globals.append(dict(id=name,tree=tree,minimum=minimum,maximum=maximum,expected_bounds=bounds))
    modules=[]
    for name,entries in [
        ('last-zero',[(0,0),(0x1000,16),(0x2000,0)]),
        ('last-sized',[(0,0),(0x1000,16),(0x2000,32)]),
        ('unsorted',[(0x2000,0),(0,0),(0x1000,16)]),
        ('one-symbol',[(0,0),(0x1000,0)]),
        ('alias-last-sized',[(0,0),(0x1000,16),(0x2000,0),(0x2000,32)]),
        ('alias-last-zero',[(0,0),(0x1000,16),(0x2000,32),(0x2000,0)]),
        ('wide-size',[(0,0),(0x1000,16),(0x100000001234,0xffffffffffffffff)]),
    ]:
        symbols=[SimpleNamespace(st_value=value,st_size=size) for value,size in entries]
        context=SimpleNamespace(symbol_space=SimpleNamespace(get_type=lambda _:SimpleNamespace(size=8)),layers={'virtual':SimpleNamespace(address_mask=MASK)},object=lambda *args,**kw:symbols)
        class ModuleHarness: pass
        harness=ModuleHarness()
        harness.section_strtab=1;harness.num_symtab=len(entries);harness.section_symtab=1;harness._context=context;harness.vol=SimpleNamespace(layer_name='virtual');harness.get_elf_table_name=lambda:'elf';harness.get_symbol_table_name=lambda:'kernel'
        bounds=extensions.module.get_module_address_boundaries(harness)
        modules.append(dict(id=name,entries=entries,expected_bounds=bounds))
    routing=[]
    for name,query,regions in [
        ('first-module-hole',0x1008,[('first',0x1000,0x2000,[(0x1000,4,'short')]),('second',0x1000,0x2000,[(0x1000,16,'long')])]),
        ('first-module-symbol',0x1002,[('first',0x1000,0x2000,[(0x1000,4,'short')]),('second',0x1000,0x2000,[(0x1000,16,'long')])]),
        ('global-inclusive-end',0x4000,[('first',0x3000,0x5000,[(0x4000,4,'at-end')])]),
        ('global-after-end',0x4001,[('first',0x3000,0x5000,[(0x4000,4,'at-end')])]),
        ('second-outside-first',0x2002,[('first',0x1000,0x2000,[(0x1000,4,'short')]),('second',0x1800,0x3000,[(0x2000,16,'second-symbol')])]),
    ]:
        class Module:
            def __init__(self,name,low,high,entries):self.name=name;self.low=low;self.high=high;self.entries=entries
            def get_module_address_boundaries(self):return self.low,self.high
            def get_symbols(self):
                for value,size,name in self.entries:
                    yield SimpleNamespace(st_value=value,st_size=size,get_name=lambda value=name:value)
        entries=[Module(*r) for r in regions]
        class Harness:
            def _is_module_ksym_address(self,address):return 0x1000<=address<=0x4000
            def _get_module_by_address(self,address):return None
            def _find_address_in_module_symbols(self,module,address):return Kallsyms._find_address_in_module_symbols(self,module,address)
            def _elfsym_to_kassymbol(self,module,symbol,index,subsystem=None):return symbol.get_name()
        harness=Harness();harness._MODULE_SUBSYSTEM_NAME='module';harness._context=SimpleNamespace(layers={'virtual':SimpleNamespace(address_mask=MASK)});harness._layer_name='virtual';harness._module_memory_region=[(m,m.low,m.high) for m in entries]
        expected=Kallsyms.module_lookup_address(harness,query)
        routing.append(dict(id=name,query=query,regions=regions,expected=expected))
    stack=[]
    for name,width,start,values,faults in [
        ('aligned-zero',8,0,[0,0x1234],[]),
        ('unaligned-last-word',8,1,[0x1111,0x2222],[]),
        ('unaligned-four-byte',4,1,[0,0x1234,0x2345,0x3456],[]),
        ('missing-second-word',8,0,[0x1111,0x2222],[0x1008]),
        ('missing-first-word',8,0,[0x1111,0x2222],[0x1000]),
        ('sp-at-top',8,16,[],[]),
        ('sp-bad-high-bits',8,0x1234000000000000,[],[]),
    ]:
        data=bytearray(64)
        for index,value in enumerate(values):data[start+index*width:start+(index+1)*width]=value.to_bytes(width,'little')
        def read(at,size):
            if at in faults:raise exceptions.InvalidAddressException('task',at)
            return bytes(data[at-0x1000:at-0x1000+size])
        layer=SimpleNamespace(page_size=4,address_mask=MASK,canonicalize=lambda x:x)
        context=SimpleNamespace(modules={'kernel':SimpleNamespace(layer_name='virtual',get_type=lambda _:SimpleNamespace(size=width))},layers={'virtual':layer})
        task=SimpleNamespace(get_address_space_layer=lambda:SimpleNamespace(read=read),stack=0x1000,thread=SimpleNamespace(sp=0x1000+start),files=SimpleNamespace(vol=SimpleNamespace(data_format=SimpleNamespace(byteorder='little'))),pid=1)
        try:
            entries=[dict(position=e.position,address=e.address,value=e.value) for e in PsCallStack.get_task_callstack(context,'kernel',task,kas=SimpleNamespace(lookup_address=lambda _:None),include_unresolved=True)]
            error=False
        except exceptions.VolatilityException:
            entries=[];error=True
        stack.append(dict(id=name,width=width,base=0x1000,sp=0x1000+start,size=16,data_hex=data.hex(),faults=faults,expected=entries,expected_error=error))
    return dict(reference_commit=PIN,source_sha256=hashlib.sha256((checkout/'volatility3/framework/symbols/linux/kallsyms.py').read_bytes()).hexdigest(),module_source_sha256=hashlib.sha256((checkout/'volatility3/framework/symbols/linux/extensions/__init__.py').read_bytes()).hexdigest(),stack_source_sha256=hashlib.sha256((checkout/'volatility3/framework/plugins/linux/pscallstack.py').read_bytes()).hexdigest(),scope='Actual global module boundaries, module ELF boundary expression, first-module lookup and get_task_callstack loop with synthetic fields/tables/layers. No recovered names or stack words. Does not validate modern latch-tree routing, task address-space creation or the complete field-fault matrix.',global_bounds=globals,module_bounds=modules,routing=routing,stack=stack)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/callstack-module-gates.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
