#!/usr/bin/env python3
"""Pinned Envars buffer handling/generator through typed adapters (VSL 1.0)."""
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
    from volatility3.framework import objects
    from volatility3.framework.symbols.linux import extensions
    from volatility3.plugins.linux.envars import Envars
    from volatility3.plugins.linux.pslist import PsList

    class Node(SimpleNamespace): pass
    class Task(Node):
        is_kernel_thread=extensions.task_struct.is_kernel_thread
        def get_parent_pid(self): return extensions.task_struct.get_parent_pid(self)
    class Array(objects.Array):
        def __init__(self,context):
            self._context=context;self._vol=dict(count=8,offset=0,layer_name='memory')

    specs=[
        ('pairs',b'A=1\0B=2\0',{}),('trailing-nuls',b'A=1\0\0\0',{}),
        ('no-trailing-nul',b'A=1',{}),('bad-middle',b'A=1\0bad\0B=2\0',{}),
        ('bad-first',b'bad\0B=2\0',{}),('empty-middle',b'A=1\0\0B=2\0',{}),
        ('empty-key',b'=value\0',{}),('empty-value',b'KEY=\0',{}),
        ('multiple-equals',b'KEY=a=b=c\0',{}),('duplicates',b'A=1\0A=2\0A=1\0',{}),
        ('controls',b'K\n=a\tb\r\0',{}),('empty',b'',{}),('only-nuls',b'\0\0\0',{}),
        ('limit-inclusive',b'K='+b'x'*8190,{}),('limit-exceeded',b'K='+b'x'*8191,{}),
        ('inverted-range',b'A=1\0',{'length':-1}),
        ('unreadable-tail',b'X=1\0',{'readable':False}),
        ('no-process-layer',b'A=1\0',{'layer':False}),
        ('kernel-thread',b'A=1\0',{'flags':0x200000}),
        ('other-flags',b'A=1\0',{'flags':2}),
        ('unreadable-parent',b'A=1\0',{'parent_readable':False}),
    ]
    for index,value in enumerate([b'\x80',b'\xc0\xaf',b'\xc2',b'\xe0\x80\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xf0\x9f\x92']):
        specs.append((f'utf8-{index}',b'K'+value+b'=V'+value+b'\0',{}))
    cases=[]
    for name,payload,options in specs:
        start=0x200ffe;length=options.get('length',len(payload))
        context=Node(layers={'memory':Node(maximum_address=100,read=lambda at,n:b'task\0\0\0\0'[at:at+n]),
            'process':Node(is_valid=lambda at,n:options.get('readable',True),read=lambda at,n:payload[:n])})
        task=Task(pid=1,tgid=101,comm=Array(context),flags=options.get('flags',0),
            mm=Node(env_start=start,env_end=start+length),
            add_process_layer=lambda:'process' if options.get('layer',True) else None,
            real_parent=Node(tgid=77,pid=7,is_readable=lambda:options.get('parent_readable',True)))
        harness=Node(context=context,get_task_env_variables=Envars.get_task_env_variables)
        rows=[list(map(str,row)) for _,row in Envars._generator(harness,[task])]
        excluded=[t for t in [task] if not PsList.create_pid_filter([101])(t)]
        assert not list(Envars._generator(harness,excluded))
        cases.append(dict(id=name,payload_hex=payload.hex(),start=start,**options,expected=rows))
    return dict(reference_commit=PIN,source_sha256={p:hashlib.sha256((checkout/p).read_bytes()).hexdigest() for p in [
        'volatility3/framework/plugins/linux/envars.py','volatility3/framework/plugins/linux/pslist.py',
        'volatility3/framework/symbols/linux/extensions/__init__.py','volatility3/framework/objects/utility.py']},
        scope='Actual Envars._generator/get_task_env_variables, kernel-thread/parent methods, UTF8 parsing and PID filter. Typed field/process-layer adapters supply bounds, readability and process-layer availability; this does not certify complete layer construction, all corrupt layouts, traversal or full failure/resource contracts.',cases=cases)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/envars.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
