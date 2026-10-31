#!/usr/bin/env python3
"""Pinned PsAux argument extraction/generator through field/layer adapters (VSL 1.0)."""
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
    from volatility3.framework import objects, exceptions, renderers
    from volatility3.framework.symbols.linux import extensions
    from volatility3.plugins.linux.psaux import PsAux
    from volatility3.plugins.linux.pslist import PsList

    class Node(SimpleNamespace): pass
    class Array(objects.Array):
        def __init__(self,context): self._context=context;self._vol=dict(count=8,offset=0,layer_name='memory')
    class Task(Node):
        def get_parent_pid(self): return extensions.task_struct.get_parent_pid(self)
        @property
        def mm(self):
            if self.unreadable_mm: raise exceptions.InvalidAddressException('memory',0xa030)
            return self.memory

    specs=[('argv',b'cmd\0one\0two\0',{}),('no-final-nul',b'cmd\0one',{}),
        ('multiple-trailing-nuls',b'cmd\0\0\0',{}),('leading-nul',b'\0cmd\0',{}),
        ('sole-nul',b'\0',{}),('two-nuls',b'\0\0',{}),('three-nuls',b'\0\0\0',{}),
        ('one-space',b' ',{}),('two-spaces',b'  ',{}),('original-final-space',b'cmd ',{}),
        ('original-two-spaces',b'cmd  ',{}),('empty',b'',{}),
        ('limit-inclusive',b'x'*4096,{}),('limit-exceeded',b'x'*4097,{}),
        ('inverted',b'cmd\0',{'length':-1}),('read-error',b'cmd\0',{'readable':False}),
        ('no-process-layer',b'cmd\0',{'layer':False}),('null-mm',b'cmd\0',{'null_mm':True}),
        ('unreadable-mm',b'cmd\0',{'unreadable_mm':True}),
        ('kthread-flag-mm-present',b'cmd\0',{'flags':0x200000}),
        ('unreadable-parent',b'cmd\0',{'parent_readable':False}),('control',b'cmd\tA\n\0',{})]
    for index,value in enumerate([b'\x80',b'\xc0\xaf',b'\xc2',b'\xe0\x80\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xf0\x9f\x92']):
        specs.append((f'utf8-{index}',b'cmd\0'+value+b'\0',{}))
    cases=[]
    for name,payload,options in specs:
        start=0x200ffe;length=options.get('length',len(payload))
        def read(at,n):
            if not options.get('readable',True):raise exceptions.InvalidAddressException('process',at)
            return payload[:n]
        context=Node(layers={'memory':Node(maximum_address=100,read=lambda at,n:b'task\0\0\0\0'[at:at+n]),'process':Node(read=read)})
        task=Task(pid=1,tgid=101,comm=Array(context),flags=options.get('flags',0),unreadable_mm=options.get('unreadable_mm',False),
            memory=None if options.get('null_mm') else Node(arg_start=start,arg_end=start+length),
            add_process_layer=lambda:'process' if options.get('layer',True) else None,
            real_parent=Node(tgid=77,pid=7,is_readable=lambda:options.get('parent_readable',True)))
        harness=Node(context=context)
        harness._get_command_line_args=lambda task,name:PsAux._get_command_line_args(harness,task,name)
        rows=[['N/A' if isinstance(v,renderers.UnreadableValue) else str(v) for v in row] for _,row in PsAux._generator(harness,[task])]
        excluded=[t for t in [task] if not PsList.create_pid_filter([101])(t)]
        assert not list(PsAux._generator(harness,excluded))
        cases.append(dict(id=name,payload_hex=payload.hex(),start=start,**options,expected=rows))
    return dict(reference_commit=PIN,source_sha256={p:hashlib.sha256((checkout/p).read_bytes()).hexdigest() for p in [
        'volatility3/framework/plugins/linux/psaux.py','volatility3/framework/plugins/linux/pslist.py',
        'volatility3/framework/symbols/linux/extensions/__init__.py','volatility3/framework/objects/utility.py']},
        scope='Actual PsAux._generator/_get_command_line_args, task parent method, UTF8 replacement and PID filter. Field/process-layer adapters supply mm faults, bounds, layer availability and read faults. Does not certify full list_tasks validity, real layer construction, all ISF/page corruption or complete fault/resource contracts.',cases=cases)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/psaux.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
