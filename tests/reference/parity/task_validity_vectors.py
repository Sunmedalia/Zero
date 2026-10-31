#!/usr/bin/env python3
"""Actual pinned task validity/list iterators over synthetic typed byte storage (VSL 1.0)."""
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
    from volatility3.framework import objects, exceptions
    from volatility3.framework.symbols.linux import extensions
    from volatility3.framework.objects import utility
    from volatility3.plugins.linux.pslist import PsList

    definitions={'pid':(16,4),'tgid':(20,4),'real_parent':(24,'task_struct'),
                 'signal':(32,'signal_struct'),'nsproxy':(40,'nsproxy'),
                 'active_mm':(48,'mm_struct'),'mm':(56,'mm_struct')}
    sizes={'task_struct':256,'signal_struct':32,'nsproxy':24,'mm_struct':128,'list_head':16}
    defaults={'pid':1,'tgid':1,'real_parent':0x13000,'signal':0x11000,'nsproxy':0x12000,'active_mm':0x14000,'mm':0x14000}

    class Memory:
        def __init__(self,holes):self.data=bytearray(0x20000);self.holes=holes;self.writes=[];self.maximum_address=len(self.data)-1
        def is_valid(self,at,size=1):return at>=0 and at+size<=len(self.data) and not any(at<end and at+size>start for start,end in self.holes)
        def read(self,at,size):
            if not self.is_valid(at,size):raise exceptions.InvalidAddressException('memory',at)
            return bytes(self.data[at:at+size])
        def put(self,at,data):self.data[at:at+len(data)]=data;self.writes.append([at,data.hex()])
    class Pointer(int):
        def __new__(cls,value,target,context):
            obj=int.__new__(cls,value);obj.target=target;obj.context=context;return obj
        def is_readable(self):return self.context.layers['memory'].is_valid(int(self),sizes[self.target])
        def dereference(self):return Head(self.context,int(self))
    class Head:
        def __init__(self,context,at):self._context=context;self.vol=SimpleNamespace(offset=at,layer_name='memory')
        def __getattr__(self,name):
            if name not in ['next','prev']:raise AttributeError(name)
            value=int.from_bytes(self._context.layers['memory'].read(self.vol.offset+(0 if name=='next' else 8),8),'little')
            return Pointer(value,'list_head',self._context)
        to_list=extensions.list_head.to_list
    class Array(objects.Array):
        def __init__(self,context,at):self._context=context;self._vol=dict(layer_name='memory',offset=at,count=16)
    class Task:
        def __init__(self,context,at,fields,width,signed,task_offset):
            self._context=context;self.fields=fields;self.width=width;self.signed=signed;self.task_offset=task_offset
            self.vol=SimpleNamespace(offset=at,size=256,layer_name='memory',type_name='kernel!task_struct')
        def has_member(self,name):return name in self.fields or name in ['tasks','comm']
        def __getattr__(self,name):
            if name=='tasks':return Head(self._context,self.vol.offset+self.task_offset)
            if name=='comm':return Array(self._context,self.vol.offset+64)
            if name not in self.fields:raise AttributeError(name)
            offset,ty=self.fields[name];size=4 if name in ['pid','tgid'] else self.width
            value=int.from_bytes(self._context.layers['memory'].read(self.vol.offset+offset,size),'little',signed=self.signed if name in ['pid','tgid'] else False)
            return value if name in ['pid','tgid'] else Pointer(value,ty,self._context)
        is_valid=extensions.task_struct.is_valid

    def build(spec,width=8):
        fields={k:v for k,v in definitions.items() if k not in spec.get('omit',[])}
        signed=spec.get('signed',True);offset=spec.get('task_offset',80)
        memory=Memory(spec.get('holes',[]));context=SimpleNamespace(layers={'memory':memory})
        task=lambda at:Task(context,at,fields,width,signed,offset)
        context.object=lambda symbol_type,layer_name,offset:task(offset)
        context.symbol_space=SimpleNamespace(get_type=lambda _:SimpleNamespace(relative_child_offset=lambda _:offset))
        context.modules={'kernel':SimpleNamespace(object_from_symbol=lambda **kw:task(0x9000))}
        entries=spec.get('entries',[dict(address=0xa000)])
        for index,entry in enumerate(entries):
            at=entry['address'];values={**defaults,'pid':index+1,'tgid':index+1,**entry.get('values',{})}
            for name,(field_offset,ty) in fields.items():
                size=4 if name in ['pid','tgid'] else width
                memory.put(at+field_offset,values[name].to_bytes(size,'little',signed=signed if name in ['pid','tgid'] else False))
            name=bytes.fromhex(entry.get('name_hex',b'alpha\0'.hex()))
            memory.put(at+64,name.ljust(16,b'\0')[:16])
        if spec.get('walk'):
            head=0x9000+offset;nodes=[e['address']+offset for e in entries]
            memory.put(head,nodes[0].to_bytes(8,'little'));memory.put(head+8,nodes[-1].to_bytes(8,'little'))
            for index,node in enumerate(nodes):
                memory.put(node,(nodes[index+1] if index+1<len(nodes) else head).to_bytes(8,'little'))
                memory.put(node+8,(nodes[index-1] if index else head).to_bytes(8,'little'))
            for at,value in spec.get('links',[]):memory.put(at,value.to_bytes(8,'little'))
        return context,task,memory

    specs=[dict(id='valid'),dict(id='pid-zero',entries=[dict(address=0xa000,values=dict(pid=0,tgid=0))]),
        dict(id='negative-pid',entries=[dict(address=0xa000,values=dict(pid=-1))]),
        dict(id='negative-tgid',entries=[dict(address=0xa000,values=dict(tgid=-1))]),
        dict(id='unsigned-high-id',signed=False,entries=[dict(address=0xa000,values=dict(pid=0x80000001))]),
        dict(id='task-tail-hole',holes=[[0xa0ff,0xa100]]),dict(id='task-prefix-hole',holes=[[0xa000,0xa001]])]
    for field,address,size in [('signal',0x11000,32),('nsproxy',0x12000,24),('real_parent',0x13000,256)]:
        specs += [dict(id=f'{field}-null',entries=[dict(address=0xa000,values={field:0})]),
                  dict(id=f'{field}-tail-hole',holes=[[address+size-1,address+size]]),dict(id=f'{field}-absent',omit=[field])]
    specs += [dict(id='borrowed-mm',entries=[dict(address=0xa000,values=dict(mm=0))]),
              dict(id='null-mm-and-active',entries=[dict(address=0xa000,values=dict(mm=0,active_mm=0))]),
              dict(id='null-active-nonnull-mm',entries=[dict(address=0xa000,values=dict(active_mm=0))]),
              dict(id='mismatched-mm',entries=[dict(address=0xa000,values=dict(mm=0x15000))]),
              dict(id='active-tail-hole',holes=[[0x1407f,0x14080]]),
              dict(id='mm-tail-hole',entries=[dict(address=0xa000,values=dict(mm=0x15000))],holes=[[0x1507f,0x15080]]),
              dict(id='absent-active-null-mm',omit=['active_mm'],entries=[dict(address=0xa000,values=dict(mm=0))]),
              dict(id='absent-active-nonnull-mm',omit=['active_mm']),dict(id='absent-mm',omit=['mm'])]
    validity=[]
    for width in [4,8]:
        for original in specs:
            spec=dict(original);context,task,memory=build(spec,width)
            record=dict(spec,pointer_width=width,writes=memory.writes)
            try:record['expected']=task(0xa000).is_valid()
            except Exception as error:record['error']=type(error).__name__
            validity.append(record)
    walks=[];offset=80;head=0x9000+offset
    walks_specs=[dict(id='closed'),dict(id='forward-cycle',links=[[0xa000+offset,0xa000+offset]]),
        dict(id='no-forward-link',links=[[head,0]]),dict(id='forward-outside',links=[[head,0x30000]]),
        dict(id='duplicate-pid',entries=[dict(address=0xa000),dict(address=0xa200,values=dict(pid=1))]),
        dict(id='zero-ids',entries=[dict(address=0xa000,values=dict(pid=0,tgid=0)),dict(address=0xa200)]),
        dict(id='negative-id',entries=[dict(address=0xa000,values=dict(pid=-1)),dict(address=0xa200)]),
        dict(id='task-tail-hole',holes=[[0xa0ff,0xa100]]),
        dict(id='link-tail-hole',holes=[[0xa000+offset+15,0xa000+offset+16]]),
        dict(id='head-first-byte-hole',holes=[[head,head+1]]),dict(id='head-link-read-error',holes=[[head+1,head+8]]),
        dict(id='underflow-object',links=[[head,40]],task_offset=80),
        dict(id='selected-second',pids=[2])]
    for name,data in [('nonterminated',b'abcdefghijklmnop'),('empty',b''),('control',b'A\nB\0'),('invalid-utf8',b'ok\xc0bad\0'),('replacement-codepoint',b'ok\xef\xbf\xbdbad\0')]:
        walks_specs.append(dict(id=f'name-{name}',entries=[dict(address=0xa000,name_hex=data.hex()),dict(address=0xa200)]))
    for original in walks_specs:
        spec=dict(walk=True,entries=[dict(address=0xa000),dict(address=0xa200)],**{k:v for k,v in original.items() if k!='entries'})
        if 'entries' in original:spec['entries']=original['entries']
        context,task,memory=build(spec)
        record=dict(spec,pointer_width=8,writes=memory.writes)
        try:
            found=PsList.list_tasks(context,'kernel',filter_func=PsList.create_pid_filter(spec.get('pids')))
            record['expected']=[[t.vol.offset,int(t.pid),int(t.tgid),utility.array_to_string(t.comm)] for t in found]
        except Exception as error:record['error']=type(error).__name__
        walks.append(record)
    return dict(reference_commit=PIN,source_sha256={p:hashlib.sha256((checkout/p).read_bytes()).hexdigest() for p in [
        'volatility3/framework/symbols/linux/extensions/__init__.py','volatility3/framework/plugins/linux/pslist.py','volatility3/framework/objects/utility.py']},
        scope='Actual task_struct.is_valid, list_head.to_list, PsList.list_tasks and array_to_string over typed byte-backed adapters with explicit capture holes. Pointer widths 4/8 test field decoding under supplied layer validity, not Intel32 page-table support. Native fixtures use full x64 page tables and identical field bytes. All layer alias/exception/resource contracts and thread enumeration remain unverified.',validity=validity,walks=walks)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/task-validity.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
