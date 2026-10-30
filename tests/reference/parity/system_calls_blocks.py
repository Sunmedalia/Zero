#!/usr/bin/env python3
"""Generate synthetic syscall validator vectors with the unmodified pinned reference.
Reference wrappers: Volatility Foundation, VSL 1.0. No recovered sample content.
Run with the reference venv; output is reviewed and consumed by Rust regression tests.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'

def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip() == PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    import capstone
    from volatility3.framework import exceptions
    from volatility3.plugins.windows.malware.direct_system_calls import DirectSystemCalls, syscall_finder_type
    from volatility3.plugins.windows.malware.indirect_system_calls import IndirectSystemCalls
    assert capstone.__version__ == '5.0.6'
    from volatility3.framework import renderers
    assert renderers.UnreadableValue() != renderers.UnreadableValue() # pinned active filter identity comparison
    class Layer:
        def __init__(self,segments): self.segments=segments
        def read(self,at,size):
            for start,data in self.segments:
                if start<=at and at+size<=start+len(data): return data[at-start:at-start+size]
            raise exceptions.InvalidAddressException('synthetic',at)
    vectors=[]
    direct=bytes.fromhex('4c8bd1 b83f000000 0f05 c3')
    indirect=bytes.fromhex('4c8bd1 b83f000000 ff25 20000000 c3')
    specs=[
        ('direct-standard',False,direct,'intel64'),
        ('direct-register-arithmetic',False,bytes.fromhex('4987ca 31c0 0f05 c3'),'intel64'),
        ('direct-zero-opcode',False,bytes.fromhex('4c8bd1 b83f000000 0000 0f05 c3'),'intel64'),
        ('direct-call',False,bytes.fromhex('4c8bd1 b83f000000 e800000000 0f05 c3'),'intel64'),
        ('direct-early-syscall',False,bytes.fromhex('0f05 4c8bd1 b83f000000 c3'),'intel64'),
        ('direct-x86-mode',False,direct,'intel'),
        ('indirect-standard',True,indirect,'intel64'),
        ('indirect-unsigned-displacement',True,indirect[:10]+bytes.fromhex('ffffffff')+indirect[14:],'intel64'),
        ('indirect-zero-displacement',True,indirect[:10]+bytes(4)+indirect[14:],'intel64'),
        ('indirect-wrong-target',True,indirect,'intel64'),
        ('indirect-wrong-path',True,indirect,'intel64'),
        ('indirect-syscall',True,direct,'intel64'),
        ('indirect-x86-mode',True,indirect,'intel'),
        ('direct-missing-context',False,direct,'intel64'),
    ]
    for name,is_indirect,code,architecture in specs:
        data=bytearray(0x200);data[0x40:0x40+len(code)]=code
        hit=0x1040+(code.find(b'\xff\x25') if is_indirect and b'\xff\x25' in code else code.find(b'\x0f\x05'))
        segments=[(0x1000,bytes(data))]
        paths=[(0x1000,0x200,None),(0x2000,0x1000,'C:\\Windows\\ntdll.dll')]
        if is_indirect and b'\xff\x25' in code:
            end=0x1040+code.find(b'\xff\x25');d=int.from_bytes(code[10:14],'little')
            pointer=end+d+6
            if 0x1000<=pointer<0x11f8:
                data[pointer-0x1000:pointer-0x1000+8]=(0x2000).to_bytes(8,'little');segments[0]=(0x1000,bytes(data))
            else:segments.append((pointer,(0x2000).to_bytes(8,'little')))
            segments.append((0x2000,b'\x0f\x04' if name=='indirect-wrong-target' else b'\x0f\x05'))
        if name=='indirect-wrong-path':paths[1]=(0x2000,0x1000,'C:\\other.dll')
        if name=='direct-missing-context':segments=[(0x1040,code)]
        finder=syscall_finder_type(IndirectSystemCalls._indirect_syscall_block_target if is_indirect else None,not is_indirect,'', ['call','leave','int3','ret'] if is_indirect else ['jmp','call','leave','int3'],['jmp'] if is_indirect else ['ret'])
        found=DirectSystemCalls._is_valid_syscall(finder,Layer(segments),architecture,paths,hit)
        vectors.append({'id':name,'indirect':is_indirect,'x86':architecture=='intel','hit':hit,'segments':[{'address':a,'hex':b.hex()} for a,b in segments],'vads':[{'start':a,'size':n,'path':p or ''} for a,n,p in paths],'expected':{'address':found[0],'disasm':found[1]} if found else None})
    return {'reference_commit':PIN,'capstone_version':capstone.__version__,'scope':'Synthetic validator vectors only; no whole-plugin or real-image claim','cases':vectors}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/system-calls.json'));a=p.parse_args()
    a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
