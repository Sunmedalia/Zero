#!/usr/bin/env python3
"""Actual pinned crash layers over synthetic full/bitmap dump bytes (VSL 1.0)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

PIN='881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    from volatility3.framework import contexts,exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.crash import WindowsCrashDump32Layer,WindowsCrashDump64Layer
    cases=[]
    for width,layer_type in [(4,WindowsCrashDump32Layer),(8,WindowsCrashDump64Layer)]:
        for label,kind,runs,bits,pages in [
            ('full-disjoint',1,[[1,2],[8,1]],0,[]),
            ('full-adjacent-runs',1,[[1,1],[2,2]],0,[]),
            ('bitmap-first-last',5,[],3,[0,2]),
            ('bitmap-word-boundary',5,[],65,[0,31,32,63,64]),
            ('bitmap-full-word',5,[],64,list(range(32))),
            ('bitmap-zero-word-gap',5,[],96,[0,1,64,65]),
            ('bitmap-full-final-word',5,[],64,list(range(32,64))),
        ]:
            header=4096 if width==4 else 8192
            offset=header if kind==1 else header+4096
            mapped=([pfn for base,count in runs for pfn in range(base,base+count)] if kind==1 else pages)
            data=bytearray(offset+len(mapped)*4096)
            writes=[]
            def write(at,value,size):
                data[at:at+size]=value.to_bytes(size,'little');writes.append([at,value,size])
            data[:8]=b'PAGEDUMP' if width==4 else b'PAGEDU64'
            write(16,0x1000,width);write(32 if width==4 else 48,0x14c if width==4 else 0x8664,4)
            write(3976 if width==4 else 3992,kind,4)
            if kind==1:
                desc=100 if width==4 else 136
                write(desc,len(runs),4)
                write(desc+4 if width==4 else desc+8,len(mapped),width)
                for index,(base,count) in enumerate(runs):
                    at=desc+(8 if width==4 else 16)+index*width*2
                    write(at,base,width);write(at+width,count,width)
            else:
                data[header:header+8]=b'SDMPDUMP'
                write(header+32,offset,8);write(header+40,len(mapped),8);write(header+48,bits,8)
                for page in mapped:data[header+56+page//8]|=1<<(page%8)
            for index,pfn in enumerate(mapped):data[offset+index*4096:offset+(index+1)*4096]=bytes([pfn%251])*4096
            ctx=contexts.Context();ctx.layers.add_layer(BufferDataLayer(ctx,'file','file',buffer=bytes(data)))
            ctx.config['crash.base_layer']='file'
            layer=layer_type(ctx,'crash','crash');ctx.layers.add_layer(layer)
            segments=[[at,at+length,physical] for at,physical,length,_ in layer._segments]
            queries=[]
            for pfn in sorted(set(mapped+[3,7,33])):
                at=pfn*4096
                try:value=layer.read(at,4).hex();error=None
                except exceptions.InvalidAddressException as exc:value=None;error=type(exc).__name__
                queries.append(dict(address=at,length=4,expected_hex=value,error=error))
            # A read that spans a backing mapping boundary must keep all bytes
            # when physically adjacent, and fail when a physical hole intervenes.
            if mapped:
                at=mapped[0]*4096+4094
                try:value=layer.read(at,4).hex();error=None
                except exceptions.InvalidAddressException as exc:value=None;error=type(exc).__name__
                queries.append(dict(address=at,length=4,expected_hex=value,error=error))
            cases.append(dict(id=f'{width}-{label}',width=width,kind=kind,header=header,data_offset=offset,writes=writes,runs=runs,bits=bits,pages=mapped,length=len(data),expected_segments=segments,queries=queries))
    files=['layers/crash.py','layers/segmented.py','symbols/windows/extensions/crash.py','symbols/windows/crash.json','symbols/windows/crash64.json','symbols/windows/crash_common.json']
    return dict(reference_commit=PIN,source_sha256={name:hashlib.sha256((checkout/'volatility3/framework'/name).read_bytes()).hexdigest() for name in files},scope='Actual WindowsCrashDump32Layer/64Layer constructors, actual bundled crash symbols, segment extraction and actual reads from complete synthetic full and bitmap containers. Covers disjoint/adjacent full runs, bitmap ULONG boundaries, fully populated and zero words, gaps, packed file offsets and cross-segment reads. Valid containers only; truncated/malformed headers, unused bitmap tail bits, all dump kinds and failure-contract equivalence remain unverified.',cases=cases)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'))
    parser.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/crash-mappings.json'))
    args=parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()),indent=2)+'\n')
