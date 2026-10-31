#!/usr/bin/env python3
"""Actual pinned Windows Intel mapping over complete synthetic page tables (VSL 1.0)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
    sys.path.insert(0, str(checkout))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import WindowsIntel, WindowsIntelPAE, WindowsIntel32e
    cases = []
    for arch, layer_type, width, maxva in [('x86', WindowsIntel, 4, (1<<32)-1), ('pae', WindowsIntelPAE, 8, (1<<32)-1), ('x64', WindowsIntel32e, 8, (1<<48)-1)]:
        variants = ['basic', 'backing-hole', 'short-backing-tail', 'missing-leaf-table', 'one-readable-entry', 'uniform-leaf-table', 'transition', 'prototype-transition', 'final-page', 'large-page', 'large-pat', 'large-with-backing-hole', 'large-reserved-bit13', 'large-reserved-bit20', 'large-transition']
        if arch in ['pae','x64']:
            variants += ['root-pse-bit']
        if arch == 'x64':
            variants += ['present-high-bit45', 'transition-high-bit45', 'present-high-bit51', 'table-high-bit45']
        if arch == 'pae':
            variants += ['short-root-page', 'high-physical-bits', 'four-identical-root-entries']
        for label in variants:
            length = 0x800000 if label.startswith('large') else 0x20000
            data=bytearray(length)
            writes=[]
            def put(at, value):
                data[at:at+width]=value.to_bytes(width,'little')
                writes.append([at,value])
            root=0x1000
            if arch == 'x64':
                put(root,0x2003);put(0x2000,0x3003);put(0x3000,0x4003);leaf=0x4000
            elif arch == 'pae':
                put(root,0x2003);put(0x2000,0x3003);leaf=0x3000
            else:
                put(root,0x2003);leaf=0x2000
            put(leaf,0x8003);put(leaf+width,0x9003);put(leaf+2*width,0x10003)
            holes=[]
            if label=='backing-hole':holes=[[0x9000,0xa000]]
            elif label=='short-backing-tail':holes=[[0x10fff,0x11000]]
            elif label=='missing-leaf-table':holes=[[leaf,leaf+4096]]
            elif label=='one-readable-entry':holes=[[leaf+width,leaf+4096]]
            elif label=='uniform-leaf-table':
                for at in range(leaf,leaf+4096,width):put(at,0x8003)
            elif label=='transition':put(leaf,0x8800)
            elif label=='prototype-transition':put(leaf,0x8c00)
            elif label=='root-pse-bit':put(root,0x2083)
            elif label=='present-high-bit45':put(leaf,(1<<45)|0x8003)
            elif label=='transition-high-bit45':put(leaf,(1<<45)|0x8800)
            elif label=='present-high-bit51':put(leaf,(1<<51)|0x8003)
            elif label=='table-high-bit45':put(root,(1<<45)|0x2003)
            elif label=='high-physical-bits':put(leaf,(1<<44)|0x8003)
            elif label=='four-identical-root-entries':
                for at in range(root,root+32,8):put(at,0x2003)
            elif label=='short-root-page':holes=[[root+32,root+4096]]
            elif label=='final-page':
                data[0x1000:0x5000]=b'\0'*0x4000;writes=[]
                if arch=='x64':put(root+511*8,0x2003);put(0x2000+511*8,0x3003);put(0x3000+511*8,0x4003);put(0x4000+511*8,0x8003)
                elif arch=='pae':put(root+3*8,0x2003);put(0x2000+511*8,0x3003);put(0x3000+511*8,0x8003)
                else:put(root+1023*4,0x2003);put(0x2000+1023*4,0x8003)
            elif label.startswith('large'):
                directory=0x3000 if arch=='x64' else 0x2000 if arch=='pae' else root
                put(directory,0x400083 | (0x1000 if label=='large-pat' else 0))
                if label=='large-transition':put(directory,0x400880)
                if label=='large-reserved-bit13':put(directory,0x402083)
                if label=='large-reserved-bit20':put(directory,0x500083)
                if label=='large-with-backing-hole':holes=[[0x401000,0x402000]]
            patterned = label.startswith('large')
            if patterned:
                for page in range(0x400000,len(data),4096):data[page:page+4096]=bytes([(page//4096)%251])*4096
            class Capture(BufferDataLayer):
                def is_valid(self, offset, size=1):
                    return super().is_valid(offset,size) and not any(offset < end and offset+size > start for start,end in holes)
            ctx=contexts.Context();ctx.layers.add_layer(Capture(ctx,'physical','physical',buffer=bytes(data)))
            ctx.config['kernel.memory_layer']='physical';ctx.config['kernel.page_map_offset']=root
            layer=layer_type(ctx,'kernel','kernel');ctx.layers.add_layer(layer)
            mapped=list(layer.mapping(0,maxva,ignore_errors=True))
            queries=[]
            addresses=[0,0x123,0x1000,0x2000]
            if label=='final-page':addresses += [maxva-4095,maxva]
            requests=[(at,1) for at in addresses]
            if patterned:requests += [(0x1ff8,32)]
            for at,read_length in requests:
                try:physical,_,_=layer._translate(at);translate_error=None
                except exceptions.InvalidAddressException as exc:physical=None;translate_error=type(exc).__name__
                try:read_hex=layer.read(at,read_length).hex();read_error=None
                except exceptions.InvalidAddressException as exc:read_hex=None;read_error=type(exc).__name__
                queries.append(dict(address=at,length=read_length,physical=physical,translate_error=translate_error,read_hex=read_hex,read_error=read_error))
            cases.append(dict(id=f'{arch}-{label}',arch=arch,width=width,length=length,root=root,writes=writes,holes=holes,patterned=patterned,queries=queries,expected=[[at,size,physical] for at,size,physical,_,_ in mapped]))
    source=checkout/'volatility3/framework/layers/intel.py'
    return dict(reference_commit=PIN,source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),scope='Actual WindowsIntel/WindowsIntelPAE/WindowsIntel32e mapping and translation over full synthetic page-table bytes, plus direct translation, one-byte reads and patterned 32-byte reads across 4 KiB boundaries. Physical BufferDataLayer subclass models explicit backing holes. Full default virtual range length excludes maximum_address. Covers contiguous/discontiguous PFNs, missing tables and backing tails, uniform tables, transition/prototype flags, uppermost page, large pages/PAT, reserved PFN bits, transition large pages and PAE root/physical-bit limits and Windows x64 45-bit PFN/software-flag behavior. Does not certify container mapping/decompression, all malformed reserved PFNs, all architectures or complete scan fault reporting.',cases=cases)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'))
    parser.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/pool-mappings.json'))
    args=parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()),indent=2)+'\n')
