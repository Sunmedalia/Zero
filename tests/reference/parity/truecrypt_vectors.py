#!/usr/bin/env python3
"""Synthetic TrueCrypt section/parser vectors executed by the pinned reference.
Reference wrappers are VSL 1.0; all password strings below are invented test data.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
PIN='881e970121c16f0932fb9d16fbd5fb258cbcbf75'
def build(case):
    data=bytearray([0xcc])*0x3000
    def patch(at,value):data[at:at+len(value)]=value
    patch(0,b'MZ');patch(60,(0x80).to_bytes(4,'little'));patch(0x80,b'PE\0\0');patch(0x84,(0x8664 if case['wide'] else 0x14c).to_bytes(2,'little'));patch(0x86,(1).to_bytes(2,'little'))
    optional=240 if case['wide'] else 224;patch(0x94,optional.to_bytes(2,'little'));patch(0x98,(0x20b if case['wide'] else 0x10b).to_bytes(2,'little'))
    table=0x98+optional;patch(table,case.get('section_name','.data').encode().ljust(8,b'\0'));patch(table+8,case['section_size'].to_bytes(4,'little'));patch(table+12,case.get('section_start',0x1000).to_bytes(4,'little'))
    for at,value in case['patches']:patch(at,bytes.fromhex(value))
    return bytes(data)
def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    from volatility3.framework import contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.plugins.windows.truecrypt import Passphrase
    cases=[]
    def case(name,wide=True,minimum=5,size=0x100,patches=(),**extra):
        c={'id':name,'wide':wide,'min_length':minimum,'section_size':size,'patches':list(patches),**extra};cases.append(c);return c
    def record(at,password,terminator=0,padding=b'\0\0\0',length=None):
        return (at,((len(password) if length is None else length).to_bytes(4,'little',signed=True)+password+bytes([terminator])+padding).hex())
    good=record(0x1000,b'Test passphrase!')
    case('x64-default',patches=[good,record(0x1040,b'abcd'),record(0x1080,b'X'*64)])
    case('x86-default',wide=False,patches=[good])
    case('minimum-four',minimum=4,patches=[record(0x1000,b'abcd')])
    case('minimum-over-maximum',minimum=65,patches=[good])
    case('zero-length',minimum=0,size=4,patches=[record(0x1000,b'')])
    case('negative-minimum-positive-length',minimum=-1,patches=[good])
    case('negative-length-reference-error',minimum=-1,patches=[record(0x1000,b'',length=-1)])
    case('non-nul-terminator-still-matches',patches=[record(0x1000,b'Example',terminator=0x7f)])
    case('nonzero-padding-rejected',patches=[record(0x1000,b'Example',padding=b'\0\x01\0')])
    case('non-ascii-rejected',patches=[record(0x1000,b'bad\x7fword'),record(0x1040,b'bad\x1fword')])
    case('maximum-length-rejected',patches=[record(0x1000,b'X'*65)])
    case('unaligned-record-rejected',patches=[record(0x1001,b'Example')])
    case('record-extends-past-data',size=4,patches=[good])
    case('data-virtual-size-unaligned',size=7,patches=[good])
    case('section-base-unaligned',section_start=0x1001,patches=[record(0x1001,b'Example')])
    case('case-sensitive-section-name',section_name='.DATA',patches=[good])
    for c in cases:
        ctx=contexts.Context();layer=BufferDataLayer(ctx,'test','synthetic',buffer=build(c));ctx.layers.add_layer(layer)
        harness=SimpleNamespace(context=ctx,config_path='truecrypt_test',config={'min-length':c['min_length']})
        try:c['expected']=[{'offset':offset,'password':password} for offset,password in Passphrase.scan_module(harness,0,'synthetic')]
        except Exception as error:c['error_type']=type(error).__name__;c['error']=str(error)
    return {'reference_commit':PIN,'reference_source_sha256':hashlib.sha256((checkout/'volatility3/framework/plugins/windows/truecrypt.py').read_bytes()).hexdigest(),'scope':'Synthetic section/parser semantics only; invented passwords; no real positive image evidence','fill_byte':204,'image_size':0x3000,'cases':cases}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/truecrypt.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
