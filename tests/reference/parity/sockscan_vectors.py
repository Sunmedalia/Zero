#!/usr/bin/env python3
"""Fixed Sockscan source precedence, byte scanning and original-layer IPv6 reads (VSL 1.0)."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch
PIN='881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain','--untracked-files=no'],text=True).strip()
    sys.path.insert(0,str(checkout))
    from volatility3.plugins.linux.sockscan import Sockscan
    from volatility3.plugins.linux import sockstat
    from volatility3.framework.layers.scanners import MultiStringScanner
    from volatility3.framework import contexts,objects
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.symbols.linux.extensions.network import inet_sock
    import socket
    patterns={'file':b'F'*8,'destructor':b'D'*8,'both':b'B'*8}
    cases=[]
    for name,events,filtered in [
        ('independent',[(0x19050,'destructor',None),(0x1b028,'file',0x19100)],[]),
        ('same-target',[(0x19050,'destructor',None),(0x1b028,'file',0x19000),(0x1b128,'file',0x19000)],[]),
        ('two-file-targets',[(0x1b028,'file',0x19100),(0x1b128,'file',0x19200)],[]),
        ('first-file-filtered',[(0x1b028,'file',0x19100),(0x1b128,'file',0x19200)],[0x19100]),
        ('first-file-unresolved',[(0x1b028,'file',None),(0x1b128,'file',0x19200)],[]),
        ('shared-pattern',[(0x19050,'both',0x19100),(0x1b028,'file',0x19100)],[]),
    ]:
        targets={at:target for at,_,target in events}
        layer=SimpleNamespace(scan=lambda *args:((at,patterns[kind]) for at,kind,_ in events))
        module=SimpleNamespace(symbol_table_name='synthetic',layer_name='virtual',object_from_symbol=lambda **kw:None)
        context=SimpleNamespace(modules={'kernel':module},layers={'physical':layer},object=lambda *args,**kw:SimpleNamespace(vol=SimpleNamespace(offset=kw['offset'])))
        def walk(kernel,physical,at,offset):
            return None if targets[at] is None else SimpleNamespace(vol=SimpleNamespace(offset=targets[at]))
        harness=SimpleNamespace(context=context,_progress_callback=None,
            _find_memory_layer_name=lambda _: 'physical',
            _find_file_ops_needles=lambda _:({patterns['file'],patterns['both']},40),
            _find_sk_destruct_needles=lambda _:({patterns['destructor'],patterns['both']},80),
            _walk_file_ops_needles=walk,
            _extract_sock_fields=lambda sock,handler:None if sock.vol.offset in filtered else (sock.vol.offset,))
        with patch.object(sockstat,'SockHandlers',lambda *args:None):
            emitted=[int(row[1][0]) for row in Sockscan._generator(harness,'kernel')]
        cases.append(dict(id=name,events=events,filtered=filtered,expected_offsets=emitted))
    ipv6=[]
    for name,offset in [('physical-high-pointer',0xffff80000001e000),('physical-low-pointer',0x100),('physical-null-pointer',0),('physical-masked-pointer',0xd100000000000100)]:
        data=bytearray(1024)
        data[0x100:0x110]=ipaddress.IPv6Address('::1').packed
        data[0x110:0x120]=ipaddress.IPv6Address('2001:db8::1').packed
        class Layers(dict):
            def read(self,layer,at,length): return offset.to_bytes(8,'little')
        pointer_context=SimpleNamespace(layers=Layers(virtual=SimpleNamespace(address_mask=(1<<48)-1)))
        info=SimpleNamespace(native_layer_name='virtual',layer_name='physical',offset=0)
        resolved=objects.Pointer._unmarshall(pointer_context,objects.DataFormatInfo(8,'little',False),info)
        context=contexts.Context();context.layers.add_layer(BufferDataLayer(context,'physical','physical',buffer=bytes(data)))
        common=SimpleNamespace(skc_family=socket.AF_INET6)
        harness=SimpleNamespace(_context=context,vol=SimpleNamespace(layer_name='physical'),
            sk=SimpleNamespace(**{'_inet_sock__sk_common':common}),
            pinet6=SimpleNamespace(saddr=SimpleNamespace(vol=SimpleNamespace(offset=resolved)),daddr=SimpleNamespace(vol=SimpleNamespace(offset=resolved+16))))
        c=dict(id=name,pointer=offset,expected_source=inet_sock.get_src_addr(harness),expected_destination=inet_sock.get_dst_addr(harness))
        common.skc_family=10
        c.update(linux_source=inet_sock.get_src_addr(harness),linux_destination=inet_sock.get_dst_addr(harness))
        ipv6.append(c)
    scans=[]
    for width in [4,8]:
        values=[0x12345678,0x87654321] if width==4 else [0x1122334455667788,0x8877665544332211]
        data=bytearray(80)
        for offset,index in [(3,1),(32,0),(60,1)]:data[offset:offset+width]=values[index].to_bytes(width,'little')
        patterns=[v.to_bytes(width,'little') for v in values]
        hits=[(offset,int.from_bytes(pattern,'little')) for offset,pattern in MultiStringScanner(patterns)(bytes(data),0)]
        scans.append(dict(width=width,values=values,data_hex=data.hex(),expected_hits=hits))
    return dict(reference_commit=PIN,
        source_sha256=hashlib.sha256((checkout/'volatility3/framework/plugins/linux/sockscan.py').read_bytes()).hexdigest(),
        network_sha256=hashlib.sha256((checkout/'volatility3/framework/symbols/linux/extensions/network.py').read_bytes()).hexdigest(),
        host_af_inet6=socket.AF_INET6,scope='Actual Sockscan generator with synthetic scan events and field extraction; actual inet_sock address methods with synthetic field offsets and physical BufferDataLayer; actual MultiStringScanner order. Does not validate file/inode traversal or full socket-family handlers.',sources=cases,ipv6=ipv6,scans=scans)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'));p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/sockscan.json'));a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
