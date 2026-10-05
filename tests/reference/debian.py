#!/usr/bin/env python3
"""Independent, read-only acceptance cross-check. No engine/Volatility imports.

Uses only Python's standard library and the fixed sample's validated root.
Run after CLI exports with --no-cache, using a prepared RAW image.
"""
import argparse, json, zipfile, lzma, mmap, struct, ipaddress, bisect
from functools import lru_cache
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--image', required=True)
parser.add_argument('--symbols', default='linux.zip')
parser.add_argument('--results-prefix', default='/tmp/zero-')
parser.add_argument('--modern',action='store_true')
parser.add_argument('--plugins', help='comma-separated outputs to verify; default all')
args = parser.parse_args()
if args.modern:D=json.loads(lzma.decompress(Path(args.symbols).read_bytes()))
else:D=json.loads(lzma.decompress(zipfile.ZipFile(args.symbols).read('linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz')))
F=open(args.image,'rb'); M=mmap.mmap(F.fileno(),0,access=mmap.ACCESS_READ)
ROOT=json.load(open(args.results_prefix+'pslist.json'))['page_table'] if args.modern else json.load(open(Path(__file__).resolve().parent.parent / 'fixtures/debian-3.2.json'))['page_table']
segments=[];offset=0
if M[:4]==b'EMiL':
 while offset<len(M):
  magic,version,start,end,_=struct.unpack_from('<IIQQQ',M,offset);assert magic==0x4c694d45 and version==1
  segments.append((start,end+1,offset+32));offset+=32+end-start+1
else:segments=[(0,len(M),0)]
starts=[s[0] for s in segments]
def physical(p,n):
 out=b''
 while n:
  index=bisect.bisect_right(starts,p)-1
  if index<0 or not segments[index][0]<=p<segments[index][1]:raise ValueError('physical hole '+hex(p))
  start,end,offset=segments[index];count=min(n,end-p);out+=M[offset+p-start:offset+p-start+count];n-=count;p+=count
 return out
def field(t,f):
 if '.' in f:
  first,rest=f.split('.',1);a=field(t,first);b=field(a['type']['name'],rest);return dict(b,offset=a['offset']+b['offset'])
 fields=D['user_types'][t]['fields']
 if f in fields:return fields[f]
 matches=[]
 for key,value in fields.items():
  if key.startswith('unnamed_field_'):
   try:child=field(value['type']['name'],f);matches.append(dict(child,offset=value['offset']+child['offset']))
   except KeyError:pass
 if len(matches)!=1:raise KeyError((t,f))
 return matches[0]
def off(t,f):return field(t,f)['offset']
@lru_cache(maxsize=262144)
def pa(v,root=ROOT):
 p=root
 for shift in [39,30,21,12]:
  e=int.from_bytes(physical(p+((v>>shift)&511)*8,8),'little')
  if not e&1:raise ValueError('missing '+hex(v))
  block=not e&2 if args.modern else bool(e&128)
  if shift in [30,21] and block:return (e&(0xfffffffff000 if args.modern else 0xffffffffff000)&~((1<<shift)-1))+(v&((1<<shift)-1))
  p=e&(0xfffffffff000 if args.modern else 0xffffffffff000)
 return p+(v&4095)
def read(v,n,root=ROOT):
 out=b''
 while n:
  sz=min(n,4096-(v&4095));out+=physical(pa(v,root),sz);v+=sz;n-=sz
 return out
def num(v,t,f):
 if args.modern and t=='vfsmount' and f not in D['user_types'][t]['fields']:
  n=num(v-off('mount','mnt'),'mount',f);return n+off('mount','mnt') if f=='mnt_parent' else n
 item=field(t,f);ty=item['type'];kind=ty['kind']
 if kind=='struct':return num(v+item['offset'],ty['name'],'val')
 size=8 if kind=='pointer' else D['base_types'][ty['name']]['size'] if kind=='base' else D['enums'][ty['name']]['size'] if kind=='enum' else D['base_types'][ty['type']['name']]['size']
 n=int.from_bytes(read(v+off(t,f),size),'little')
 return (n>>ty['bit_position'])&((1<<ty['bit_length'])-1) if kind=='bitfield' else n
def word(v):return int.from_bytes(read(v,8),'little')
def vmas(mm):
 if not args.modern:
  node=num(mm,'mm_struct','mmap');seen=set();out=[]
  while node:
   assert node not in seen;seen.add(node);out.append(node);node=num(node,'vm_area_struct','vm_next')
  return out
 root=num(mm+off('mm_struct','mm_mt'),'maple_tree','ma_root');seen=set()
 def walk(entry,maximum,node=True):
  if not entry:return []
  assert entry not in seen;seen.add(entry)
  if not node:return [entry]
  typ=(entry>>3)&15;assert typ in (1,2,3);base=entry&~255
  ty='maple_arange_64' if typ==3 else 'maple_range_64'
  if num(base,ty,'parent')&~255==base:raise ValueError('deleted maple node '+hex(base))
  count=field(ty,'slot')['type']['count'];last=num(base,ty,'meta.end') if typ==3 else None
  if last is None:
   pivot=word(base+off(ty,'pivot')+(count-2)*8);last=num(base,ty,'meta.end') if pivot==0 else count-2 if pivot==maximum else count-1
  out=[]
  for i in range(last+1):
   pivot=word(base+off(ty,'pivot')+i*8) if i<count-1 else maximum
   child=word(base+off(ty,'slot')+i*8)
   if child:out.extend([child] if typ==1 else walk(child,pivot))
  return out
 out=sorted(set(walk(root,(1<<64)-1,root&3==2)),key=lambda v:num(v,'vm_area_struct','vm_start'))
 assert len(out)==num(mm,'mm_struct','map_count')
 return out
def cstr(v):return read(v,128).split(b'\0')[0].decode('utf8',errors='replace')
def name(d):
 q=d+off('dentry','d_name');return read(num(q,'qstr','name'),num(q,'qstr','len')).decode(errors='replace')
def fsname(d):
    sb=num(d,'dentry','d_sb');st=num(sb,'super_block','s_type')
    return cstr(num(st,'file_system_type','name'))
def filepath(task,file):
    fs=num(task,'task_struct','fs');root=fs+off('fs_struct','root')
    rd=num(root,'path','dentry');rm=num(root,'path','mnt')
    p=file+off('file','f_path');d=num(p,'path','dentry');m=num(p,'path','mnt');parts=[];seen=set()
    while (d,m)!=(rd,rm):
        assert (d,m) not in seen and len(seen)<1024
        seen.add((d,m))
        if d==num(m,'vfsmount','mnt_root'):
            parent=num(m,'vfsmount','mnt_parent')
            if parent==m:
                if fsname(d)=='tmpfs':return '[tmpfs]/'+'/'.join(reversed(parts))
                raise ValueError('path outside process root')
            d=num(m,'vfsmount','mnt_mountpoint');m=parent
        else:
            parts.append(name(d));parent=num(d,'dentry','d_parent')
            if parent==d:
                if fsname(d)=='anon_inodefs':return 'anon_inode:['+parts[0]+']'
                raise ValueError('path outside process root')
            d=parent
    return '/'+'/'.join(reversed(parts))
def safe_filepath(task,file):
    try:return filepath(task,file)
    except (ValueError,AssertionError):return '[unresolved]'
def state(n):
    return {1:'ESTABLISHED',2:'SYN_SENT',3:'SYN_RECV',4:'FIN_WAIT1',5:'FIN_WAIT2',6:'TIME_WAIT',7:'CLOSE',8:'CLOSE_WAIT',9:'LAST_ACK',10:'LISTEN',11:'CLOSING',12:'NEW_SYN_RECV'}.get(n,'Unknown')
def socketrow(ino):
    socket=ino-off('socket_alloc','vfs_inode')+off('socket_alloc','socket');sk=num(socket,'socket','sk');common=sk+off('sock','__sk_common')
    family=num(common,'sock_common','skc_family');ty=num(sk,'sock','sk_type');proto=num(sk,'sock','sk_protocol')
    typen={1:'STREAM',2:'DGRAM',3:'RAW',5:'SEQPACKET'}.get(ty,str(ty));proton={6:'TCP',17:'UDP'}.get(proto,str(proto))
    if family in (2,10) and proto in (6,17):
        sport=int.from_bytes(read(sk+off('inet_sock','inet_sport'),2),'big');dport=int.from_bytes(read(common+off('sock_common','skc_dport') if args.modern else sk+off('inet_sock','inet_dport'),2),'big')
        if family==2:
            local=str(ipaddress.IPv4Address(read(common+off('sock_common','skc_rcv_saddr'),4)))+':'+str(sport)
            remote=str(ipaddress.IPv4Address(read(common+off('sock_common','skc_daddr'),4)))+':'+str(dport)
        else:
            info=common if args.modern else num(sk,'inet_sock','pinet6')
            local='['+str(ipaddress.IPv6Address(read(info+off('sock_common','skc_v6_rcv_saddr') if args.modern else info+off('ipv6_pinfo','rcv_saddr'),16)))+']:'+str(sport)
            remote='['+str(ipaddress.IPv6Address(read(info+off('sock_common','skc_v6_daddr') if args.modern else info+off('ipv6_pinfo','daddr'),16)))+']:'+str(dport)
        fam='IPv4' if family==2 else 'IPv6';status=state(num(common,'sock_common','skc_state')) if proto==6 else 'UDP'
    elif family==1:
        fam='Unix';addr=num(sk,'unix_sock','addr');peer=num(sk,'unix_sock','peer')
        local='[unnamed]'
        if addr:
            length=num(addr,'unix_address','len');offset=off('sockaddr_un','sun_path');b=read(addr+off('unix_address','name')+offset,length-offset)
            if b:local='@'+b[1:].decode(errors='replace') if b[0]==0 else b.split(b'\0')[0].decode(errors='replace')
        remote=f"{num(peer,'sock','sk_socket'):#018x}" if peer else '[none]';status=state(num(common,'sock_common','skc_state'))
    else:fam=str(family);local=remote='';status='UnsupportedFamily'
    return [fam,typen,proton,local,remote,status,f'{socket:#018x}']
def path_pair(d,m,root=None):
    parts=[];seen=set()
    while root!=(d,m):
        assert (d,m) not in seen and len(seen)<1024
        seen.add((d,m))
        if d==num(m,'vfsmount','mnt_root'):
            parent=num(m,'vfsmount','mnt_parent')
            if parent==m:
                if fsname(d)=='tmpfs':return '[tmpfs]/'+'/'.join(reversed(parts))
                assert root is None
                return '/'+'/'.join(reversed(parts))
            d=num(m,'vfsmount','mnt_mountpoint');m=parent
        else:parts.append(name(d));d=num(d,'dentry','d_parent')
    return '/'+'/'.join(reversed(parts))
credentials={};leaders=set()
expected={p:[] for p in ['psaux','envars','maps','lsof','sockstat','banners','pwd','pscred','threads','mountinfo','check_creds','dmesg','psstate','capabilities','fdsummary']}
head=D['symbols']['init_task']['address']+off('task_struct','tasks');node=int.from_bytes(read(head,8),'little');seen=set();missing=[]
while node!=head:
    assert node not in seen;seen.add(node);task=node-off('task_struct','tasks');pid=str(num(task,'task_struct','pid'));comm=read(task+off('task_struct','comm'),16).split(b'\0')[0].decode(errors='replace');prefix=[pid,comm]
    state_field='__state' if '__state' in D['user_types']['task_struct']['fields'] else 'state'
    expected['psstate'].append(prefix+[f"{num(task,'task_struct',f):#018x}" for f in [state_field,'exit_state','flags']])
    mm=num(task,'task_struct','mm')
    if not mm:expected['psaux'].append(prefix+[f'[{comm}]','KernelThread'])
    else:
        for plugin,kind in [('psaux','arg'),('envars','env')]:
            start=num(mm,'mm_struct',kind+'_start');end=num(mm,'mm_struct',kind+'_end')
            try:b=read(start,end-start,pa(num(mm,'mm_struct','pgd'))) if end>start else b''
            except ValueError:missing.append((plugin,pid));continue
            if plugin=='psaux':
                if b.endswith(b'\0'):b=b[:-1]
                expected[plugin].append(prefix+[b.decode(errors='replace').replace('\0',' '),'OK'])
            else:
                for v in b.split(b'\0'):
                    if not v:continue
                    key,sep,val=v.decode(errors='replace').partition('=');expected[plugin].append(prefix+[key,val])
        vseen=set()
        try:vmnodes=vmas(mm)
        except ValueError as e:missing.append(('maps',pid,str(e)));vmnodes=[]
        for v in vmnodes:
            assert v not in vseen;vseen.add(v);start=num(v,'vm_area_struct','vm_start');end=num(v,'vm_area_struct','vm_end');flags=num(v,'vm_area_struct','vm_flags');file=num(v,'vm_area_struct','vm_file')
            perms=''.join(c if flags&mask else '-' for c,mask in [('r',1),('w',2),('x',4)])+('s' if flags&8 else 'p')
            expected['maps'].append(prefix+[f'{start:#018x}',f'{end:#018x}',perms,str(num(v,'vm_area_struct','vm_pgoff')*4096),safe_filepath(task,file) if file else '[anonymous]'])
    counts=[0,0,0,0]
    files=num(task,'task_struct','files')
    if files:
        table=num(files,'files_struct','fdt');count=num(table,'fdtable','max_fds');array=num(table,'fdtable','fd')
        for fd in range(count):
            file=int.from_bytes(read(array+fd*8,8),'little')
            if not file:continue
            path=file+off('file','f_path');d=num(path,'path','dentry');ino=num(d,'dentry','d_inode');mode=num(ino,'inode','i_mode')&0xf000;inum=str(num(ino,'inode','i_ino'))
            type_name={0x1000:'FIFO',0x2000:'Character',0x4000:'Directory',0x6000:'Block',0x8000:'Regular',0xa000:'Symlink',0xc000:'Socket'}.get(mode,'Unknown')
            try:label=f'socket:[{inum}]' if mode==0xc000 else f'pipe:[{inum}]' if mode==0x1000 and d==num(d,'dentry','d_parent') else filepath(task,file) if mode==0x1000 else safe_filepath(task,file)
            except (ValueError,AssertionError):missing.append(('lsof',pid,fd));continue
            counts[0]+=1
            if mode in (0x8000,0xc000,0x1000):counts[{0x8000:1,0xc000:2,0x1000:3}[mode]]+=1
            expected['lsof'].append(prefix+[str(fd),type_name,inum,label,f'{file:#018x}'])
            if mode==0xc000:expected['sockstat'].append(prefix+[str(fd)]+socketrow(ino))
    expected['fdsummary'].append(prefix+[str(n) for n in counts])
    fs=num(task,'task_struct','fs')
    if not fs:rootpath=cwd='[none]'
    else:
        root=fs+off('fs_struct','root');pwd=fs+off('fs_struct','pwd');rd=num(root,'path','dentry');rm=num(root,'path','mnt')
        if not rd or not rm:assert not mm;rootpath=cwd='[none]'
        else:rootpath=path_pair(rd,rm);cwd=path_pair(num(pwd,'path','dentry'),num(pwd,'path','mnt'),(rd,rm))
    expected['pwd'].append(prefix+[rootpath,cwd])
    cred=num(task,'task_struct','cred');credentials.setdefault(cred,[]).append(prefix)
    masks=[]
    for f in ['cap_inheritable','cap_permitted','cap_effective','cap_bset']:
        ty=field('cred',f)['type']
        size=D['user_types'][ty['name']]['size'] if ty['kind']=='struct' else D['base_types'][ty['name']]['size']
        assert 0<size<=8
        masks.append(f"{int.from_bytes(read(cred+off('cred',f),size),'little'):#018x}")
    expected['capabilities'].append(prefix+masks+[f'{cred:#018x}'])
    expected['pscred'].append(prefix+[str(num(cred,'cred',f)) for f in ['uid','gid','euid','egid','suid','sgid','fsuid','fsgid']]+[f'{cred:#018x}'])
    leader=num(task,'task_struct','group_leader')
    if leader not in leaders:
        leaders.add(leader)
        if args.modern:
            signal=num(leader,'task_struct','signal');th=signal+off('signal_struct','thread_head');entry=word(th);threads=[]
            while entry!=th:threads.append(entry-off('task_struct','thread_node'));entry=word(entry)
        else:
            offset=off('task_struct','thread_group');current=leader;threads=[current]
            while True:
                n=word(current+offset)
                if n==leader+offset:break
                current=n-offset;threads.append(current)
        for current in threads:
            tid=str(num(current,'task_struct','pid'));threadname=read(current+off('task_struct','comm'),16).split(b'\0')[0].decode(errors='replace')
            expected['threads'].append(prefix+[tid,threadname,f'{current:#018x}'])
    ns=num(task,'task_struct','nsproxy')
    if ns:
        ns=num(ns,'nsproxy','mnt_ns');mounts=[]
        if args.modern:
            pending=[num(ns,'mnt_namespace','root')]
            while pending:
                mount=pending.pop();mounts.append(mount+off('mount','mnt'));h=mount+off('mount','mnt_mounts');entry=word(h);children=[]
                while entry!=h:children.append(entry-off('mount','mnt_child'));entry=word(entry)
                pending.extend(reversed(children))
            assert len(mounts)==num(ns,'mnt_namespace','nr_mounts')
        else:
            mh=ns+off('mnt_namespace','list');entry=word(mh)
            while entry!=mh:mounts.append(entry-off('vfsmount','mnt_list'));entry=word(entry)
        for mount in mounts:
            parent=num(mount,'vfsmount','mnt_parent');dev=num(mount,'vfsmount','mnt_devname');sb=num(mount,'vfsmount','mnt_sb');ty=num(sb,'super_block','s_type')
            expected['mountinfo'].append(prefix+[str(num(mount,'vfsmount','mnt_id')),str(num(parent,'vfsmount','mnt_id')),cstr(dev) if dev else '[none]',path_pair(num(mount,'vfsmount','mnt_root'),mount),cstr(num(ty,'file_system_type','name')),f"{num(mount,'vfsmount','mnt_flags'):#018x}",f'{mount:#018x}'])
    node=int.from_bytes(read(node+off('list_head','next'),8),'little')
assert len(seen)==(169 if args.modern else 133)
for cred,owners in sorted(credentials.items()):
    if len(owners)>1:expected['check_creds'].append([f'{cred:#018x}',','.join(o[0] for o in owners),','.join(o[1] for o in owners),str(num(cred,'cred','uid')),str(num(cred,'cred','euid'))])
p=0
while True:
    p=M.find(b'Linux version ',p)
    if p<0:break
    end=M.find(b'\0',p,p+65536)
    if end>=0:
        data=M[p:end]
        if all(c in (9,10,13) or c>=32 and c!=127 for c in data):expected['banners'].append([f'{next(start+p-offset for start,end,offset in segments if offset<=p<offset+end-start):#018x}',data.decode(errors='replace')])
    p+=1
if args.modern:
    prb=word(D['symbols']['prb']['address']);dr=prb+off('printk_ringbuffer','desc_ring');tr=prb+off('printk_ringbuffer','text_data_ring');count=1<<num(dr,'prb_desc_ring','count_bits');size=1<<num(tr,'prb_data_ring','size_bits')
    descs=num(dr,'prb_desc_ring','descs');infos=num(dr,'prb_desc_ring','infos');data=num(tr,'prb_data_ring','data');tail=word(dr+off('prb_desc_ring','tail_id'));headid=word(dr+off('prb_desc_ring','head_id'));mask=(1<<62)-1
    for n in range(((headid-tail)&mask)+1):
        id=(tail+n)&mask;idx=id&(count-1);desc=descs+idx*D['user_types']['prb_desc']['size'];state=word(desc+off('prb_desc','state_var'))
        if state&mask!=id or state>>62 not in (1,2):continue
        info=infos+idx*D['user_types']['printk_info']['size'];length=num(info,'printk_info','text_len');begin=num(desc,'prb_desc','text_blk_lpos.begin');nextpos=num(desc,'prb_desc','text_blk_lpos.next')
        if begin&1:continue
        offset=(begin&(size-1)) if begin//size==nextpos//size else 0
        assert word(data+offset)==id
        expected['dmesg'].append([str(num(info,'printk_info','seq')),read(data+offset+8,length).decode(errors='replace')])
else:
    ptr=int.from_bytes(read(D['symbols']['log_buf']['address'],8),'little');size=int.from_bytes(read(D['symbols']['log_buf_len']['address'],4),'little');end=int.from_bytes(read(D['symbols']['log_end']['address'],4),'little');count=min(size,int.from_bytes(read(D['symbols']['logged_chars']['address'],4),'little'))
    start=(end-count)&0xffffffff;data=bytes(read(ptr+((start+i)&(size-1)),1)[0] for i in range(count));lines=data.decode(errors='replace').split('\n')
    if lines and lines[-1]=='':lines.pop()
    expected['dmesg']=[[str(i),line] for i,line in enumerate(lines)]
for plugin,rows in expected.items():
    if args.plugins and plugin not in args.plugins.split(','):continue
    actual=json.load(open(args.results_prefix+plugin+'.json'))['rows']
    if actual!=rows:
        for index,(a,b) in enumerate(zip(actual,rows)):
            if a!=b:raise AssertionError((plugin,index,a,b))
        raise AssertionError((plugin,len(actual),len(rows)))
    print(plugin,len(rows),'all fields independently verified')
print('Missing user pages:',missing)
