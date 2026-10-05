#!/usr/bin/env python3
"""Independent read-only checks for the seven additional analyses.
First runs the base sample parser, then derives all inspect fields from memory.
Bash validates recovered HIST_ENTRY records directly; completeness is covered by
synthetic Rust fixtures (the live samples have missing pages/no Bash processes).
"""
import runpy
from pathlib import Path
G=runpy.run_path(str(Path(__file__).with_name('debian.py')))
globals().update({k:v for k,v in G.items() if not k.startswith('__')})
hexaddr=lambda v:f'{v:#018x}'
def exported(plugin):return json.load(open(args.results_prefix+plugin+'.json'))
def check(plugin,rows):
 actual=exported(plugin)['rows']
 assert actual==rows,(plugin,len(actual),len(rows),next(((i,a,b) for i,(a,b) in enumerate(zip(actual,rows)) if a!=b),None))
 print(plugin,len(rows),'all fields independently verified')
def linked(head,offset):
 out=[];node=word(head);last=head
 while node!=head:
  assert node not in out and word(node+8)==last
  out.append(node);last=node;node=word(node)
 assert word(head+8)==last
 return [n-offset for n in out]
def module_range(module):
 if args.modern:
  mem=module+off('module','mem');start=num(mem,'module_memory','base');size=num(mem,'module_memory','size')
 else:start=num(module,'module','module_core');size=num(module,'module','core_size')
 return start,start+size
mods=linked(D['symbols']['modules']['address'],off('module','list'))
ls=[]
for m in mods:
 if args.modern:
  mem=m+off('module','mem');size=sum(num(mem+i*D['user_types']['module_memory']['size'],'module_memory','size') for i in range(4));base=num(mem,'module_memory','base')
 else:base=num(m,'module','module_core');size=num(m,'module','core_size')
 ls.append([cstr(m+off('module','name')),hexaddr(base),str(size)])
check('lsmod',ls)
kset=word(D['symbols']['module_kset']['address']);objects=linked(kset+off('kset','list'),off('kobject','entry'));sysfs=set()
for obj in objects:
 m=num(obj-off('module_kobject','kobj'),'module_kobject','mod')
 if m:
  assert m+off('module','mkobj')==obj-off('module_kobject','kobj')
  assert cstr(num(obj,'kobject','name'))==cstr(m+off('module','name'))
  sysfs.add(m)
check('check_modules',[[cstr(m+off('module','name')),hexaddr(m),*[hexaddr(v) for v in module_range(m)],str(m in mods).lower(),str(m in sysfs).lower(),'Consistent' if m in mods and m in sysfs else 'ViewMismatch; inspect lifecycle/unloading'] for m in sorted(set(mods)|sysfs)])
size=D.get('metadata',{}).get('zero',{}).get('symbol_sizes',{}).get('sys_call_table') or D['symbols']['sys_call_table']['type']['count']*8
assert size and size%8==0
symbols=sorted((v['address'],name) for name,v in D['symbols'].items() if 'address' in v);addresses=[s[0] for s in symbols]
ranges=[(D['symbols'].get('_stext',D['symbols'].get('_text'))['address'],D['symbols']['_etext']['address'],'kernel')]+[(*module_range(m),cstr(m+off('module','name'))) for m in mods]
rows=[]
for i in range(size//8):
 target=word(D['symbols']['sys_call_table']['address']+i*8);read(target,1);index=bisect.bisect_right(addresses,target)-1
 address,name=symbols[index];label=name if address==target else name+'+'+hex(target-address)
 owner=next((name for a,b,name in ranges if a<=target<b),'[unknown]')
 rows.append(['sys_call_table',str(i),hexaddr(target),label,owner,'KernelText' if owner=='kernel' else 'OutsideKnownExecutableRanges' if owner=='[unknown]' else 'ModuleTarget; inspect hook'])
check('check_syscall',rows)
tasks=linked(head,off('task_struct','tasks'))
psrows=[[str(num(t,'task_struct','pid')),str(num(t,'task_struct','tgid')),str(num(num(t,'task_struct','real_parent'),'task_struct','pid')),read(t+off('task_struct','comm'),16).split(b'\0')[0].decode(errors='replace'),hexaddr(t)] for t in tasks]
check('pslist',psrows);check('pstree',psrows)
threads={int(r[4],16) for r in expected['threads']};pids=[]
if args.modern:
 stack=[num(D['symbols']['init_pid_ns']['address']+off('pid_namespace','idr')+off('idr','idr_rt'),'xarray','xa_head')];visited=set()
 while stack:
  entry=stack.pop()
  if not entry:continue
  assert entry not in visited;visited.add(entry)
  if entry&3==2:
   assert entry>4096;node=entry-2;stack.extend(word(node+off('xa_node','slots')+i*8) for i in range(field('xa_node','slots')['type']['count']))
  else:assert entry&3==0;pids.append(entry)
 taskoffset=off('task_struct','pid_links')
else:
 table=word(D['symbols']['pid_hash']['address']);shift=int.from_bytes(read(D['symbols']['pidhash_shift']['address'],4),'little');ns=D['symbols']['init_pid_ns']['address']
 for i in range(1<<shift):
  n=word(table+i*D['user_types']['hlist_head']['size']);visited=set()
  while n:
   assert n not in visited;visited.add(n);u=n-off('upid','pid_chain')
   if num(u,'upid','ns')==ns:pids.append(u-off('pid','numbers'))
   n=word(n)
 taskoffset=off('task_struct','pids')+off('pid_link','node')
pidtasks=set()
for p in pids:
 n=word(p+off('pid','tasks'));previous=p+off('pid','tasks');visited=set()
 while n:
  assert n not in visited and word(n+8)==previous;visited.add(n)
  t=n-taskoffset
  if num(t,'task_struct','pid'):pidtasks.add(t)
  previous=n;n=word(n)
rows=[]
for t in sorted(set(tasks)|threads|pidtasks):
 pid=num(t,'task_struct','pid');tgid=num(t,'task_struct','tgid');a=t in tasks;b=t in pidtasks;c=t in threads
 reason='Consistent' if a and b and c else 'ThreadOnly' if pid!=tgid and not a and b and c else 'ViewMismatch; inspect exit/lifecycle'
 rows.append([str(pid),read(t+off('task_struct','comm'),16).split(b'\0')[0].decode(errors='replace'),hexaddr(t),str(a).lower(),str(b).lower(),str(c).lower(),reason])
check('psxview',rows)
elfs=[];malfind=[];bash_tasks={}
for task in tasks:
 pid=str(num(task,'task_struct','pid'));comm=read(task+off('task_struct','comm'),16).split(b'\0')[0].decode(errors='replace');mm=num(task,'task_struct','mm')
 if not mm:continue
 root=pa(num(mm,'mm_struct','pgd'))
 if comm=='bash':bash_tasks[pid]=root
 try:nodes=vmas(mm)
 except ValueError:continue
 for node in nodes:
  start=num(node,'vm_area_struct','vm_start');end=num(node,'vm_area_struct','vm_end');flags=num(node,'vm_area_struct','vm_flags');file=num(node,'vm_area_struct','vm_file')
  if not flags&1:continue
  path=safe_filepath(task,file) if file else '[anonymous]'
  try:b=read(start,64,root)
  except ValueError:continue
  if b[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',b,18)[0]==(183 if args.modern else 62) and struct.unpack_from('<H',b,16)[0] in (2,3) and struct.unpack_from('<H',b,52)[0]==64:
   elfs.append([pid,comm,hexaddr(start),hexaddr(end),'EXEC' if struct.unpack_from('<H',b,16)[0]==2 else 'DYN',hexaddr(struct.unpack_from('<Q',b,24)[0]),path])
  if flags&4 and (flags&2 or not file):
   perms=''.join(c if flags&mask else '-' for c,mask in [('r',1),('w',2),('x',4)])+('s' if flags&8 else 'p')
   malfind.append([pid,comm,hexaddr(start),hexaddr(end),perms,path,'WritableExecutable' if flags&2 else 'AnonymousExecutable',b[:32].hex(' ')])
check('elfs',elfs);check('malfind',malfind)
def userstr(ptr,root):
 b=bytearray()
 for i in range(65536):
  c=read(ptr+i,1,root)
  if c==b'\0':return b.decode(errors='replace')
  b.extend(c)
 raise ValueError('unterminated')
for pid,name,timestamp,command,addr in exported('bash')['rows']:
 assert name=='bash' and pid in bash_tasks
 root=bash_tasks[pid];line,ts,data=struct.unpack('<QQQ',read(int(addr,16),24,root))
 assert userstr(line,root)==command
 assert userstr(ts,root)=='#'+timestamp if timestamp!='[missing]' else ts==0
if not bash_tasks:check('bash',[])
else:print('bash',len(exported('bash')['rows']),'recovered records independently verified; missing pages prevent completeness')
info=dict(exported('systeminfo')['rows'])
assert info['Architecture']==('aarch64' if args.modern else 'x86_64') and int(info['PageTable'],16)==ROOT and info['PageSize']=='4096' and info['VABits']=='48' and int(info['KernelSlide'],16)==0
assert info['Kernel']==exported('pslist')['banner'] and info['ImageFormat']==('LiME' if args.modern else 'RAW')
import hashlib
assert info['ImageSHA256']==hashlib.sha256(M).hexdigest()
assert info['SymbolSource']==exported('pslist')['symbol']
assert info['Validation']=='完整 banner／init_task／双向链表／页表已验证'
# Serde preserves insertion order of ISF keys; compare its digest to the source
# raw JSON bytes (Isf::parse hashes the decoded input, not a reformatted object).
raw=lzma.decompress(Path(args.symbols).read_bytes()) if args.modern else lzma.decompress(zipfile.ZipFile(args.symbols).read('linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz'))
assert info['SymbolSHA256']==hashlib.sha256(raw).hexdigest()
print('systeminfo 11 all fields independently verified')
