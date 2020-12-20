#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("one_byte")
libc = elf.libc

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option.
# Returns chunk index.
def malloc():
    global index
    io.sendthen("> ", "1")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send("3")
    io.sendafter("index: ", f"{index}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

# Select the "read" option; read 0x58 bytes.
def read(index):
    io.send("4")
    io.sendafter("index: ", f"{index}")
    r = io.recv(0x58)
    io.recvuntil("> ")
    return r

io = start()
io.recvuntil("> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Request a chunk.
chunk_A = malloc()

# Edit chunk A.
edit(chunk_A, b"Y"*32)

# Read data from chunk A.
data = read(chunk_A)
log.info(f"Read from chunk_A:\n{data}")

# Free chunk A.
free(chunk_A)

# Because you haven't leaked a libc address yet, libc.sym.<symbol name>
# will only print a symbol's offset, rather than its actual address.
log.info(f"offset of puts() from start of GLIBC shared object: 0x{libc.sym.puts:02x}")

# Once you've leaked an address, e.g. the printf() function, use:
# libc.sym.address = <leaked printf address> - libc.sym.printf
# to correctly set your libc base address to its runtime address. Now future calls
# to libc.sym will use the symbol's actual address rather than its offset.

# =============================================================================

io.interactive()
