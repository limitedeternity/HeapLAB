#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_orange")
libc = elf.libc

gs = '''
set breakpoint pending on
break _IO_flush_all_lockp
enable breakpoints once 1
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Select the "malloc (small)" option.
def small_malloc():
    io.send("1")
    io.recvuntil("> ")

# Select the "malloc (large)" option.
def large_malloc():
    io.sendthen("> ", "2")

# Select the "edit (1st small chunk)" option; send data.
def edit(data):
    io.send("3")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil("heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil("> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Request a small chunk.
small_malloc()

# Edit the 1st small chunk.
edit(b"Y"*24)

# Request a large chunk.
large_malloc()

# =============================================================================

io.interactive()
