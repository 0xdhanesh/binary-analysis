# GDB Scripts & Automation

## Overview

This directory contains GDB scripts, cheatsheets, and automation tools for efficient binary analysis and exploitation development.

---

## Essential GDB Extensions

### 1. GEF (GDB Enhanced Features)
```bash
# Installation
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Features:
# - Enhanced disassembly with syntax highlighting
# - Heap analysis (heap chunks, bins)
# - ROP gadget search
# - Pattern generation/offset finding
```

### 2. Pwndbg
```bash
# Installation
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Features:
# - Telescope (recursive pointer dereferencing)
# - Heap visualization
# - Automatic ASLR detection
```

### 3. PEDA (Python Exploit Development Assistance)
```bash
# Installation
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
```

---

## GDB Cheatsheet

### Basic Commands

| Command | Description | Example |
|---------|-------------|---------|
| `run [args]` | Start program | `run < input.txt` |
| `break *addr` | Set breakpoint | `break *main` |
| `continue` | Continue execution | `c` |
| `step` | Step into function | `s` |
| `next` | Step over function | `n` |
| `finish` | Run until return | `fin` |
| `info registers` | Show all registers | `i r` |
| `info functions` | List all functions | `i func` |
| `disassemble func` | Disassemble function | `disas main` |

### Memory Examination

| Command | Format | Description |
|---------|--------|-------------|
| `x/nfu addr` | - | Examine memory (n=count, f=format, u=unit) |
| `x/20wx $esp` | Word (32-bit) hex | Examine 20 words from ESP |
| `x/10gx $rsp` | Giant (64-bit) hex | Examine 10 qwords from RSP |
| `x/s addr` | String | Print null-terminated string |
| `x/i $eip` | Instruction | Disassemble at EIP |

**Format Specifiers:**
- `x` = hexadecimal
- `d` = decimal
- `s` = string
- `i` = instruction
- `c` = character

**Unit Sizes:**
- `b` = byte (1 byte)
- `h` = halfword (2 bytes)
- `w` = word (4 bytes)
- `g` = giant (8 bytes)

---

## Automation Scripts

### 1. Pattern Generation & Offset Finding

```python
# pattern_gen.py
from pwn import *

# Generate cyclic pattern
pattern = cyclic(200)
print(pattern.decode())

# Find offset from crash value
# Example: EIP = 0x62616164
offset = cyclic_find(0x62616164)
print(f"Offset: {offset}")
```

**GDB Integration:**
```bash
# Generate pattern
gdb ./vulnerable
(gdb) run $(python3 -c "from pwn import *; print(cyclic(200))")

# After crash, find offset
(gdb) info registers eip
# eip: 0x62616164

# Calculate offset
$ python3 -c "from pwn import *; print(cyclic_find(0x62616164))"
# 44
```

---

### 2. Automated Exploitation Script

```python
# auto_exploit.gdb
# GDB script for automated exploitation

# Set breakpoints
break *main
break *vulnerable_function+42

# Run with pattern
run $(python3 -c "from pwn import *; print(cyclic(200))")

# Continue to crash
continue

# Examine crash state
info registers
x/20wx $esp

# Find offset
python
from pwn import *
import gdb
eip_value = int(gdb.parse_and_eval("$eip"))
offset = cyclic_find(eip_value)
print(f"[+] Offset to EIP: {offset}")
end

# Quit
quit
```

**Usage:**
```bash
gdb -x auto_exploit.gdb ./vulnerable
```

---

### 3. Heap Analysis Script

```gdb
# heap_analysis.gdb
# Analyze heap state

define heap_dump
    # Dump all heap chunks
    heap chunks
    
    # Show tcache bins
    heap bins tcache
    
    # Show fastbins
    heap bins fast
    
    # Show unsorted bin
    heap bins unsorted
end

# Set breakpoint before and after malloc/free
break malloc
commands
    silent
    printf "[MALLOC] Size: %d\n", $rdi
    continue
end

break free
commands
    silent
    printf "[FREE] Address: %p\n", $rdi
    x/4gx $rdi - 16  # Show chunk header
    continue
end
```

---

### 4. ROP Gadget Finder

```python
# rop_finder.py
from pwn import *

binary = ELF('./vulnerable')
rop = ROP(binary)

# Find specific gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

print(f"pop rdi; ret: {hex(pop_rdi)}")
print(f"pop rsi; pop r15; ret: {hex(pop_rsi_r15)}")
print(f"ret: {hex(ret)}")

# Build ROP chain
rop.raw(pop_rdi)
rop.raw(next(binary.search(b'/bin/sh\x00')))
rop.raw(binary.symbols['system'])

print(rop.dump())
```

**GDB Integration:**
```bash
# Search for gadgets in GDB (with GEF)
gef> ropper --search "pop rdi"
gef> ropper --search "pop rsi; pop r15"
```

---

## Advanced Techniques

### 1. Conditional Breakpoints

```gdb
# Break only when condition is true
break *main if $rdi == 0x41414141

# Break on specific iteration
break *loop_start if $rcx == 10
```

### 2. Watchpoints (Memory Access)

```gdb
# Break when memory is written
watch *(int*)0x804c000

# Break when memory is read
rwatch *(int*)0x804c000

# Break on read or write
awatch *(int*)0x804c000
```

### 3. Scripting with Python (GDB API)

```python
# gdb_script.py
import gdb

class ExploitHelper(gdb.Command):
    def __init__(self):
        super(ExploitHelper, self).__init__("exploit", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        # Get register values
        rip = int(gdb.parse_and_eval("$rip"))
        rsp = int(gdb.parse_and_eval("$rsp"))
        
        print(f"[+] RIP: {hex(rip)}")
        print(f"[+] RSP: {hex(rsp)}")
        
        # Read memory
        inferior = gdb.selected_inferior()
        memory = inferior.read_memory(rsp, 64)
        print(f"[+] Stack: {memory.hex()}")

ExploitHelper()
```

**Load in GDB:**
```gdb
source gdb_script.py
exploit
```

---

## Quick Reference

### One-Liners

```bash
# Dump all strings in binary
gdb -batch -ex "info functions" ./binary

# Find offset to function
gdb -batch -ex "p &system" /lib/x86_64-linux-gnu/libc.so.6

# Automated pattern crash
gdb -q -ex "run $(python3 -c 'from pwn import *; print(cyclic(200))')" ./vuln

# Dump GOT entries
gdb -batch -ex "x/20gx &_GLOBAL_OFFSET_TABLE_" ./binary
```

---

## Further Reading

- [GDB Documentation](https://sourceware.org/gdb/documentation/)
- [GEF Documentation](https://hugsy.github.io/gef/)
- [Pwntools GDB Integration](https://docs.pwntools.com/en/stable/gdb.html)
