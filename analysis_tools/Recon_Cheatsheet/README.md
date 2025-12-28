# Reconnaissance Cheatsheet

## Overview

This cheatsheet covers essential reconnaissance techniques for binary analysis, from initial file classification to advanced dynamic analysis.

---

## Phase 1: File Classification

### Basic File Information

```bash
# Determine file type
file target_binary
# Output: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

# Check architecture and linking
file -b target_binary

# Identify stripped status
file target_binary | grep -q "not stripped" && echo "Symbols present" || echo "Stripped"
```

### File Metadata

```bash
# File size
ls -lh target_binary

# File hash (for tracking/identification)
md5sum target_binary
sha256sum target_binary

# File permissions
ls -la target_binary
# Check for SUID bit: -rwsr-xr-x (exploitation yields privilege escalation)
```

---

## Phase 2: Security Mitigations

### Checksec (Security Features)

```bash
# Using checksec (install: apt install checksec)
checksec --file=target_binary

# Using pwntools
python3 -c "from pwn import *; print(ELF('./target_binary').checksec())"

# Manual check (readelf)
readelf -l target_binary | grep -E "GNU_STACK|GNU_RELRO"
readelf -s target_binary | grep -E "__stack_chk_fail"
```

**Protection Interpretation:**

| Protection | Enabled | Disabled | Exploitation Impact |
|-----------|---------|----------|---------------------|
| **RELRO** | `RELRO: Full RELRO` | `RELRO: Partial RELRO` or `No RELRO` | Full: GOT read-only; Partial: GOT writable |
| **Stack Canary** | `CANARY: found` | `CANARY: not found` | Canary: Must leak or brute-force |
| **NX** | `NX: enabled` | `NX: disabled` | NX: Requires ROP; Disabled: Shellcode on stack |
| **PIE** | `PIE: enabled` | `PIE: disabled` | PIE: Code randomization, needs leak |
| **FORTIFY** | `FORTIFY: enabled` | `FORTIFY: disabled` | Compile-time buffer checks |

---

## Phase 3: Static Analysis

### Strings Analysis

```bash
# Extract all strings
strings target_binary

# Find interesting patterns
strings target_binary | grep -E "(password|admin|flag|key|secret)"

# Find IP addresses
strings target_binary | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"

# Find URLs
strings target_binary | grep -oE "https?://[^\s]+"

# Advanced: FLOSS (obfuscated strings)
floss target_binary
```

### Symbol Analysis

```bash
# List all symbols (if not stripped)
nm target_binary

# List dynamic symbols
nm -D target_binary

# Find specific function
nm target_binary | grep "vulnerable_function"

# List imported functions (PLT)
objdump -d target_binary | grep "@plt"

# Readelf symbols
readelf -s target_binary
```

### Disassembly

```bash
# Disassemble entire binary
objdump -d target_binary > disasm.txt

# Disassemble specific function
objdump -d target_binary | grep -A 50 "<main>:"

# Intel syntax (easier to read)
objdump -M intel -d target_binary

# Disassemble with source (if compiled with -g)
objdump -S target_binary
```

### Dependency Analysis

```bash
# List shared libraries
ldd target_binary
# Output:
#   libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f...)
#   /lib64/ld-linux-x86-64.so.2 (0x00007f...)

# Find libc version (for ROP gadgets)
ldd target_binary | grep libc
ls -la /lib/x86_64-linux-gnu/libc.so.6

# Check for custom libraries
ldd target_binary | grep -v "lib64\|lib/x86_64"
```

### Control Flow Analysis

```bash
# Generate call graph (using radare2)
r2 -q -c "aa; agC" target_binary > callgraph.dot
dot -Tpng callgraph.dot -o callgraph.png

# Find dangerous functions
objdump -d target_binary | grep -E "strcpy|gets|sprintf|system|exec"

# Cross-references to function
r2 -q -c "aa; axt @ sym.vulnerable_function" target_binary
```

---

## Phase 4: Dynamic Analysis

### System Call Tracing

```bash
# Trace all syscalls
strace ./target_binary

# Trace specific syscalls
strace -e trace=open,read,write ./target_binary

# Trace with timestamps
strace -t ./target_binary

# Trace network activity
strace -e trace=network ./target_binary

# Follow child processes
strace -f ./target_binary
```

### Library Call Tracing

```bash
# Trace all library calls
ltrace ./target_binary

# Trace specific functions
ltrace -e malloc,free,strcpy ./target_binary

# Count calls
ltrace -c ./target_binary

# Output to file
ltrace -o trace.log ./target_binary
```

### Process Monitoring

```bash
# Monitor file access
inotifywait -m /path/to/watch

# Monitor network connections
netstat -tulpn | grep target_binary

# Check open files
lsof -p $(pidof target_binary)

# Memory maps
cat /proc/$(pidof target_binary)/maps
```

---

## Phase 5: Fuzzing

### Basic Fuzzing

```bash
# Crash detection with cyclic pattern
python3 -c "from pwn import *; print(cyclic(500))" | ./target_binary

# Fuzz with random data
for i in {1..100}; do
    head -c 1000 /dev/urandom | ./target_binary
done

# Format string fuzzing
echo "AAAA %x %x %x %x %x %x" | ./target_binary
```

### AFL (American Fuzzy Lop)

```bash
# Compile with AFL instrumentation
afl-gcc -o target_afl target.c

# Create input directory
mkdir -p afl_in
echo "test" > afl_in/seed1

# Run fuzzer
afl-fuzz -i afl_in -o afl_out ./target_afl @@

# Check crashes
ls afl_out/crashes/
```

---

## Phase 6: Debugging Workflow

### GDB Reconnaissance

```bash
# Start GDB
gdb ./target_binary

# Essential commands
(gdb) info functions          # List all functions
(gdb) info variables          # List global variables
(gdb) disassemble main        # Disassemble main
(gdb) break *main             # Set breakpoint
(gdb) run AAAA                # Run with argument
(gdb) vmmap                   # Memory mappings (GEF/Pwndbg)
(gdb) checksec                # Security features (GEF/Pwndbg)
```

### Memory Mapping Analysis

```bash
# View memory layout
gdb ./target_binary
(gdb) break main
(gdb) run
(gdb) info proc mappings

# Example output:
# 0x555555554000  0x555555555000  0x1000     0x0  /path/to/binary (code)
# 0x7ffff7a0d000  0x7ffff7bd0000  0x1c3000   0x0  /lib/libc.so.6
# 0x7ffffffde000  0x7ffffffff000  0x21000    0x0  [stack]
```

---

## Phase 7: Exploitation Reconnaissance

### Finding Gadgets (ROP)

```bash
# Using ROPgadget
ROPgadget --binary target_binary

# Find specific gadget
ROPgadget --binary target_binary --only "pop|ret"

# Find syscall gadget
ROPgadget --binary target_binary --only "syscall"

# Using ropper
ropper --file target_binary --search "pop rdi"
```

### Libc Database (for ASLR bypass)

```bash
# Identify libc version from leaked addresses
# 1. Leak a known function address (e.g., puts)
# 2. Search libc database

# Using libc-database
./find puts 0x7f1234567890

# Online: https://libc.blukat.me/
# Input: Last 3 nibbles of leaked address
```

---

## Quick Reference Card

### One-Liner Toolkit

```bash
# Complete recon pipeline
file target && checksec target && strings target | grep -E "(flag|password)" && ldd target

# Find all dangerous functions
objdump -d target | grep -E "strcpy|gets|sprintf|system" | cut -d: -f1

# Automated crash detection
for i in {10..500..10}; do python3 -c "print('A'*$i)" | ./target && echo "Crashed at $i"; done

# Extract GOT addresses
objdump -R target | grep JUMP_SLOT

# Find writable sections
readelf -S target | grep -E "WA|AW"
```

---

## Tools Summary

| Category | Tools |
|----------|-------|
| **File Analysis** | file, checksec, readelf, objdump |
| **Strings** | strings, FLOSS |
| **Disassembly** | objdump, Ghidra, IDA Pro, radare2 |
| **Dynamic** | strace, ltrace, GDB, Frida |
| **Fuzzing** | AFL, radamsa, zzuf |
| **ROP** | ROPgadget, ropper, pwntools |

---

## Further Reading

- [Binary Analysis Course (RPISEC)](https://github.com/RPISEC/MBE)
- [Reverse Engineering for Beginners](https://beginners.re/)
