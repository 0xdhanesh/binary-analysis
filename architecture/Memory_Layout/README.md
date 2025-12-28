# Memory Layout

## Overview

Understanding memory layout is fundamental to binary exploitation. This document covers the organization of process memory, including code, data, heap, and stack segments.

---

## Process Memory Layout (Linux x64)

```
High Memory (0x7FFFFFFFFFFF)
┌─────────────────────────────────────┐
│  Kernel Space                       │  Not accessible from user mode
│  (0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF)
├─────────────────────────────────────┤
│  [Stack]                            │  ← RSP (grows downward)
│  - Local variables                  │
│  - Function arguments               │
│  - Return addresses                 │
│  - Environment variables            │
├─────────────────────────────────────┤
│  ↓ (Stack grows down)               │
│                                     │
│  [Unused Memory]                    │
│                                     │
│  ↑ (Heap grows up)                  │
├─────────────────────────────────────┤
│  [Heap]                             │  ← Managed by malloc/free
│  - Dynamically allocated memory     │
│  - Grows toward higher addresses    │
├─────────────────────────────────────┤
│  [BSS Segment]                      │  Uninitialized global/static vars
│  - Zero-initialized data            │  (Writable)
├─────────────────────────────────────┤
│  [Data Segment]                     │  Initialized global/static vars
│  - Initialized global variables     │  (Writable)
│  - Static variables                 │
├─────────────────────────────────────┤
│  [Read-Only Data]                   │  Constants, string literals
│  - String literals                  │  (Read-only)
│  - Const variables                  │
├─────────────────────────────────────┤
│  [Text Segment / Code]              │  Executable code
│  - Program instructions             │  (Read + Execute, no Write)
│  - Shared library code              │
├─────────────────────────────────────┤
│  [Reserved / NULL]                  │  0x0000000000000000
└─────────────────────────────────────┘
Low Memory (0x0000000000000000)
```

---

## Segment Details

### 1. Text Segment (Code)

**Purpose:** Contains executable instructions

**Properties:**
- **Permissions:** Read + Execute (RX)
- **Fixed size** (determined at compile time)
- **Shared** among multiple instances of same program

**Exploitation:**
- **Code injection:** Impossible (no write permission)
- **Code reuse:** ROP (Return-Oriented Programming)

**Example:**
```c
int add(int a, int b) {
    return a + b;  // This code lives in .text segment
}
```

**Memory Map:**
```bash
$ cat /proc/$(pidof program)/maps | grep "r-xp"
555555554000-555555555000 r-xp 00000000 08:01 12345  /path/to/program
```

---

### 2. Data Segment

**Purpose:** Initialized global and static variables

**Properties:**
- **Permissions:** Read + Write (RW)
- **Fixed size**
- **Persistent** across function calls

**Example:**
```c
int global_var = 42;        // .data segment
static int static_var = 10; // .data segment

int main() {
    global_var++;  // Modifies .data segment
}
```

**Exploitation:**
- **GOT overwrite:** Global Offset Table (for dynamic linking)
- **Data corruption:** Overwrite global flags/pointers

---

### 3. BSS Segment

**Purpose:** Uninitialized global and static variables

**Properties:**
- **Permissions:** Read + Write (RW)
- **Zero-initialized** by loader
- **Fixed size**

**Example:**
```c
int uninitialized_global;        // .bss segment (initialized to 0)
static int uninitialized_static; // .bss segment

int main() {
    printf("%d\n", uninitialized_global);  // Prints 0
}
```

---

### 4. Heap

**Purpose:** Dynamic memory allocation (malloc, new, etc.)

**Properties:**
- **Permissions:** Read + Write (RW)
- **Grows upward** (toward higher addresses)
- **Managed by allocator** (glibc malloc, tcache, etc.)

**Structure:**
```
Heap Memory
┌─────────────────────────────────────┐
│  Top Chunk (wilderness)             │  ← Extends heap via sbrk/mmap
├─────────────────────────────────────┤
│  Allocated Chunk 3                  │
│  [Header | User Data]               │
├─────────────────────────────────────┤
│  Free Chunk 2 (in freelist)         │
│  [Header | fd | bk | ...]           │
├─────────────────────────────────────┤
│  Allocated Chunk 1                  │
│  [Header | User Data]               │
├─────────────────────────────────────┤
│  Heap Base                          │
└─────────────────────────────────────┘
```

**Exploitation:**
- **Heap overflow:** Corrupt adjacent chunks
- **Use-After-Free:** Reallocate freed memory
- **Double-free:** Corrupt freelist pointers

**Example:**
```c
int *ptr = malloc(64);  // Allocates 64 bytes on heap
free(ptr);              // Returns memory to heap
```

---

### 5. Stack

**Purpose:** Function call management, local variables

**Properties:**
- **Permissions:** Read + Write (RW) - NX if DEP enabled
- **Grows downward** (toward lower addresses)
- **LIFO** (Last In, First Out)

**Stack Frame Structure:**
```
High Addresses
┌─────────────────────────────────────┐
│  Function Arguments (caller)        │  [RBP+16], [RBP+24], ...
├─────────────────────────────────────┤
│  Return Address                     │  [RBP+8] ← Exploit target!
├─────────────────────────────────────┤  ← RBP (Frame Pointer)
│  Saved RBP                          │  [RBP]
├─────────────────────────────────────┤
│  Local Variable 1                   │  [RBP-8]
│  Local Variable 2                   │  [RBP-16]
│  Buffer[64]                         │  [RBP-80] to [RBP-16]
├─────────────────────────────────────┤  ← RSP (Stack Pointer)
│  Unused Stack Space                 │
└─────────────────────────────────────┘
Low Addresses
```

**Exploitation:**
- **Stack overflow:** Overwrite return address
- **Stack pivot:** Redirect RSP to controlled memory
- **ROP chains:** Chain gadgets on stack

---

## Memory Permissions

| Segment | Read | Write | Execute | Typical Permissions |
|---------|------|-------|---------|---------------------|
| **Text** | ✓ | ✗ | ✓ | `r-xp` |
| **Data** | ✓ | ✓ | ✗ | `rw-p` |
| **BSS** | ✓ | ✓ | ✗ | `rw-p` |
| **Heap** | ✓ | ✓ | ✗ | `rw-p` |
| **Stack** | ✓ | ✓ | ✗ (if NX) | `rw-p` |
| **Libraries** | ✓ | ✗ | ✓ | `r-xp` (code), `rw-p` (data) |

---

## ASLR (Address Space Layout Randomization)

**Purpose:** Randomize memory addresses to prevent exploitation

**Randomized Segments:**
- **Stack:** Base address randomized
- **Heap:** Base address randomized
- **Libraries:** Loaded at random addresses
- **PIE binaries:** Code segment randomized

**Example (ASLR disabled vs enabled):**
```bash
# Disable ASLR
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Run program twice
./program & cat /proc/$(pidof program)/maps | grep stack
./program & cat /proc/$(pidof program)/maps | grep stack
# Output: Same stack address both times

# Enable ASLR
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

# Run program twice
./program & cat /proc/$(pidof program)/maps | grep stack
./program & cat /proc/$(pidof program)/maps | grep stack
# Output: Different stack addresses
```

**Bypassing ASLR:**
1. **Information leak:** Leak stack/heap/libc address
2. **Brute-force:** Spray memory (32-bit systems)
3. **Partial overwrite:** Overwrite least significant bytes

---

## Viewing Memory Layout

### /proc/[pid]/maps

```bash
# View memory layout of running process
cat /proc/$(pidof program)/maps

# Example output:
555555554000-555555555000 r-xp 00000000 08:01 12345  /path/to/program (text)
555555755000-555555756000 r--p 00001000 08:01 12345  /path/to/program (rodata)
555555756000-555555757000 rw-p 00002000 08:01 12345  /path/to/program (data)
555555757000-555555778000 rw-p 00000000 00:00 0      [heap]
7ffff7a0d000-7ffff7bd0000 r-xp 00000000 08:01 67890  /lib/libc.so.6
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0      [stack]
```

### GDB (vmmap)

```bash
gdb ./program
(gdb) break main
(gdb) run
(gdb) vmmap  # GEF/Pwndbg command

# Output:
# Start              End                Perm  Name
# 0x0000555555554000 0x0000555555555000 r-xp  /path/to/program
# 0x00007ffff7a0d000 0x00007ffff7bd0000 r-xp  /lib/libc.so.6
# 0x00007ffffffde000 0x00007ffffffff000 rw-p  [stack]
```

---

## Key Takeaways

1. **Stack grows down, heap grows up**
2. **Code is read-only + executable (RX)**
3. **Data/BSS/Heap/Stack are read-write (RW)**
4. **ASLR randomizes addresses** (requires leaks)
5. **Return address on stack** is primary exploit target

---

## Further Reading

- [Linux Memory Management](https://www.kernel.org/doc/html/latest/admin-guide/mm/index.html)
- [ELF Format Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
