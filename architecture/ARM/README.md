# ARM Architecture (32-bit)

## Overview

The **ARM architecture** is a family of RISC (Reduced Instruction Set Computer) processors widely used in mobile devices, embedded systems, and IoT. Understanding ARM is crucial for mobile security and embedded exploitation.

---

## General-Purpose Registers

| Register | Alias | Purpose | Preserved? |
|----------|-------|---------|------------|
| **R0** | - | 1st argument, return value | No |
| **R1** | - | 2nd argument | No |
| **R2** | - | 3rd argument | No |
| **R3** | - | 4th argument | No |
| **R4-R10** | - | General purpose | Yes (callee-saved) |
| **R11** | **FP** | Frame Pointer | Yes |
| **R12** | **IP** | Intra-Procedure-call scratch | No |
| **R13** | **SP** | Stack Pointer | Yes |
| **R14** | **LR** | Link Register (return address) | Special |
| **R15** | **PC** | Program Counter | N/A |

### Special Registers

| Register | Description | Exploitation Impact |
|----------|-------------|---------------------|
| **PC (R15)** | Program Counter | **Primary exploit target** (like EIP/RIP) |
| **LR (R14)** | Link Register | Stores return address (can be corrupted) |
| **SP (R13)** | Stack Pointer | Points to top of stack |
| **CPSR** | Current Program Status Register | Flags (N, Z, C, V) |

---

## ARM vs x86 Register Comparison

| Purpose | ARM | x86 | x64 |
|---------|-----|-----|-----|
| **1st Argument** | R0 | Stack | RDI (Linux) / RCX (Win) |
| **2nd Argument** | R1 | Stack | RSI (Linux) / RDX (Win) |
| **3rd Argument** | R2 | Stack | RDX (Linux) / R8 (Win) |
| **4th Argument** | R3 | Stack | RCX (Linux) / R9 (Win) |
| **Return Value** | R0 | EAX | RAX |
| **Stack Pointer** | SP (R13) | ESP | RSP |
| **Program Counter** | PC (R15) | EIP | RIP |
| **Return Address** | LR (R14) | Stack | Stack |

---

## Calling Convention (AAPCS - ARM Architecture Procedure Call Standard)

**Argument Passing:**
- First 4 arguments in **R0-R3**
- Remaining arguments on **stack**
- Return value in **R0** (32-bit) or **R0:R1** (64-bit)

**Example:**
```c
int add(int a, int b, int c, int d, int e) {
    return a + b + c + d + e;
}

int result = add(1, 2, 3, 4, 5);
```

**Assembly (ARM):**
```asm
; Caller
mov    r0, #1       ; 1st arg
mov    r1, #2       ; 2nd arg
mov    r2, #3       ; 3rd arg
mov    r3, #4       ; 4th arg
mov    r4, #5
push   {r4}         ; 5th arg on stack
bl     add          ; Branch with Link (saves return address in LR)
add    sp, sp, #4   ; Clean up stack

; Callee
add:
    push   {r4, lr}     ; Save callee-saved registers + return address
    
    add    r0, r0, r1   ; a + b
    add    r0, r0, r2   ; + c
    add    r0, r0, r3   ; + d
    ldr    r4, [sp, #8] ; Load 5th arg from stack
    add    r0, r0, r4   ; + e
    
    pop    {r4, pc}     ; Restore registers and return (PC = LR)
```

**Stack Layout:**
```
High Memory
┌─────────────────────────────┐
│  5th argument (5)           │  [SP+8] (after push {r4, lr})
├─────────────────────────────┤
│  Saved LR (return address)  │  [SP+4]
├─────────────────────────────┤  ← SP
│  Saved R4                   │  [SP]
└─────────────────────────────┘
Low Memory

Note: First 4 args in R0-R3 (not on stack)
```

---

## Instruction Set

### ARM Mode (32-bit instructions)

| Instruction | Description | Example |
|-------------|-------------|---------|
| `mov Rd, Op` | Move data | `mov r0, #42` |
| `ldr Rd, [Rn]` | Load from memory | `ldr r0, [sp]` |
| `str Rd, [Rn]` | Store to memory | `str r0, [sp, #4]` |
| `push {Rx}` | Push registers | `push {r4, lr}` |
| `pop {Rx}` | Pop registers | `pop {r4, pc}` |
| `add Rd, Rn, Op` | Addition | `add r0, r0, r1` |
| `sub Rd, Rn, Op` | Subtraction | `sub sp, sp, #16` |
| `bl label` | Branch with Link (call) | `bl printf` |
| `bx Rm` | Branch and exchange | `bx lr` (return) |
| `cmp Rn, Op` | Compare (sets flags) | `cmp r0, #0` |
| `beq label` | Branch if equal | `beq success` |
| `bne label` | Branch if not equal | `bne fail` |

### Thumb Mode (16-bit instructions)

- **Thumb:** Compressed instruction set (16-bit)
- **Thumb-2:** Mix of 16-bit and 32-bit instructions
- **Switching:** `bx` instruction (LSB of target address determines mode)

```asm
; ARM mode
mov    r0, #1
bx     thumb_func  ; Switch to Thumb if LSB of address is 1

; Thumb mode
thumb_func:
    movs   r0, #2   ; 16-bit instruction
    bx     lr       ; Return (switch back to ARM if LR LSB is 0)
```

---

## Stack Frame (ARM)

```
Function Prologue:
    push   {r4-r11, lr}  ; Save callee-saved registers + return address
    sub    sp, sp, #N    ; Allocate N bytes for local variables

Function Epilogue:
    add    sp, sp, #N    ; Deallocate local variables
    pop    {r4-r11, pc}  ; Restore registers and return (PC = LR)

Complete Stack Frame:
High Memory
┌─────────────────────────────┐
│  Arguments 5+ (if any)      │  [SP+40], [SP+44], ...
├─────────────────────────────┤
│  Saved LR (return address)  │  [SP+36] ← Exploit target!
│  Saved R11 (FP)             │  [SP+32]
│  Saved R10                  │  [SP+28]
│  ...                        │
│  Saved R4                   │  [SP]
├─────────────────────────────┤  ← SP (after prologue)
│  Local Variables            │
└─────────────────────────────┘
Low Memory
```

---

## Exploitation Considerations

### 1. Return Address in LR

```asm
vulnerable_func:
    push   {r4, lr}      ; Save LR on stack
    sub    sp, sp, #64   ; Allocate buffer
    
    mov    r0, sp        ; Buffer address
    bl     gets          ; Unbounded read!
    
    add    sp, sp, #64
    pop    {r4, pc}      ; Pops corrupted LR into PC!
```

**Overflow Target:**
- Overwrite saved LR on stack
- When `pop {r4, pc}` executes, PC = corrupted LR

### 2. Cache Coherency (Shellcode)

```python
# ARM shellcode may require cache flush
# Instruction cache (I-cache) vs Data cache (D-cache)
# Self-modifying code or JIT requires cache synchronization
```

### 3. Endianness

- **Little-Endian:** Most ARM systems (default)
- **Big-Endian:** Some embedded systems

```python
# Little-endian (default)
p32(0x12345678) → b'\x78\x56\x34\x12'

# Big-endian (rare)
p32(0x12345678, endian='big') → b'\x12\x34\x56\x78'
```

### 4. NULL Byte Constraints

```asm
; Avoid NULL bytes in shellcode
mov    r0, #0        ; Contains NULL: 00 00 A0 E3
; Better:
eor    r0, r0, r0    ; XOR (no NULLs): 00 00 00 E0 (still has NULLs!)
; Best:
sub    r0, r0, r0    ; SUB (no NULLs): 00 00 40 E0
```

---

## ROP Gadgets (ARM)

```asm
; Typical ROP gadget
pop    {r4, pc}      ; Load r4 and jump to next gadget

; Chaining gadgets
payload = b"A" * 72
payload += p32(gadget1)  ; pop {r0, pc}
payload += p32(arg1)     ; Value for r0
payload += p32(gadget2)  ; pop {r1, pc}
payload += p32(arg2)     ; Value for r1
payload += p32(system)   ; Final target
```

---

## Further Reading

- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/)
- [ARM Exploitation (Azeria Labs)](https://azeria-labs.com/writing-arm-assembly-part-1/)
- [ARM64 Architecture](../ARM64/)
