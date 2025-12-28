# ARM64 / AArch64 Architecture

## Overview

**ARM64** (also called **AArch64**) is the 64-bit execution state of the ARM architecture. It's used in modern mobile devices (iPhone, Android flagships), Apple Silicon Macs, and cloud servers (AWS Graviton).

---

## General-Purpose Registers

| Register | Size | Purpose | Preserved? | ARM32 Equivalent |
|----------|------|---------|------------|------------------|
| **X0-X7** | 64-bit | Arguments & return values | No | R0-R7 |
| **X8** | 64-bit | Indirect result location | No | - |
| **X9-X15** | 64-bit | Temporary registers | No | - |
| **X16-X17** | 64-bit | Intra-procedure-call (IP0, IP1) | No | R12 (IP) |
| **X18** | 64-bit | Platform register | Special | - |
| **X19-X28** | 64-bit | Callee-saved registers | Yes | R4-R11 |
| **X29** | 64-bit | Frame Pointer (FP) | Yes | R11 (FP) |
| **X30** | 64-bit | Link Register (LR) | Special | R14 (LR) |
| **SP** | 64-bit | Stack Pointer | Yes | R13 (SP) |
| **PC** | 64-bit | Program Counter | N/A | R15 (PC) |

### Register Aliasing

```
X0 (64-bit): [                    W0 (32-bit)                    ]

Example:
X0 = 0x0123456789ABCDEF
W0 = 0x89ABCDEF (lower 32 bits)

Using W0 zeros upper 32 bits:
mov w0, #42  → X0 = 0x000000000000002A
```

---

## Special Registers

| Register | Description | Exploitation Impact |
|----------|-------------|---------------------|
| **PC** | Program Counter | **Primary exploit target** (like EIP/RIP) |
| **LR (X30)** | Link Register | Stores return address (can be corrupted) |
| **SP** | Stack Pointer | Points to top of stack |
| **FP (X29)** | Frame Pointer | Base of stack frame |

---

## Calling Convention (AAPCS64)

### Argument Passing

| Argument | Register | Type |
|----------|----------|------|
| 1st | **X0** | Integer/pointer |
| 2nd | **X1** | Integer/pointer |
| 3rd | **X2** | Integer/pointer |
| 4th | **X3** | Integer/pointer |
| 5th | **X4** | Integer/pointer |
| 6th | **X5** | Integer/pointer |
| 7th | **X6** | Integer/pointer |
| 8th | **X7** | Integer/pointer |
| 9th+ | Stack | Right-to-left |

**Return Value:**
- **X0** (64-bit integer/pointer)
- **X0:X1** (128-bit value)

### Example Function Call

```c
long add(long a, long b, long c, long d, long e, long f, long g, long h, long i) {
    return a + b + c + d + e + f + g + h + i;
}

long result = add(1, 2, 3, 4, 5, 6, 7, 8, 9);
```

**Assembly (ARM64):**
```asm
; Caller
mov    x0, #1       ; 1st arg
mov    x1, #2       ; 2nd arg
mov    x2, #3       ; 3rd arg
mov    x3, #4       ; 4th arg
mov    x4, #5       ; 5th arg
mov    x5, #6       ; 6th arg
mov    x6, #7       ; 7th arg
mov    x7, #8       ; 8th arg
mov    x8, #9
str    x8, [sp]     ; 9th arg on stack
bl     add          ; Branch with Link (saves return address in LR)

; Callee
add:
    stp    x29, x30, [sp, #-16]!  ; Save FP and LR
    mov    x29, sp                ; Set frame pointer
    
    add    x0, x0, x1   ; a + b
    add    x0, x0, x2   ; + c
    add    x0, x0, x3   ; + d
    add    x0, x0, x4   ; + e
    add    x0, x0, x5   ; + f
    add    x0, x0, x6   ; + g
    add    x0, x0, x7   ; + h
    ldr    x8, [sp, #16]; Load 9th arg
    add    x0, x0, x8   ; + i
    
    ldp    x29, x30, [sp], #16  ; Restore FP and LR
    ret                         ; Return (PC = LR)
```

---

## Stack Frame

```
Function Prologue:
    stp    x29, x30, [sp, #-16]!  ; Save FP and LR, decrement SP
    mov    x29, sp                ; Set FP to current SP
    sub    sp, sp, #N             ; Allocate N bytes for locals

Function Epilogue:
    mov    sp, x29                ; Restore SP
    ldp    x29, x30, [sp], #16    ; Restore FP and LR, increment SP
    ret                           ; Return (PC = LR)

Complete Stack Frame:
High Memory
┌─────────────────────────────────────┐
│  Arguments 9+ (if any)              │  [SP+16], [SP+24], ...
├─────────────────────────────────────┤
│  Saved LR (return address)          │  [SP+8] ← Exploit target!
├─────────────────────────────────────┤  ← FP (X29)
│  Saved FP                           │  [SP]
├─────────────────────────────────────┤
│  Local Variables                    │  [SP-8], [SP-16], ...
├─────────────────────────────────────┤  ← SP
│  Unused Stack Space                 │
└─────────────────────────────────────┘
Low Memory
```

---

## Common Instructions

| Instruction | Description | Example |
|-------------|-------------|---------|
| `mov Xd, Xn` | Move register | `mov x0, x1` |
| `ldr Xt, [Xn]` | Load from memory | `ldr x0, [sp]` |
| `str Xt, [Xn]` | Store to memory | `str x0, [sp, #8]` |
| `ldp Xt1, Xt2, [Xn]` | Load pair | `ldp x29, x30, [sp]` |
| `stp Xt1, Xt2, [Xn]` | Store pair | `stp x29, x30, [sp, #-16]!` |
| `add Xd, Xn, Xm` | Addition | `add x0, x0, x1` |
| `sub Xd, Xn, Xm` | Subtraction | `sub sp, sp, #16` |
| `bl label` | Branch with Link (call) | `bl printf` |
| `blr Xn` | Branch with Link to Register | `blr x8` |
| `ret` | Return (PC = LR) | `ret` |
| `br Xn` | Branch to Register | `br x0` |
| `cmp Xn, Xm` | Compare (sets flags) | `cmp x0, #0` |
| `b.eq label` | Branch if equal | `b.eq success` |
| `b.ne label` | Branch if not equal | `b.ne fail` |

---

## ARM64 vs ARM32 Comparison

| Feature | ARM32 | ARM64 |
|---------|-------|-------|
| **Registers** | 16 (R0-R15) | 31 (X0-X30) + SP |
| **Register Size** | 32-bit | 64-bit |
| **Arguments** | R0-R3 (4 args) | X0-X7 (8 args) |
| **Return Address** | LR (R14) | LR (X30) |
| **Instruction Set** | ARM/Thumb | AArch64 only (no Thumb) |
| **Pointer Size** | 4 bytes | 8 bytes |
| **Stack Alignment** | 4-byte | 16-byte |

---

## Exploitation Considerations

### 1. Return Address in LR

```asm
vulnerable_func:
    stp    x29, x30, [sp, #-16]!  ; Save LR on stack
    sub    sp, sp, #64            ; Allocate buffer
    
    mov    x0, sp                 ; Buffer address
    bl     gets                   ; Unbounded read!
    
    add    sp, sp, #64
    ldp    x29, x30, [sp], #16    ; Pops corrupted LR!
    ret                           ; PC = corrupted LR
```

**Overflow Target:**
- Overwrite saved LR on stack
- When `ret` executes, PC = corrupted LR

### 2. Pointer Authentication Codes (PAC)

**Modern ARM64 (iOS, macOS) uses PAC:**

```asm
; Function prologue with PAC
pacibsp                    ; Sign LR with SP
stp    x29, x30, [sp, #-16]!

; Function epilogue with PAC
ldp    x29, x30, [sp], #16
retab                      ; Authenticate LR before return
```

**Exploitation:**
- PAC signs return addresses with cryptographic key
- Corrupted LR fails authentication → Crash
- **Bypass:** Leak PAC key or use gadgets without PAC

### 3. 16-Byte Stack Alignment

**Stack must be 16-byte aligned at function calls:**

```python
# ARM64 exploit
payload = b"A" * offset
payload += p64(gadget1)  # Must maintain 16-byte alignment!
payload += p64(gadget2)
```

### 4. NULL Bytes in Addresses

```
ARM64 addresses (userspace):
0x0000000100000000 - 0x00007FFFFFFFFFFF
      ^^^^
      NULL bytes!

Workaround: Use partial overwrites or ROP
```

---

## ROP Gadgets (ARM64)

### Common Gadgets

```asm
; Load arguments
ldp x0, x1, [sp], #16; ret   ; Load X0 and X1 from stack
ldr x0, [sp], #8; ret         ; Load X0 from stack

; Call functions
blr x8; ret                   ; Call function in X8
br x9                         ; Jump to X9 (no return)

; Stack pivot
mov sp, x0; ret               ; Set SP to X0
add sp, sp, #0x100; ret       ; Adjust SP
```

### ROP Chain Example

```python
# ARM64 ROP to call system("/bin/sh")
from pwn import *

binary = ELF('./vuln_arm64')
rop = ROP(binary)

# Find gadgets
ldr_x0_sp = rop.find_gadget(['ldr x0, [sp]', 'ret'])[0]
blr_x8 = rop.find_gadget(['blr x8', 'ret'])[0]

# Build chain
payload = b"A" * offset
payload += p64(ldr_x0_sp)        # ldr x0, [sp]; ret
payload += p64(binsh_addr)       # X0 = "/bin/sh"
payload += p64(blr_x8)           # blr x8 (X8 = system)
```

---

## iOS/macOS Specific

### 1. Objective-C Runtime

```asm
; Objective-C method call
adrp   x0, _OBJC_CLASSLIST_REFERENCES_$_@PAGE
ldr    x0, [x0, _OBJC_CLASSLIST_REFERENCES_$_@PAGEOFF]
adrp   x1, _OBJC_SELECTOR_REFERENCES_@PAGE
ldr    x1, [x1, _OBJC_SELECTOR_REFERENCES_@PAGEOFF]
bl     _objc_msgSend
```

### 2. Kernel Exploitation

**ARM64 kernel uses different exception levels:**
- **EL0:** Userspace
- **EL1:** Kernel
- **EL2:** Hypervisor
- **EL3:** Secure Monitor

---

## CTF Tips

### 1. Identifying ARM64 Binaries

```bash
file binary
# Output: ELF 64-bit LSB executable, ARM aarch64, ...

readelf -h binary | grep Machine
# Output: Machine: AArch64
```

### 2. Cross-Compilation

```bash
# Install cross-compiler
sudo apt install gcc-aarch64-linux-gnu

# Compile for ARM64
aarch64-linux-gnu-gcc -o vuln_arm64 vuln.c -static
```

### 3. Emulation (QEMU)

```bash
# Install QEMU
sudo apt install qemu-user

# Run ARM64 binary on x86
qemu-aarch64 ./vuln_arm64
```

### 4. Debugging (GDB)

```bash
# GDB with ARM64 support
gdb-multiarch ./vuln_arm64

(gdb) set architecture aarch64
(gdb) break *main
(gdb) run
(gdb) info registers  # View X0-X30, SP, PC
```

---

## Further Reading

- [ARM Architecture Reference Manual (ARMv8)](https://developer.arm.com/documentation/ddi0487/latest)
- [AAPCS64 Calling Convention](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
- [iOS Kernel Exploitation](https://googleprojectzero.blogspot.com/2019/08/a-very-deep-dive-into-ios-exploit.html)
- [Pointer Authentication on ARM64](https://github.com/apple/llvm-project/blob/apple/main/clang/docs/PointerAuthentication.rst)

---

**Related:** [ARM (32-bit)](../ARM/) | [MIPS](../MIPS/)
