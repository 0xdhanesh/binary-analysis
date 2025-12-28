# x64 Architecture (64-bit Intel/AMD)

## Overview

The **x64 architecture** (also known as x86-64, AMD64, or Intel 64) extends x86 to 64-bit, providing larger address space, more registers, and improved performance. It's the dominant architecture for modern desktop and server systems.

---

## General-Purpose Registers

| Register | Size | Purpose | Preserved? | x86 Equivalent |
|----------|------|---------|------------|----------------|
| **RAX** | 64-bit | Accumulator, return value | No | EAX |
| **RBX** | 64-bit | General purpose | Yes | EBX |
| **RCX** | 64-bit | 4th argument (Windows), counter | No | ECX |
| **RDX** | 64-bit | 3rd argument (Windows), data | No | EDX |
| **RSI** | 64-bit | 2nd argument (Linux), source index | No (Linux) | ESI |
| **RDI** | 64-bit | 1st argument (Linux), dest index | No (Linux) | EDI |
| **RBP** | 64-bit | Base pointer (stack frame) | Yes | EBP |
| **RSP** | 64-bit | Stack pointer | Yes | ESP |
| **R8-R15** | 64-bit | Additional general-purpose registers | Varies | N/A |

### Extended Registers (R8-R15)

| Register | Preserved? | Purpose (Linux) | Purpose (Windows) |
|----------|------------|-----------------|-------------------|
| **R8** | No | 5th argument | 3rd argument |
| **R9** | No | 6th argument | 4th argument |
| **R10** | No | Temporary | Temporary |
| **R11** | No | Temporary | Temporary |
| **R12-R15** | Yes | General purpose | General purpose |

### Register Hierarchy (64-bit)

```
RAX (64-bit): [                    EAX (32-bit)                    ]
               [                     AX (16-bit)                     ]
               [              AH (8-bit) | AL (8-bit)               ]

Example:
RAX = 0x0123456789ABCDEF
EAX = 0x89ABCDEF (lower 32 bits)
AX  = 0xCDEF (lower 16 bits)
AL  = 0xEF (lower 8 bits)
AH  = 0xCD (bits 8-15)

R8 (64-bit):  [                    R8D (32-bit)                    ]
               [                     R8W (16-bit)                    ]
               [                              R8B (8-bit)           ]
```

---

## Calling Conventions

### System V AMD64 ABI (Linux, macOS, BSD)

**Argument Passing:**
| Argument | Register | Type |
|----------|----------|------|
| 1st | **RDI** | Integer/pointer |
| 2nd | **RSI** | Integer/pointer |
| 3rd | **RDX** | Integer/pointer |
| 4th | **RCX** | Integer/pointer |
| 5th | **R8** | Integer/pointer |
| 6th | **R9** | Integer/pointer |
| 7th+ | Stack | Right-to-left |

**Floating Point:**
- XMM0-XMM7 for first 8 FP arguments

**Return Value:**
- **RAX** (integer/pointer)
- **XMM0** (floating point)

**Example:**
```c
long add(long a, long b, long c, long d, long e, long f, long g) {
    return a + b + c + d + e + f + g;
}

long result = add(1, 2, 3, 4, 5, 6, 7);
```

**Assembly (System V):**
```asm
; Caller
mov    rdi, 1      ; 1st arg
mov    rsi, 2      ; 2nd arg
mov    rdx, 3      ; 3rd arg
mov    rcx, 4      ; 4th arg
mov    r8, 5       ; 5th arg
mov    r9, 6       ; 6th arg
push   7           ; 7th arg (on stack)
call   add
add    rsp, 8      ; Clean up stack (1 arg × 8 bytes)

; Callee
add:
    push   rbp
    mov    rbp, rsp
    
    mov    rax, rdi       ; a
    add    rax, rsi       ; + b
    add    rax, rdx       ; + c
    add    rax, rcx       ; + d
    add    rax, r8        ; + e
    add    rax, r9        ; + f
    add    rax, [rbp+16]  ; + g (from stack)
    
    pop    rbp
    ret
```

**Stack Layout (System V):**
```
High Memory
┌─────────────────────────────┐
│  7th argument (7)           │  [RBP+16]
├─────────────────────────────┤
│  Return Address             │  [RBP+8]
├─────────────────────────────┤  ← RBP
│  Saved RBP                  │  [RBP]
├─────────────────────────────┤  ← RSP
│  Local Variables            │
└─────────────────────────────┘
Low Memory

Note: First 6 args in registers (RDI, RSI, RDX, RCX, R8, R9)
```

---

### Microsoft x64 Calling Convention (Windows)

**Argument Passing:**
| Argument | Register | Type |
|----------|----------|------|
| 1st | **RCX** | Integer/pointer |
| 2nd | **RDX** | Integer/pointer |
| 3rd | **R8** | Integer/pointer |
| 4th | **R9** | Integer/pointer |
| 5th+ | Stack | Right-to-left |

**Shadow Space:**
- Caller **must** allocate 32 bytes (4 × 8) on stack for callee to spill registers
- Even if function has < 4 parameters!

**Assembly (Windows):**
```asm
; Caller
sub    rsp, 40        ; Allocate shadow space (32) + alignment (8)
mov    rcx, 1         ; 1st arg
mov    rdx, 2         ; 2nd arg
mov    r8, 3          ; 3rd arg
mov    r9, 4          ; 4th arg
mov    QWORD PTR [rsp+32], 5   ; 5th arg (above shadow space)
call   add
add    rsp, 40        ; Clean up

; Callee
add:
    ; Can use [rsp+8] to [rsp+32] to save RCX, RDX, R8, R9
    mov    rax, rcx
    add    rax, rdx
    add    rax, r8
    add    rax, r9
    add    rax, [rsp+40]  ; 5th arg
    ret
```

**Stack Layout (Windows):**
```
High Memory
┌─────────────────────────────┐
│  5th argument               │  [RSP+40] (after prologue)
├─────────────────────────────┤
│  Shadow space (32 bytes)    │  [RSP+8] to [RSP+32]
│  (for RCX, RDX, R8, R9)     │
├─────────────────────────────┤
│  Return Address             │  [RSP]
└─────────────────────────────┘
Low Memory
```

---

## Comparison: x86 vs x64

| Feature | x86 (32-bit) | x64 (64-bit) |
|---------|--------------|--------------|
| **Address Space** | 4 GB (2³²) | 16 EB (2⁶⁴ theoretical, 256 TB practical) |
| **Registers** | 8 GPRs (EAX-EDI, ESP, EBP) | 16 GPRs (RAX-R15, RSP, RBP) |
| **Pointer Size** | 4 bytes | 8 bytes |
| **Instruction Pointer** | EIP | RIP |
| **Calling Convention** | Stack-based (cdecl) | Register-based (first 6 args) |
| **Stack Alignment** | 4-byte | 16-byte |
| **RIP-Relative Addressing** | No | Yes (PIE support) |

---

## RIP-Relative Addressing

**x64 introduces position-independent code:**
```asm
; x86 (absolute addressing)
mov    eax, [0x08048000]  ; Hardcoded address

; x64 (RIP-relative)
mov    rax, [rip+0x1000]  ; Relative to current instruction
```

**Exploitation Impact:**
- Enables PIE (Position Independent Executable)
- Requires address leaks for exploitation
- ROP gadgets must be found dynamically

---

## Stack Frame (x64)

```
Function Prologue:
    push   rbp
    mov    rbp, rsp
    sub    rsp, N      ; Allocate N bytes (N must be 16-byte aligned!)

Function Epilogue:
    leave              ; mov rsp, rbp; pop rbp
    ret

Complete Stack Frame:
High Memory
┌─────────────────────────────┐
│  Arguments 7+ (if any)      │  [RBP+16], [RBP+24], ...
├─────────────────────────────┤
│  Return Address             │  [RBP+8] ← Exploit target!
├─────────────────────────────┤  ← RBP
│  Saved RBP                  │  [RBP]
├─────────────────────────────┤
│  Local Variables            │  [RBP-8], [RBP-16], ...
├─────────────────────────────┤  ← RSP (16-byte aligned)
│  Unused Stack Space         │
└─────────────────────────────┘
Low Memory
```

---

## Exploitation Considerations

### 1. Larger Addresses (8 bytes)

```python
# x86 payload
payload = b"A" * 44 + p32(0x08048000)  # 4-byte address

# x64 payload
payload = b"A" * 72 + p64(0x7ffff7a0d000)  # 8-byte address
```

### 2. NULL Bytes in Addresses

```
x64 addresses often contain NULL bytes:
0x00007ffff7a0d000
  ^^^^
  
Workaround: Use partial overwrites or ROP
```

### 3. Register-Based Arguments

```asm
; Shellcode must set up registers for execve()
mov    rdi, address_of_binsh  ; 1st arg: filename
xor    rsi, rsi               ; 2nd arg: argv (NULL)
xor    rdx, rdx               ; 3rd arg: envp (NULL)
mov    rax, 59                ; syscall number (execve)
syscall
```

---

## Further Reading

- [System V AMD64 ABI](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)
- [Microsoft x64 Calling Convention](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [x64 Shellcoding](../../vulnerabilities/Stack_Overflow/)
