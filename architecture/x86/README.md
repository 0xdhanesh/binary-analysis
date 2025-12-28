# x86 Architecture (32-bit Intel)

## Overview

The **x86 architecture** (also known as IA-32) is a 32-bit CISC (Complex Instruction Set Computer) architecture developed by Intel. Understanding x86 is fundamental for binary exploitation, as it's still widely used in embedded systems and legacy applications.

---

## General-Purpose Registers

| Register | Size | Purpose | Preserved Across Calls? |
|----------|------|---------|-------------------------|
| **EAX** | 32-bit | Accumulator (return values, arithmetic) | No (caller-saved) |
| **EBX** | 32-bit | Base register (general purpose) | Yes (callee-saved) |
| **ECX** | 32-bit | Counter (loop iterations, string ops) | No (caller-saved) |
| **EDX** | 32-bit | Data register (I/O, arithmetic) | No (caller-saved) |
| **ESI** | 32-bit | Source Index (string/array operations) | Yes (callee-saved) |
| **EDI** | 32-bit | Destination Index (string/array ops) | Yes (callee-saved) |
| **EBP** | 32-bit | Base Pointer (stack frame base) | Yes (callee-saved) |
| **ESP** | 32-bit | Stack Pointer (top of stack) | Yes (callee-saved) |

### Register Hierarchy

```
EAX (32-bit): [        AX (16-bit)        ]
               [  AH (8-bit) | AL (8-bit) ]

Example:
EAX = 0x12345678
AX  = 0x5678 (lower 16 bits)
AH  = 0x56 (high byte of AX)
AL  = 0x78 (low byte of AX)
```

---

## Special Registers

| Register | Purpose |
|----------|---------|
| **EIP** | Instruction Pointer (program counter) - **Primary exploit target** |
| **EFLAGS** | Status flags (Zero, Carry, Sign, Overflow, etc.) |
| **CS, DS, SS, ES, FS, GS** | Segment registers (rarely used in modern flat memory model) |

---

## Calling Conventions

### 1. cdecl (C Declaration - Default for C)

**Characteristics:**
- Arguments pushed **right-to-left** onto stack
- Caller cleans up stack
- Return value in **EAX**

**Example:**
```c
int add(int a, int b, int c) {
    return a + b + c;
}

int result = add(1, 2, 3);
```

**Assembly:**
```asm
; Caller (main)
push   3           ; Push c (rightmost argument first)
push   2           ; Push b
push   1           ; Push a
call   add
add    esp, 12     ; Caller cleans up stack (3 args × 4 bytes)
mov    [result], eax  ; Store return value

; Callee (add function)
add:
    push   ebp         ; Save old frame pointer
    mov    ebp, esp    ; Set new frame pointer
    
    mov    eax, [ebp+8]   ; Load a (1st argument)
    add    eax, [ebp+12]  ; Add b (2nd argument)
    add    eax, [ebp+16]  ; Add c (3rd argument)
    
    pop    ebp         ; Restore frame pointer
    ret                ; Return (EAX contains result)
```

**Stack Layout:**
```
High Addresses
┌─────────────────────┐
│  c = 3              │  [EBP+16]
├─────────────────────┤
│  b = 2              │  [EBP+12]
├─────────────────────┤
│  a = 1              │  [EBP+8]
├─────────────────────┤
│  Return Address     │  [EBP+4]
├─────────────────────┤  ← EBP
│  Saved EBP          │  [EBP]
├─────────────────────┤  ← ESP
│  Local Variables    │
└─────────────────────┘
Low Addresses
```

---

### 2. stdcall (Standard Call - Windows API)

**Characteristics:**
- Arguments pushed **right-to-left**
- **Callee** cleans up stack
- Return value in **EAX**

**Assembly:**
```asm
; Caller
push   3
push   2
push   1
call   add
; No stack cleanup! Callee does it.

; Callee
add:
    push   ebp
    mov    ebp, esp
    ; ... function body ...
    pop    ebp
    ret    12      ; Return and clean 12 bytes (3 args × 4)
```

---

### 3. fastcall (Fast Call - Optimized)

**Characteristics:**
- First 2 arguments in **ECX** and **EDX**
- Remaining arguments on stack (right-to-left)
- Callee cleans up stack
- Return value in **EAX**

**Assembly:**
```asm
; Caller
push   3           ; 3rd argument on stack
mov    edx, 2      ; 2nd argument in EDX
mov    ecx, 1      ; 1st argument in ECX
call   add

; Callee
add:
    push   ebp
    mov    ebp, esp
    
    mov    eax, ecx       ; a (from ECX)
    add    eax, edx       ; b (from EDX)
    add    eax, [ebp+8]   ; c (from stack)
    
    pop    ebp
    ret    4              ; Clean 1 arg from stack
```

---

## Stack Frame Anatomy

```
Function Prologue:
    push   ebp         ; Save caller's frame pointer
    mov    ebp, esp    ; Establish new frame pointer
    sub    esp, N      ; Allocate N bytes for local variables

Function Epilogue:
    mov    esp, ebp    ; Restore stack pointer
    pop    ebp         ; Restore caller's frame pointer
    ret                ; Pop return address into EIP

Alternative (single instruction):
    leave              ; Equivalent to: mov esp, ebp; pop ebp
    ret
```

**Complete Stack Frame:**
```
High Memory
┌─────────────────────────────┐
│  Function Arguments         │  [EBP+8], [EBP+12], ...
├─────────────────────────────┤
│  Return Address             │  [EBP+4] ← Exploit target!
├─────────────────────────────┤  ← EBP (Frame Pointer)
│  Saved EBP                  │  [EBP]
├─────────────────────────────┤
│  Local Variable 1           │  [EBP-4]
│  Local Variable 2           │  [EBP-8]
│  ...                        │
│  Buffer[64]                 │  [EBP-72] to [EBP-8]
├─────────────────────────────┤  ← ESP (Stack Pointer)
│  Unused Stack Space         │
└─────────────────────────────┘
Low Memory

Stack grows downward (ESP decreases)
```

---

## Common Instructions

| Instruction | Description | Example |
|-------------|-------------|---------|
| `mov dst, src` | Move data | `mov eax, 42` |
| `push src` | Push onto stack (ESP -= 4) | `push eax` |
| `pop dst` | Pop from stack (ESP += 4) | `pop ebx` |
| `call addr` | Call function (push EIP, jump) | `call printf` |
| `ret` | Return (pop EIP) | `ret` |
| `add dst, src` | Addition | `add eax, ebx` |
| `sub dst, src` | Subtraction | `sub esp, 0x20` |
| `xor dst, src` | XOR operation | `xor eax, eax` (zero EAX) |
| `cmp op1, op2` | Compare (sets flags) | `cmp eax, 0` |
| `jmp addr` | Unconditional jump | `jmp 0x8048000` |
| `je addr` | Jump if equal (ZF=1) | `je success` |
| `jne addr` | Jump if not equal (ZF=0) | `jne fail` |
| `lea dst, src` | Load effective address | `lea eax, [ebp-8]` |

---

## Exploitation Considerations

### 1. Return Address Overwrite

```asm
vulnerable_func:
    push   ebp
    mov    ebp, esp
    sub    esp, 64        ; 64-byte buffer
    
    lea    eax, [ebp-64]  ; Buffer address
    push   eax
    call   gets           ; Unbounded read!
    
    leave
    ret                   ; Pops corrupted address into EIP!
```

### 2. Register State at Crash

```bash
(gdb) info registers
eax            0x41414141  1094795585
ebx            0x0         0
ecx            0xffffcf10  -12528
edx            0xf7fc5580  -134568576
esi            0x1         1
edi            0xf7fc4000  -134574080
ebp            0x41414141  0x41414141  ← Corrupted!
esp            0xffffcf50  0xffffcf50
eip            0x41414141  0x41414141  ← Controlled!
```

### 3. Shellcode Constraints

- **32-bit addresses:** 4 bytes (e.g., `0x08048000`)
- **NULL bytes:** Avoid `\x00` (terminates strings)
- **Bad characters:** Depends on input method (e.g., `\n`, `\r`, `\x20`)

---

## Further Reading

- [Intel® 64 and IA-32 Architectures Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [x86 Assembly Guide (University of Virginia)](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html)
- [Calling Conventions Comparison](../x64/README.md#calling-conventions)
