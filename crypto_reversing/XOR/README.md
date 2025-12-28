# XOR Cipher Analysis

## Overview

**XOR (Exclusive OR)** is one of the most common encryption primitives in malware and CTF challenges. Understanding XOR properties is essential for reverse engineering obfuscated code and encrypted data.

---

## XOR Properties

### Mathematical Properties

| Property | Formula | Example |
|----------|---------|---------|
| **Commutative** | `A ⊕ B = B ⊕ A` | `0x41 ⊕ 0x55 = 0x55 ⊕ 0x41` |
| **Associative** | `(A ⊕ B) ⊕ C = A ⊕ (B ⊕ C)` | - |
| **Identity** | `A ⊕ 0 = A` | `0x41 ⊕ 0x00 = 0x41` |
| **Self-Inverse** | `A ⊕ A = 0` | `0x41 ⊕ 0x41 = 0x00` |
| **Reversible** | `(A ⊕ B) ⊕ B = A` | `(0x41 ⊕ 0x55) ⊕ 0x55 = 0x41` |

**Exploitation Insight:**
```
Plaintext ⊕ Key = Ciphertext
Ciphertext ⊕ Key = Plaintext  (Decryption is same as encryption!)
```

---

## Common XOR Patterns

### 1. Single-Byte XOR

**Encryption:**
```python
def xor_encrypt(plaintext, key):
    return bytes([b ^ key for b in plaintext])

plaintext = b"SECRET"
key = 0x42
ciphertext = xor_encrypt(plaintext, key)
# Result: b'\x11\x07\x01\x10\x07\x14'
```

**Identification:**
- **Frequency Analysis:** XOR preserves character frequency
- **Known Plaintext:** If you know part of plaintext, recover key

**Breaking:**
```python
# Brute-force all 256 possible keys
def break_single_byte_xor(ciphertext):
    for key in range(256):
        plaintext = bytes([b ^ key for b in ciphertext])
        # Check if plaintext is readable (heuristic: count printable chars)
        if all(32 <= b < 127 for b in plaintext):
            print(f"Key: {hex(key)}, Plaintext: {plaintext}")

break_single_byte_xor(b'\x11\x07\x01\x10\x07\x14')
# Output: Key: 0x42, Plaintext: b'SECRET'
```

---

### 2. Multi-Byte (Repeating Key) XOR

**Encryption:**
```python
def xor_encrypt_multi(plaintext, key):
    return bytes([plaintext[i] ^ key[i % len(key)] for i in range(len(plaintext))])

plaintext = b"ATTACK AT DAWN"
key = b"KEY"
ciphertext = xor_encrypt_multi(plaintext, key)
```

**Identification:**
- **Repeating Patterns:** Ciphertext has periodic structure
- **Index of Coincidence:** Statistical test for key length

**Breaking (Kasiski Examination):**
```python
# 1. Find repeating sequences in ciphertext
# 2. Calculate distances between repetitions
# 3. GCD of distances = likely key length
# 4. Break into single-byte XOR problems

from collections import Counter

def find_key_length(ciphertext, max_keylen=20):
    # Hamming distance method
    distances = []
    for keylen in range(2, max_keylen):
        chunks = [ciphertext[i:i+keylen] for i in range(0, len(ciphertext), keylen)]
        if len(chunks) < 2:
            continue
        dist = sum(bin(chunks[0][j] ^ chunks[1][j]).count('1') 
                   for j in range(min(len(chunks[0]), len(chunks[1]))))
        distances.append((dist / keylen, keylen))
    
    distances.sort()
    return distances[0][1]  # Return most likely key length
```

---

### 3. Known Plaintext Attack

**Scenario:** You know part of the plaintext (e.g., file header, magic bytes)

```python
# Known: PNG file header
known_plaintext = b'\x89PNG\r\n\x1a\n'
ciphertext = b'\xc9\x10\x0e\x07\x6d\x6e\x7a\x68...'

# Recover key
key = bytes([known_plaintext[i] ^ ciphertext[i] for i in range(len(known_plaintext))])
print(f"Key: {key}")  # b'@@@@@@@@@'

# Decrypt entire file
plaintext = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
```

---

## Reverse Engineering XOR in Assembly

### x86 Assembly Pattern

```asm
; Single-byte XOR loop
xor_loop:
    mov    al, [esi]        ; Load byte from source
    xor    al, 0x42         ; XOR with key (0x42)
    mov    [edi], al        ; Store encrypted byte
    inc    esi              ; Next source byte
    inc    edi              ; Next destination byte
    loop   xor_loop         ; Repeat ECX times
```

**Identification:**
- Look for `xor` instruction in loops
- Key is often immediate value (`xor al, 0x42`) or loaded from memory

### x64 Assembly Pattern

```asm
; Multi-byte XOR with SIMD (SSE)
movdqu xmm0, [rsi]         ; Load 16 bytes of plaintext
movdqu xmm1, [key_addr]    ; Load 16 bytes of key
pxor   xmm0, xmm1          ; XOR 16 bytes in parallel
movdqu [rdi], xmm0         ; Store ciphertext
```

---

## Automated XOR Analysis

### Using xortool

```bash
# Install
pip install xortool

# Analyze ciphertext
xortool -l 3 ciphertext.bin  # Assume key length 3
xortool -c 20 ciphertext.bin # Assume most common char is space (0x20)

# Output: Possible keys and decrypted files
```

### Python Script (Comprehensive)

```python
#!/usr/bin/env python3
import string

def score_plaintext(data):
    """Score plaintext based on English character frequency"""
    freq = {
        'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
        'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99
    }
    score = 0
    for byte in data.lower():
        char = chr(byte) if byte < 128 else ''
        score += freq.get(char, 0)
    return score

def break_xor(ciphertext, keylen=None):
    if keylen is None:
        # Try all key lengths 1-20
        for klen in range(1, 21):
            key = []
            for i in range(klen):
                # Extract every klen-th byte
                block = ciphertext[i::klen]
                
                # Brute-force single-byte XOR
                best_score = 0
                best_key = 0
                for k in range(256):
                    plaintext = bytes([b ^ k for b in block])
                    score = score_plaintext(plaintext)
                    if score > best_score:
                        best_score = score
                        best_key = k
                
                key.append(best_key)
            
            # Decrypt with found key
            plaintext = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
            
            # Check if plaintext is readable
            if all(32 <= b < 127 or b in [9, 10, 13] for b in plaintext[:100]):
                print(f"[+] Key length: {klen}")
                print(f"[+] Key: {bytes(key)}")
                print(f"[+] Plaintext: {plaintext[:200]}")
                return bytes(key), plaintext
    
    return None, None

# Usage
with open('encrypted.bin', 'rb') as f:
    ciphertext = f.read()

key, plaintext = break_xor(ciphertext)
```

---

## Real-World Examples

### 1. Malware String Obfuscation

```c
// Obfuscated malware code
char encrypted[] = "\x11\x07\x01\x10\x07\x14";
char key = 0x42;

void decrypt_strings() {
    for (int i = 0; i < sizeof(encrypted); i++) {
        encrypted[i] ^= key;
    }
    // encrypted now contains "SECRET"
    system(encrypted);  // Execute command
}
```

**Reverse Engineering:**
1. Find XOR loop in disassembly
2. Extract key (0x42)
3. Decrypt strings statically

---

### 2. CTF Challenge (RC4-like)

```python
# Pseudo-random key stream
def prng_xor(plaintext, seed):
    key_stream = []
    state = seed
    for _ in range(len(plaintext)):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        key_stream.append(state & 0xFF)
    
    return bytes([plaintext[i] ^ key_stream[i] for i in range(len(plaintext))])
```

**Breaking:**
- If seed is weak (e.g., timestamp), brute-force
- If known plaintext exists, recover key stream

---

## Detection Signatures

### IDA Pro / Ghidra

**Search for XOR patterns:**
```
1. Find all XOR instructions
2. Check if operand is constant (immediate value)
3. Look for loops around XOR
4. Identify encrypted data sections
```

### Binary Ninja

```python
# Binary Ninja script to find XOR encryption
for func in bv.functions:
    for block in func.low_level_il:
        for insn in block:
            if insn.operation == LowLevelILOperation.LLIL_XOR:
                print(f"XOR at {hex(insn.address)}: {insn}")
```

---

## Key Takeaways

1. **XOR is symmetric:** Encryption = Decryption
2. **Weak against known plaintext:** Key recovery is trivial
3. **Frequency analysis works:** Character distribution preserved
4. **Common in malware:** String obfuscation, config encryption
5. **Easy to identify:** Look for XOR instructions in loops

---

## Further Reading

- [Cryptopals Challenges (Set 1)](https://cryptopals.com/)
- [XOR Analysis Tutorial](https://github.com/hellman/xortool)
