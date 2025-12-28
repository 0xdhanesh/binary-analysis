# AES ECB Pattern Recognition

## Overview

**AES ECB (Electronic Codebook) mode** is a block cipher mode that encrypts each block independently. This creates recognizable patterns in encrypted data, making it vulnerable to analysis and a common target in CTF challenges and malware reverse engineering.

---

## Why ECB is Weak

### The Problem: Identical Plaintext → Identical Ciphertext

```
Plaintext:  [Block 1] [Block 2] [Block 1] [Block 3]
            ↓         ↓         ↓         ↓
ECB Key:    [Key]     [Key]     [Key]     [Key]
            ↓         ↓         ↓         ↓
Ciphertext: [Cipher1] [Cipher2] [Cipher1] [Cipher3]
                                 ↑
                        Same as first block!
```

**Key Insight:** Repeated plaintext blocks produce repeated ciphertext blocks!

---

## Visual Pattern Recognition

### The Famous ECB Penguin

**Original Image:**
```
[Penguin with solid colors]
```

**ECB Encrypted:**
```
[Penguin outline still visible due to repeated color blocks]
```

**CBC Encrypted:**
```
[Complete noise - no pattern visible]
```

**Why?** Large areas of same color (same plaintext) → Same ciphertext in ECB mode

---

## Detecting ECB Mode

### Method 1: Block Repetition Analysis

```python
def detect_ecb(ciphertext, block_size=16):
    """Detect ECB mode by finding repeated blocks"""
    blocks = [ciphertext[i:i+block_size] 
              for i in range(0, len(ciphertext), block_size)]
    
    # Count unique blocks
    unique_blocks = len(set(blocks))
    total_blocks = len(blocks)
    
    # If many repeated blocks, likely ECB
    repetition_rate = 1 - (unique_blocks / total_blocks)
    
    if repetition_rate > 0.1:  # More than 10% repetition
        print(f"[!] ECB detected! Repetition rate: {repetition_rate:.2%}")
        return True
    return False

# Example usage
with open('encrypted.bin', 'rb') as f:
    ciphertext = f.read()

if detect_ecb(ciphertext):
    print("[+] This is likely AES-ECB encrypted data")
```

### Method 2: Statistical Analysis

```python
from collections import Counter

def analyze_block_frequency(ciphertext, block_size=16):
    """Analyze frequency of ciphertext blocks"""
    blocks = [ciphertext[i:i+block_size] 
              for i in range(0, len(ciphertext), block_size)]
    
    # Count block frequencies
    freq = Counter(blocks)
    
    # Find most common blocks
    most_common = freq.most_common(5)
    
    print("[*] Most common blocks:")
    for block, count in most_common:
        print(f"  {block.hex()}: {count} times")
    
    # If top block appears many times, likely ECB
    if most_common[0][1] > 3:
        return True
    return False
```

---

## Exploitation Techniques

### 1. Byte-at-a-Time ECB Decryption (Oracle Attack)

**Scenario:** You can encrypt arbitrary data, and the server appends a secret

```python
#!/usr/bin/env python3
"""
ECB Byte-at-a-Time Attack
Decrypt secret suffix one byte at a time
"""

from pwn import *

def oracle_encrypt(data):
    """Send data to encryption oracle, get ciphertext back"""
    # In CTF, this would be a network connection
    p.sendline(data)
    return p.recvline().strip()

def detect_block_size():
    """Find AES block size (usually 16)"""
    initial_len = len(oracle_encrypt(b""))
    
    for i in range(1, 64):
        length = len(oracle_encrypt(b"A" * i))
        if length > initial_len:
            return length - initial_len
    return 16

def ecb_decrypt_byte_at_a_time():
    """Decrypt secret suffix byte by byte"""
    block_size = detect_block_size()
    print(f"[+] Block size: {block_size}")
    
    secret = b""
    
    # For each byte position in secret
    for position in range(100):  # Assume max 100 bytes
        # Create padding to align secret byte at end of block
        padding_len = (block_size - 1 - position) % block_size
        padding = b"A" * padding_len
        
        # Get ciphertext with our padding + secret
        target_block_idx = position // block_size
        target_cipher = oracle_encrypt(padding)
        target_block = target_cipher[target_block_idx*block_size:(target_block_idx+1)*block_size]
        
        # Brute-force the byte
        for byte_val in range(256):
            test_input = padding + secret + bytes([byte_val])
            test_cipher = oracle_encrypt(test_input)
            test_block = test_cipher[target_block_idx*block_size:(target_block_idx+1)*block_size]
            
            if test_block == target_block:
                secret += bytes([byte_val])
                print(f"[+] Found byte {position}: {chr(byte_val) if 32 <= byte_val < 127 else '?'}")
                break
        else:
            # No match found, probably end of secret
            break
    
    print(f"\n[+] Decrypted secret: {secret}")
    return secret

# Usage
# p = remote('ctf.example.com', 1337)
# ecb_decrypt_byte_at_a_time()
```

### 2. ECB Cut-and-Paste Attack

**Scenario:** Encrypt user-controlled data in ECB mode

```python
def ecb_cut_and_paste():
    """
    Create admin account by rearranging encrypted blocks
    
    Normal encryption:
    Block 1: "email=user@ex"
    Block 2: "ample.com&role="
    Block 3: "user............"  (padded)
    
    Crafted encryption:
    Block 1: "email=attacker"
    Block 2: "@evil.comadmin"  ← "admin" + padding
    Block 3: "............&rol"
    Block 4: "e=user.........."
    
    Cut and paste:
    Block 1 + Block 2 (with admin) + Block 4 = admin account!
    """
    
    # Craft input to get "admin" in its own block
    # Padding to align "admin" at block boundary
    email = "A" * 10 + "admin" + "\x0b" * 11  # PKCS#7 padding
    
    # Encrypt this
    cipher1 = oracle_encrypt(email.encode())
    
    # Extract the block containing "admin" + padding
    admin_block = cipher1[16:32]  # Block 2
    
    # Now create normal user
    normal_cipher = oracle_encrypt(b"user@example.com")
    
    # Replace last block with admin block
    forged_cipher = normal_cipher[:32] + admin_block
    
    return forged_cipher
```

### 3. Padding Oracle Attack (ECB Variant)

```python
def ecb_padding_oracle(ciphertext):
    """
    Use padding oracle to decrypt ECB ciphertext
    Requires oracle that tells if padding is valid
    """
    block_size = 16
    blocks = [ciphertext[i:i+block_size] 
              for i in range(0, len(ciphertext), block_size)]
    
    plaintext = b""
    
    for block_idx in range(len(blocks) - 1, -1, -1):
        block = blocks[block_idx]
        decrypted_block = b""
        
        # Decrypt each byte in block (right to left)
        for byte_pos in range(block_size - 1, -1, -1):
            # Brute-force byte value
            for guess in range(256):
                # Craft malicious block
                padding_value = block_size - byte_pos
                crafted = bytearray(block_size)
                
                # Set known bytes
                for i in range(byte_pos + 1, block_size):
                    crafted[i] = decrypted_block[i - byte_pos - 1] ^ padding_value
                
                # Set guess byte
                crafted[byte_pos] = guess
                
                # Check if padding is valid
                if is_padding_valid(bytes(crafted) + block):
                    decrypted_block = bytes([guess ^ padding_value]) + decrypted_block
                    break
        
        plaintext = decrypted_block + plaintext
    
    return plaintext
```

---

## Real-World Examples

### 1. Malware Configuration Encryption

```python
# Many malware families use ECB for config encryption
def decrypt_malware_config(encrypted_config):
    """
    Decrypt malware config encrypted with AES-ECB
    Key often hardcoded in binary
    """
    from Crypto.Cipher import AES
    
    # Extract key from malware binary (via reverse engineering)
    key = b"\x01\x02\x03...\x10"  # 16 bytes
    
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(encrypted_config)
    
    # Remove PKCS#7 padding
    padding_len = plaintext[-1]
    return plaintext[:-padding_len]
```

### 2. CTF Challenge Pattern

```python
# Common CTF pattern: Image encrypted with ECB
def decrypt_ecb_image():
    """
    Decrypt image encrypted with AES-ECB
    Key recovery via known plaintext (file headers)
    """
    with open('encrypted_image.bin', 'rb') as f:
        ciphertext = f.read()
    
    # PNG header (known plaintext)
    known_plaintext = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
    known_ciphertext = ciphertext[:16]
    
    # Brute-force key (if short) or use other techniques
    # ...
```

---

## Detection in Binaries

### Using Ghidra/IDA

**Look for:**
```c
// ECB mode initialization
AES_set_encrypt_key(key, 128, &aes_key);

// ECB encryption loop
for (i = 0; i < data_len; i += 16) {
    AES_encrypt(data + i, output + i, &aes_key);  // No IV!
}
```

**Red Flags:**
- No IV (Initialization Vector) parameter
- Simple loop encrypting blocks
- No chaining between blocks

### Using Binary Ninja

```python
# Binary Ninja script to find ECB patterns
for func in bv.functions:
    for block in func.low_level_il:
        for insn in block:
            # Look for AES instructions without IV
            if 'aes' in str(insn).lower():
                print(f"Potential AES at {hex(insn.address)}")
```

---

## Mitigation

**Never use ECB mode for:**
- ❌ Encrypting data larger than one block
- ❌ Encrypting images or structured data
- ❌ Any production encryption

**Use instead:**
- ✅ **CBC** (Cipher Block Chaining) - with random IV
- ✅ **CTR** (Counter mode) - with nonce
- ✅ **GCM** (Galois/Counter Mode) - authenticated encryption

---

## CTF Tips

### 1. Quick ECB Detection

```bash
# Hex dump and look for repeated patterns
xxd encrypted.bin | less

# Count unique 16-byte blocks
xxd -p encrypted.bin | fold -w32 | sort | uniq -c | sort -rn
```

### 2. Automated Tools

```bash
# Using CyberChef
# Recipe: "Detect ECB" → Upload file

# Using Python
python3 -c "
from collections import Counter
data = open('encrypted.bin', 'rb').read()
blocks = [data[i:i+16] for i in range(0, len(data), 16)]
print(f'Unique: {len(set(blocks))}/{len(blocks)}')
print(Counter(blocks).most_common(3))
"
```

### 3. Common CTF Scenarios

**Scenario 1:** "Encrypt your username"
- **Attack:** ECB cut-and-paste to forge admin

**Scenario 2:** "Encrypted image provided"
- **Attack:** Visual pattern analysis, known plaintext

**Scenario 3:** "Encryption oracle available"
- **Attack:** Byte-at-a-time decryption

---

## Further Reading

- [Cryptopals Set 2 Challenge 12](https://cryptopals.com/sets/2/challenges/12) - ECB byte-at-a-time
- [ECB Penguin Visualization](https://blog.filippo.io/the-ecb-penguin/)
- [AES Modes of Operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

---

**Related:** [XOR Analysis](../XOR/)
