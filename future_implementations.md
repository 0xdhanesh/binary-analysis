# Binary Exploitation Mastery - Future Implementations

This document serves as a roadmap and implementation guide for expanding the repository. It is designed to be "AI-friendly," providing clear technical requirements and structural templates for future vulnerability modules.

---

## 🏗 Standard Module Structure

Every new vulnerability implementation MUST follow this directory structure within the `vulnerabilities/` folder:

```text
vulnerabilities/       # Core exploitation techniques
│   ├── future_implementation_name/ 
|          |----- vulnerable_code.c
|          |----- exploit.py      # exploit code
|          |----- README.md       # explanation
```

### Module Requirements
1. **README.md**:
   - **Theory**: Conceptual explanation of the vulnerability.
   - **Comparison Table**: How it differs from similar bugs.
   - **ASCII Diagrams**: MUST include "Normal Memory State" vs. "Corrupted Memory State".
   - **Assembly Emulation**: Intel syntax snippet showing the critical instruction (e.g., `mov [rax], rdx` for arbitrary write).
2. **vulnerable_code.c**:
   - Self-contained and minimal.
   - Must include a comment with the exact `gcc` compilation command (e.g., `-fno-stack-protector -no-pie`).
3. **exploit.py**:
   - Use `pwntools`.
   - Explain the "Why" behind every value (offsets, addresses).
   - Support multiple architectures where applicable (x86/x64/ARM/MIPS).

---

## 📝 Implementation Backlog

### I. Spatial Safety Violations (Bounds)
- [ ] **Global/BSS Buffer Overflow**: Overflowing fixed-size buffers in the `.data` or `.bss` segments.
- [ ] **Off-by-One Error (Stack)**: Typical `i <= length` loop errors allowing 1-byte overwrite.
- [ ] **Off-by-One Error (Heap)**: Poison-byte attacks or top-chunk corruption via single byte.
- [ ] **Index Out of Bounds (OOB)**: Arbitrary read/write via unchecked array indices.
- [ ] **Non-Terminated String**: String splicing attacks or information leaks.

### II. Arithmetic & Integer Violations
- [ ] **Integer Overflow/Underflow**: Bypassing size checks via wrapping.
- [ ] **Integer Signedness Error**: Exploiting transitions between `signed int` and `unsigned int`.
- [ ] **Integer Truncation**: Precision loss during type casting (e.g., `long` to `int`).
- [ ] **Pointer Arithmetic Overflow**: Manipulating pointers to wrap around memory space.

### III. Temporal Safety Violations (Lifecycle)
- [ ] **Double Free**: Freeing the same chunk twice to trigger freelist cycles.
- [ ] **Use-After-Return**: Accessing stack memory of a returned function.
- [ ] **Use-After-Scope**: Accessing local variables after they go out of scope.
- [ ] **Invalid Free**: Passing non-malloc'd pointers to `free()`.

### IV. Glibc/Ptmalloc Specific (Advanced Heap)
- [ ] **Tcache Poisoning**: Overwriting `next` pointers in tcache bins.
- [ ] **Fastbin Duplication**: Creating cycles in the fastbin freelist.
- [ ] **House of Force**: Corrupting top chunk `size` to reach arbitrary memory.
- [ ] **House of Spirit**: Creating fake chunks on the stack.
- [ ] **House of Orange**: Exploiting `_IO_FILE` structures via the heap.
- [ ] **Safe Unlinking Bypass**: Bypassing `FD->bk == P` checks.

### V. Type & Logic Confusion
- [ ] **C++ Type Confusion**: Exploiting polymorphic objects with incorrect casts.
- [ ] **vTable Pointer (vptr) Overwrite**: Hijacking C++ virtual function calls.
- [ ] **Uninitialized Variables**: Leaking sensitive data or controlling execution flow via stack residue.

### VI. Interpretation & JIT (Browser Specific)
- [ ] **JIT Bounds Check Elimination**: Tricking the JIT compiler into removing valid checks.
- [ ] **Prototype Pollution**: Corrupting object shapes in managed languages.

---

## 🤖 AI Continuation Instructions

If you are tasked with implementing any of the above:
1. **Selection**: Pick one item from the backlog.
2. **Context**: Check `architecture/Memory_Layout/README.md` to ensure the memory model is consistent.
3. **Drafting**: Create the folder and initial `README.md` first to define the attack surface.
4. **Implementation**: Ensure `vulnerable_code.c` is compiled and tested with specific security flags disabled to allow for a reliable PoC.
5. **Verification**: Document the exploit success in the `walkthrough.md` for this session.

---
*Status: Initial Backlog Generated on 2025-12-29.*
