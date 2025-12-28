# 📖 Binary Analysis Bible: The Definitive Guide

> **"To understand the program, you must become the processor."**
> 
> This document serves as the comprehensive "bible" for binary analysis. It is designed to take a reader from basic binary identification to advanced exploitation theory, focusing on methodology, tools, and deep-dive techniques.

---

## 📑 Table of Contents
1. [Binary Foundations](#-i-binary-foundations)
2. [Security Mitigations](#-ii-security-mitigations)
3. [Static Analysis: Ghidra Deep Dive](#-iii-static-analysis-ghidra-deep-dive)
4. [Dynamic Analysis: Runtime Inspection](#-iv-dynamic-analysis-runtime-inspection)
5. [Exploitation Theory](#-v-exploitation-theory)
6. [The Canon: Curated Reading List](#-vi-the-canon-curated-reading-list)

---

## 🛠 I. Binary Foundations

Before touching a debugger, you must classify your target.

### 1. File Identification
```bash
file target_binary
```
- **ELF (Executable and Linkable Format):** Standard for Linux.
- **PE (Portable Executable):** Standard for Windows.
- **Mach-O:** Standard for macOS.

### 2. Architecture & Word Size
- **x86 (32-bit):** Uses `eax`, `ebx`, `ecx`, etc. Parameters passed via **stack**.
- **x86-64 (64-bit):** Uses `rax`, `rbx`, `rcx`, etc. Parameters passed via **registers** (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`).
- **ARM/AArch64:** RISC architecture, common in mobile and IoT.

### 3. Stripped vs. Not Stripped
- **Stripped:** Debugging symbols and function names are removed. Analysis requires manual renaming and logic reconstruction.
- **Not Stripped:** Original function names (`main`, `validate_password`) are preserved. "Easy mode" for analysis.

---

## 🛡 II. Security Mitigations

Understanding what stands in your way is crucial for exploit development.

| Mitigation | Goal | Bypass Strategy |
| :--- | :--- | :--- |
| **NX / DEP** | No-Executable stack/heap. | **ROP (Return Oriented Programming)**. |
| **ASLR** | Randomizes memory addresses on every run. | **Information Leak** (leak a libc address). |
| **Stack Canary** | Detects stack buffer overflows before function return. | **Leak canary** or **Overwrite hook** (if available). |
| **PIE** | Randomizes the base address of the binary itself. | **Leak binary base** address. |
| **RELRO** | Marks the GOT (Global Offset Table) as read-only. | **Full RELRO:** Target heap hooks or stack. **Partial:** Target GOT. |

---

## 🔍 III. Static Analysis: Ghidra Deep Dive

Ghidra is your primary tool for understanding code without running it.

### 1. The Control Flow Graph (CFG)
The CFG is the "map" of a function. It shows all possible execution paths.

- **Basic Blocks:** Rectangles containing a sequence of instructions with no jumps in or out (except at the end).
- **Edges:** Lines connecting blocks representing jumps/branches.
    - **Green:** Conditional jump taken.
    - **Red:** Conditional jump not taken.
    - **Blue:** Unconditional jump.

> [!TIP]
> Use the **Graph View** (`Window -> Function Graph`) in Ghidra to spot logic loops, "if-else" structures, and switch statements instantly.

### 2. Decompilation
Ghidra's decompiler attempts to turn assembly back into C-like code.
- **Methodology:**
    1. **Rename Variables:** Right-click variables (e.g., `iVar1` -> `buffer_ptr`) to make logic clear.
    2. **Define Data Types:** Fix types (e.g., `int` -> `struct user_data*`) to clean up structure access.
    3. **Identify Sinks:** Locate calls to `strcpy`, `system`, or `fgets`.

### 3. XREFS (Cross-References)
Select a function or string and press `L` to see everywhere it is used. This is the fastest way to trace user input to a dangerous "sink".

---

## ⚡ IV. Dynamic Analysis: Runtime Inspection

Static analysis tells you what *could* happen; dynamic analysis tells you what *is* happening.

### 1. GDB (with GEF or Pwndbg)
- `vmmap`: View memory permissions and base addresses (Essential for ASLR/PIE).
- `telescope $rsp`: View the stack and what the pointers point to.
- `search -8 "flag"`: Search memory for specific strings.

### 2. Tracing
- `strace`: Trace system calls (I/O, network, memory allocation).
- `ltrace`: Trace library calls (String comparisons, printing).

---

## 💣 V. Exploitation Theory

### 1. The Stack Frame
Understanding how `call` and `ret` work is the foundation of stack smashing.
- `call` pushes the **Return Address** onto the stack.
- `ret` pops the value off the stack into the Instruction Pointer (EIP/RIP).

### 2. ROP (Return Oriented Programming)
When NX is enabled, you can't run shellcode on the stack. Instead, you stitch together existing snippets of code ("gadgets") followed by a `ret` instruction.
```asm
pop rdi; ret  <-- Gadget 1
0xdeadbeef    <-- Argument
call system   <-- Target function
```

---

## � VI. Standard Analysis Workflow (The "Bible" Checklist)

Follow this sequence for every binary you encounter:

1.  **Recon:** `file`, `checksec`, `strings`.
2.  **Behavioral:** `strace`, `ltrace`, run the binary with dummy input.
3.  **Static Entry:** Find `main`. Rename variables and identify function signatures.
4.  **Trace Input:** Follow data from `stdin` or `argv` to use-sites.
5.  **Identify Sinks:** Watch for exploitable functions (`strcpy`, `system`).
6.  **Dynamic Triage:** Use GDB to set breakpoints at sinks. Observe register state.
7.  **PoC:** Craft a payload to control the instruction pointer.

---

## �📚 VII. The Canon: Curated Reading List

To truly master binary analysis, you must study the classics.

### 🌟 Core Reading (The "Bible" Books)
1. **"Practical Malware Analysis"** by Michael Sikorski & Andrew Honig. (The gold standard for methodology).
2. **"The Art of Software Security Assessment"** by Mark Dowd et al. (The "Old Testament" of bug hunting).
3. **"Binary Analysis Cookbook"** by Alexey Zakharov. (Modern recipes for Ghidra and Radare2).

### 🌐 High-Signal Blogs & Sites
- **[LiveOverflow](https://youtube.com/liveoverflow):** Excellent visual explanations of complex topics.
- **[Aon Cyber Labs (formerly iSEC)](https://www.aon.com/en/capabilities/cyber-solutions):** Deep technical whitepapers.
- **[Project Zero Blog](https://googleprojectzero.blogspot.com/):** For the most advanced, cutting-edge exploitation techniques.
- **[CTFtime](https://ctftime.org/writeups):** Read writeups for challenges you *haven't* solved.

### 📜 Landmark Papers
- **"Smashing The Stack For Fun And Profit"** by Aleph One (Phrack 49).
- **"The Geometry of Innocent Flesh on the Bone"** (The original ROP paper).

---
*Created by Antigravity for elite security research.*
