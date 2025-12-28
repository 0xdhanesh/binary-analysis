# Dangling Pointers

## Overview

A **dangling pointer** is a pointer that continues to reference memory after that memory has been deallocated or the object's lifetime has ended. Unlike Use-After-Free (which specifically involves heap memory), dangling pointers can occur with stack variables, static memory, or any scope-based allocation.

---

## Vulnerable C Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Returns pointer to local variable (DANGEROUS!)
char* get_user_input() {
    char buffer[64];  // Stack-allocated
    printf("Enter username: ");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    
    return buffer;  // VULNERABILITY: Returns pointer to stack memory!
}

// Dangling pointer via scope
int* create_counter() {
    int count = 42;  // Stack variable
    return &count;   // VULNERABILITY: Pointer to local variable
}

int main() {
    char *username;
    int *counter;
    
    // Case 1: Stack-based dangling pointer
    username = get_user_input();
    printf("Username stored at: %p\n", username);
    
    // Stack frame of get_user_input() is now destroyed
    // username points to deallocated stack memory
    
    // Trigger stack reuse
    printf("Calling another function...\n");
    counter = create_counter();
    
    // username now points to corrupted memory
    printf("Username (corrupted): %s\n", username);  // Undefined behavior!
    printf("Counter value: %d\n", *counter);  // Also dangling!
    
    return 0;
}
```

### Compilation
```bash
gcc -o dangling dangling.c -no-pie -fno-stack-protector -Wno-return-local-addr
```

---

## Memory State Visualization

### During get_user_input() Execution

```
Stack Memory (High → Low addresses)
┌─────────────────────────────────────┐
│  main() stack frame                 │
│  ┌─────────────────────────────┐    │
│  │ username: 0x0 (uninitialized)│   │
│  │ counter: 0x0                │    │
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤
│  get_user_input() stack frame       │
│  ┌─────────────────────────────┐    │
│  │ Return address              │    │
│  │ Saved EBP                   │    │
│  │ buffer[64]: "Alice\0..."    │    │  ← Function returns this address!
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

### After get_user_input() Returns

```
Stack Memory
┌─────────────────────────────────────┐
│  main() stack frame                 │
│  ┌─────────────────────────────┐    │
│  │ username: 0x7ffc1234abcd    │    │  ← Points to freed stack memory!
│  │ counter: 0x0                │    │
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤
│  DEALLOCATED MEMORY                 │
│  ┌─────────────────────────────┐    │
│  │ (old buffer location)       │    │  ← username still points here
│  │ Contains: "Alice\0..." OR   │    │     but memory may be reused!
│  │ Contains: garbage data      │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

### After create_counter() Execution

```
Stack Memory
┌─────────────────────────────────────┐
│  main() stack frame                 │
│  ┌─────────────────────────────┐    │
│  │ username: 0x7ffc1234abcd    │    │  ← DANGLING (points to reused memory)
│  │ counter: 0x7ffc1234abc0     │    │  ← DANGLING (points to freed int)
│  └─────────────────────────────┘    │
├─────────────────────────────────────┤
│  REUSED STACK SPACE                 │
│  ┌─────────────────────────────┐    │
│  │ Old buffer now contains:    │    │
│  │ - Return address remnants   │    │
│  │ - Saved registers           │    │  ← username reads garbage here!
│  │ - count variable (42)       │    │  ← counter points here
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘

Reading username: Undefined behavior (may crash or read garbage)
Reading *counter: May still show 42, or corrupted value
```

---

## Exploitation Scenario

### Vulnerable Code (Real-World Pattern)

```c
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int id;
    char name[32];
} User;

User* current_user = NULL;

void login(int user_id) {
    User temp_user;  // Stack-allocated
    temp_user.id = user_id;
    sprintf(temp_user.name, "User_%d", user_id);
    
    current_user = &temp_user;  // VULNERABILITY: Dangling pointer!
    printf("Logged in as: %s\n", current_user->name);
}

void check_admin() {
    // current_user points to deallocated stack memory!
    if (current_user->id == 1337) {
        printf("[!] ADMIN ACCESS GRANTED\n");
        system("/bin/sh");
    } else {
        printf("Access denied for user %d\n", current_user->id);
    }
}

int main() {
    login(1000);  // Sets current_user to stack address
    
    // Stack frame reused here
    int admin_id = 1337;  // Overwrites old temp_user.id location!
    
    check_admin();  // Reads corrupted current_user->id (may be 1337!)
    return 0;
}
```

### Memory Corruption Flow

```
1. login() executes:
   - temp_user allocated on stack at 0x7ffc1000
   - current_user = 0x7ffc1000 (dangling!)
   
2. login() returns:
   - Stack frame destroyed
   - current_user still points to 0x7ffc1000
   
3. main() continues:
   - admin_id allocated at 0x7ffc1000 (SAME LOCATION!)
   - admin_id = 1337
   
4. check_admin() executes:
   - Reads current_user->id from 0x7ffc1000
   - Finds value 1337 (admin_id variable!)
   - Grants admin access!
```

---

## Detection Methods

### Static Analysis (Compiler Warnings)

```bash
gcc -Wall -Wextra -Wreturn-local-addr dangling.c
# Warning: function returns address of local variable
```

### Dynamic Analysis (AddressSanitizer)

```bash
gcc -fsanitize=address -g dangling.c -o dangling_asan
./dangling_asan

# Output:
# ERROR: AddressSanitizer: stack-use-after-return
# READ of size 1 at 0x7f1234567890
```

### Valgrind

```bash
valgrind --tool=memcheck ./dangling
# Invalid read of size 1
# Address 0x... is ... bytes inside a block of size ... free'd
```

---

## Mitigation Techniques

| Technique | Implementation | Effectiveness |
|-----------|----------------|---------------|
| **Static Analysis** | `-Wreturn-local-addr` | Catches obvious cases |
| **Dynamic Sanitizers** | `-fsanitize=address` | Runtime detection |
| **Smart Pointers** | C++ `std::unique_ptr` | Automatic lifetime management |
| **Nullify on Free** | `ptr = NULL` after scope | Prevents use |
| **Heap Allocation** | Use `malloc()` instead of stack | Manual lifetime control |

---

## Correct Implementation

```c
// Option 1: Heap allocation
char* get_user_input_safe() {
    char *buffer = malloc(64);  // Heap-allocated
    fgets(buffer, 64, stdin);
    return buffer;  // Caller must free()
}

// Option 2: Caller-provided buffer
void get_user_input_safe2(char *buffer, size_t size) {
    fgets(buffer, size, stdin);
    // No return, caller owns buffer
}

// Option 3: Static storage
char* get_user_input_safe3() {
    static char buffer[64];  // Static lifetime
    fgets(buffer, sizeof(buffer), stdin);
    return buffer;  // Valid until next call
}
```

---

## Key Takeaways

1. **Root Cause:** Returning/storing pointers to local variables
2. **Impact:** Undefined behavior, potential arbitrary read/write
3. **Detection:** Compiler warnings, ASAN, Valgrind
4. **Difference from UAF:** Stack-based vs heap-based
5. **Defense:** Heap allocation, static storage, or caller-provided buffers

---

## Further Reading

- [CWE-825: Expired Pointer Dereference](https://cwe.mitre.org/data/definitions/825.html)
- [Stack Memory Management](../../architecture/Memory_Layout/)
