#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Object structure with function pointer
typedef struct {
    char name[32];
    void (*print_func)(char *);
} User;

// Legitimate print function
void safe_print(char *name) {
    printf("User: %s\n", name);
}

// Malicious function (simulates attacker goal)
void evil_function(char *name) {
    printf("[!] EXPLOIT: Executing arbitrary code!\n");
    system("/bin/sh");  // Spawn shell
}

int main() {
    User *user1, *user2;
    char input[32];
    
    // Allocate user object
    user1 = (User *)malloc(sizeof(User));
    strcpy(user1->name, "Alice");
    user1->print_func = safe_print;
    
    printf("User created: %s\n", user1->name);
    user1->print_func(user1->name);  // Normal execution
    
    // VULNERABILITY: Free the object
    free(user1);
    printf("[*] User object freed\n");
    
    // Simulate attacker input (reallocates freed memory)
    printf("Enter new user name: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;  // Remove newline
    
    // Allocate new object (likely reuses freed chunk)
    user2 = (User *)malloc(sizeof(User));
    strcpy(user2->name, input);
    user2->print_func = evil_function;  // Attacker controls this!
    
    // VULNERABILITY: Use the old pointer (dangling)
    printf("[*] Calling function via old pointer...\n");
    user1->print_func(user1->name);  // Uses freed memory!
    
    return 0;
}
