#include <stdio.h>
#include <string.h>

void vulnerable_function(char *user_input) {
    char buffer[64];  // 64-byte buffer on the stack
    
    // VULNERABILITY: No bounds checking!
    strcpy(buffer, user_input);  // Copies unlimited data
    
    printf("You entered: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    vulnerable_function(argv[1]);
    
    printf("Execution completed normally.\n");
    return 0;
}
