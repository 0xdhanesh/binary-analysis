// vuln_rop.c - Vulnerable binary for ROP practice
#include <stdio.h>
#include <unistd.h>

// Hidden win function (for beginner practice)
void win() {
    printf("[!] You called win()!\n");
    system("/bin/sh");
}

void vulnerable() {
    char buffer[64];
    printf("Enter input: ");
    fflush(stdout);
    
    // VULNERABILITY: Buffer overflow
    read(0, buffer, 200);  // Reads 200 bytes into 64-byte buffer!
    
    printf("You entered: %s\n", buffer);
}

int main() {
    printf("=== ROP Challenge ===\n");
    printf("Can you get a shell?\n\n");
    
    vulnerable();
    
    printf("Program exiting normally.\n");
    return 0;
}
