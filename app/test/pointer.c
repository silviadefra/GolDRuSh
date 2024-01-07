#include <stdio.h>
#include <stdlib.h>

void checkPointerAndPrintError(void *ptr) {
    if (ptr == NULL) {
        printf("Error: Pointer is NULL\n");
    }
}

int main(int argc, char *argv[]) {
    
    // Convert the argument to a pointer value
    char *endptr;
    unsigned long int addr = strtoul(argv[1], &endptr, 16);
    void *ptr = (void *)addr;


    // Check the pointer and print error if necessary
    checkPointerAndPrintError(ptr);

    return 0;
}