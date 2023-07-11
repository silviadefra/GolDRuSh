#include <stdio.h>
#include <string.h>

int f(const char* str) {
    if (strcmp(str, "hello") == 0) {
        int result = strlen(str) + 2;
        printf("Result: %d\n", result);
        return result;
        } else {
        return 0;
        }
}

int g(const char* str) {
    int result = strlen(str) + 5;
    /*printf("Result: %d\n", result);*/
    return result;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        /*printf("No input string provided.\n");*/
        return 1;
    }

    char* input = argv[1];

    if (strlen(input) > 3) {
        int result = f(input);
        // Use the result if needed
    } else {
        int result = g(input);
        // Use the result if needed
    }

    return 0;
}

