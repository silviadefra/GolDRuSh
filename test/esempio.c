#include <stdio.h>

int f(int x) {
    int result;
    result= x+ 2;
    printf("Result: %d\n", result);
    return result;
}

int g(int x) {
    int result;
    result= x + 5;
    return result;
}

int main() {
    int x;
    int y;
    printf("Enter an integer: ");
    scanf("%d", &x);
    y=x+2;
    if (y > 5) {
        int result = f(x);
        printf("%p\n",f);
        
    } else {
        int result = g(x);
        
    }

    return 0;
}

