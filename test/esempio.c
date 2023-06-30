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
    /*printf("Result: %d\n", result);*/
    return result;
}

int main(int x) {
    int y;
    y=x+2;
    if (y > 5) {
        int result = f(x);
        
    } else {
        int result = g(x);
        
    }

    return 0;
}

