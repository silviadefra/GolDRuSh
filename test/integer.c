#include <stdio.h>
#include <unistd.h>
#include <stdlib.h> 
#include <fcntl.h>

int main(int argc, char *argv[])
{
    int fd;
    int size;
    int len= atoi(argv[1]);

    if (len > 8000) {return 0; }
    char *buf = (char*) malloc(len *sizeof(char));
    size=len+10;
    read(STDIN_FILENO, buf, len * sizeof(int)); 
    return 0;
}
