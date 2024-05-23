#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *vuln(char *str, long len) {
  char *buf = (char *) malloc(16);
  strncpy(buf, str, len);
  return buf;
}

char *cncp(char *str) {
  int n = strlen(str);
  char *copy = "";
  if (n < 16 || str[7] == 'x') { 
    copy = vuln(str, n); }
  return copy;
}

int test(char *str) {
  char t;
  strncpy(&t, str, 1);
  return t == 'y' || t == 'z';
}

int main(int argc, char **argv) {
  int i;
  for (i = 1; i < argc; ++i) {
    char *copy = cncp(argv[i]);
    if (test(copy)) return 1; 
  }
}