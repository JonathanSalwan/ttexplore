// https://raw.githubusercontent.com/AFLplusplus/fuzzer-challenges/main/test-strcmp.c

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define bail(msg, pos)                                         \
  while (1) {                                                  \
    return 0;                                                  \
  }

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  uint8_t *p8;

  if (len < 28) bail("too short", 0);
  if (strncasecmp((char *)buf, "0123", 4)) bail("wrong string", 0);
  if (strncasecmp((char *)buf + 4, "87654321", 8)) bail("wrong string", 4);
  if (strncasecmp((char *)buf + 12, "ABCDEFHIKLMNOPQR", 16))
    bail("wrong string", 12);
  if (len < 54) bail("too short", 0);
  if (strncasecmp((char *)buf + 28, "ZYXWVUTSRQPONMLKJIHGFEDCBA", 26))
    bail("wrong string", 28);

  return 1;
}

//int main() {}
