#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

uint32_t crc32(uint8_t *s, size_t n) {
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < n; i++) {
    char ch = s[i];
    for (size_t j = 0; j < 8; j++) {
      uint32_t b = (ch ^ crc) & 1;
      crc >>= 1;
      if (b) crc = crc ^ 0xEDB88320;
      ch >>= 1;
    }
  }
  return ~crc;
}

#define bail(msg, pos)                                         \
  while (1) {                                                  \
    fprintf(stderr, "%s at %u\n", (char *)msg, (uint32_t)pos); \
    return pos;                                                \
  }

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  uint32_t *p32, crc, i;
  uint8_t   buff[40];

  if (len < 36)
    bail("too short", 0);

  // libfuzzer workaround
  memcpy(buff, buf, 36);
  buff[36] = 0;

  if (buff[0] != 'B') bail("wrong char", 0);
  if (buff[1] != 'A') bail("wrong char", 1);
  if (buff[2] != 'R') bail("wrong char", 2);
  if (buff[3] != 'F') bail("wrong char", 3);
  for (i = 1; i < 4; i++) {
    buff[i * 4 - 1] = 'E' + i;  // no duplicate crc
    crc = crc32(buff, i * 4);
    p32 = (uint32_t *)(buff + i * 4);
    printf("Expecting: %x\n", crc);
    if (*p32 != crc) bail("wrong crc32", (i * 4));
  }
}

int main(int argc, char **argv) {
}
