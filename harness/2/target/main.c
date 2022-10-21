
int foo(const char *b) {
  switch (b[0]) {
    case 0x11:
      if (b[1] + b[2] == b[3])
        return 1;
      break;
    case 0x12:
      if (b[1] - b[2] == b[3])
        return 1;
      break;
    case 0x13:
      if (b[1] *  b[2] == b[3])
        return 1;
      break;
    case 0x14:
      if (b[1] ^  b[2] == b[3])
        return 1;
      break;
    case 0x15:
      if (b[1] <<  b[2] == b[3])
        return 1;
      break;
    case 0x30:
      if (b[1] && b[2]) {
        switch (b[b[3]]) {
          case 1:  return 1;
          case 2:  return 2;
          case 6:  return 6;
          case 9:  return 9;
          default: return 0;
        }
      }
      break;
    case 0x47:
      if (b[b[4]] == b[b[3]])
        return 10;
      break;
  }
  return -1;
}

int main(int ac, const char *av[]) {
  return foo(av[1]);
}
