/*
**  This program is under the terms of the BSD License.
**  Jonathan Salwan - 2022-07-09
*/

int foo(const char* b) {
  return strcmp(b, "working") == 0;
}

int main(int ac, const char *av[]) {
  return foo(av[1]);
}
