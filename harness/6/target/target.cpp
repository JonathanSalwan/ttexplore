// clang++ -g -O0 -fsanitize=fuzzer,memory target.cpp

#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const char* data, size_t size) {
  if (size < 4)
    return 0;
  uint32_t r = ((uint32_t*)data)[0];
  if ((r * 2) == 0xdeadbef0)
    __builtin_trap();
  return 0;
}

//int main() {
//  return 0;
//}
