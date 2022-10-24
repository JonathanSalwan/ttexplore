# Summary

* [Bootstrapping code coverage on top of Triton](#bootstrapping-code-coverage-on-top-of-triton)
* [Harness your target](#harness-your-target)
* [The output](#output)
* [The corpus](#the-corpus)
* [Sharing corpus between libfuzzer and TTexplore](#sharing-corpus-between-libfuzzer-and-TTexplore)
* [The TTexplore config structure](#the-TTexplore-config-structure)

# Bootstrapping code coverage on top of Triton

[Triton](https://github.com/jonathansalwan/Triton) is a dynamic binary analysis library that aims to provide components
such as dynamic symbolic execution, but lets the user define its own strategy in order to cover code. This repository
aims to provide a bootstrap code for doing path exploration on top of the Triton library. The [TTexplore](./lib/ttexplore.cpp) library exposes
a `SymbolicExplorator` class that takes as input a `triton::Context`. This context is used as the initial point for the path
exploration. Then, it does a classical snapshot-based code coverage process. The logic is the following:

1. Save the initial context as backup
2. Continue the execution from the given `triton::Context`
3. When execution is done, generate inputs that discover new paths
4. Restore the backup
5. Go to point 2

Note that TTexplore is not an advanced library. It's just a bootstrap code that provides a simple coverage logic. Consider this project as a base example about how to cover code with Triton. You will probably adapt it according to your targets and goals. That's why the code of the library aims to be as small as possible.

## Harness your target

Let's consider the following sample that comes from [AFL++ fuzzer challenges](https://github.com/AFLplusplus/fuzzer-challenges).

```c
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
```

Our harness is the following:

```cpp
#include <map>
#include <iostream>
#include <vector>

#include <LIEF/ELF.hpp>
#include <triton/context.hpp>
#include <triton/cpuSize.hpp>
#include <triton/stubs.hpp>

#include <ttexplore.hpp>

/* We will map the libc stub at this address */
const triton::uint64 base_libc = 0x66600000;

int main(int ac, const char *av[]) {
  /* Init the triton context */
  triton::Context ctx(triton::arch::ARCH_X86_64);

  if (ac != 2) {
    std::cerr << "Usage: " << av[0] << " <binary>" << std::endl;
    return -1;
  }

  /* We use LIEF to map segments of the target into the Triton context */
  std::unique_ptr<const LIEF::ELF::Binary> binary{LIEF::ELF::Parser::parse(av[1])};
  for (const LIEF::ELF::Segment& s : binary->segments()) {
    std::vector<triton::uint8> data;
    data.insert(data.begin(), s.content().begin(), s.content().end());
    ctx.setConcreteMemoryAreaValue(s.virtual_address(), data);
  }

  /* Map the stub of libc at 0x66600000 */
  ctx.setConcreteMemoryAreaValue(base_libc, triton::stubs::x8664::systemv::libc::code);

  /* Do the relocation of the strcmp@target.plt to my strcmp@libc_stub */
  ctx.setConcreteMemoryValue(
    triton::arch::MemoryAccess(0x4018, triton::size::qword),
    base_libc + triton::stubs::x8664::systemv::libc::symbols.at("strncasecmp")
  );

  /* Setup some Triton optimizations */
  ctx.setMode(triton::modes::ALIGNED_MEMORY, true);
  ctx.setMode(triton::modes::AST_OPTIMIZATIONS, true);
  ctx.setMode(triton::modes::CONSTANT_FOLDING, true);

  /* Setup the program counter and arguments */
  ctx.setConcreteRegisterValue(ctx.registers.x86_rip, 0x1135);     /* we directly call the target function (LLVMFuzzerTestOneInput) */
  ctx.setConcreteRegisterValue(ctx.registers.x86_rdi, 0xdead);     /* First argument of the LLVMFuzzerTestOneInput function (buf) */
  ctx.setConcreteRegisterValue(ctx.registers.x86_rsi, 100);        /* Second argument of the LLVMFuzzerTestOneInput function (len) */
  ctx.setConcreteRegisterValue(ctx.registers.x86_rsp, 0x7ffffff0); /* init stack */
  ctx.setConcreteRegisterValue(ctx.registers.x86_rbp, 0x7ffffff0); /* init stack */

  /* Setup symbolic variable. 0xdead is the first arg of LLVMFuzzerTestOneInput (see above) */
  ctx.symbolizeMemory(0xdead, 100);
  
  /* Setup exploration */
  triton::engines::exploration::SymbolicExplorator explorator;
  
  explorator.initContext(&ctx); /* define an initial context */
  explorator.explore();         /* do the exploration */
  explorator.dumpCoverage();    /* dump the code coverage */

  return 0;
  ```

Harnessing your target with TTexplore only consist to craft the `triton::Context` with the appropriate state. It can be initialized from a memory dump, a raw binary or by hand. It can be user or kernel code. The main point is that TTexplore will not emulate nor execute external calls, so your `triton::Context` must handle them before starting the exploration. For example, see how `strncasecmp` is handled in the above harness.

## Output

After compiling the harness with the TTexplore library. The output is the following:

```raw
$ ./build/harness4 ./harness/4/target/test-strcmp
[TT] exec: 0,  icov: 0,  sat: 1,  unsat: 0,  timeout: 0,  worklist: 1
[TT] exec: 1,  icov: 70,  sat: 4,  unsat: 1,  timeout: 0,  worklist: 3
[TT] exec: 2,  icov: 70,  sat: 4,  unsat: 1,  timeout: 0,  worklist: 2
[TT] exec: 3,  icov: 77,  sat: 7,  unsat: 3,  timeout: 0,  worklist: 4
[TT] exec: 4,  icov: 77,  sat: 7,  unsat: 3,  timeout: 0,  worklist: 3
[TT] exec: 5,  icov: 77,  sat: 10,  unsat: 5,  timeout: 0,  worklist: 5
[TT] exec: 6,  icov: 77,  sat: 10,  unsat: 5,  timeout: 0,  worklist: 4
[TT] exec: 7,  icov: 77,  sat: 13,  unsat: 7,  timeout: 0,  worklist: 6
[TT] exec: 8,  icov: 77,  sat: 13,  unsat: 7,  timeout: 0,  worklist: 5
[TT] exec: 9,  icov: 88,  sat: 16,  unsat: 10,  timeout: 0,  worklist: 7
[TT] exec: 10,  icov: 88,  sat: 16,  unsat: 10,  timeout: 0,  worklist: 6
[TT] exec: 11,  icov: 88,  sat: 19,  unsat: 12,  timeout: 0,  worklist: 8
[TT] exec: 12,  icov: 88,  sat: 19,  unsat: 12,  timeout: 0,  worklist: 7
[TT] exec: 13,  icov: 88,  sat: 22,  unsat: 14,  timeout: 0,  worklist: 9
[TT] exec: 14,  icov: 88,  sat: 22,  unsat: 14,  timeout: 0,  worklist: 8
[TT] exec: 15,  icov: 88,  sat: 25,  unsat: 16,  timeout: 0,  worklist: 10
[TT] exec: 16,  icov: 88,  sat: 25,  unsat: 16,  timeout: 0,  worklist: 9
[TT] exec: 17,  icov: 88,  sat: 28,  unsat: 18,  timeout: 0,  worklist: 11
[TT] exec: 18,  icov: 88,  sat: 28,  unsat: 18,  timeout: 0,  worklist: 10
[TT] exec: 19,  icov: 88,  sat: 31,  unsat: 20,  timeout: 0,  worklist: 12
[TT] exec: 20,  icov: 88,  sat: 31,  unsat: 20,  timeout: 0,  worklist: 11
[TT] exec: 21,  icov: 88,  sat: 34,  unsat: 22,  timeout: 0,  worklist: 13
[TT] exec: 22,  icov: 88,  sat: 34,  unsat: 22,  timeout: 0,  worklist: 12
[TT] exec: 23,  icov: 88,  sat: 37,  unsat: 24,  timeout: 0,  worklist: 14
[TT] exec: 24,  icov: 88,  sat: 37,  unsat: 24,  timeout: 0,  worklist: 13
[TT] exec: 25,  icov: 100,  sat: 40,  unsat: 27,  timeout: 0,  worklist: 15
[TT] exec: 26,  icov: 100,  sat: 40,  unsat: 27,  timeout: 0,  worklist: 14
[TT] exec: 27,  icov: 100,  sat: 43,  unsat: 29,  timeout: 0,  worklist: 16
[TT] exec: 28,  icov: 100,  sat: 43,  unsat: 29,  timeout: 0,  worklist: 15
[TT] exec: 29,  icov: 100,  sat: 46,  unsat: 31,  timeout: 0,  worklist: 17
[TT] exec: 30,  icov: 100,  sat: 46,  unsat: 31,  timeout: 0,  worklist: 16
[TT] exec: 31,  icov: 100,  sat: 49,  unsat: 33,  timeout: 0,  worklist: 18
[TT] exec: 32,  icov: 100,  sat: 49,  unsat: 33,  timeout: 0,  worklist: 17
[TT] exec: 33,  icov: 100,  sat: 52,  unsat: 35,  timeout: 0,  worklist: 19
[TT] exec: 34,  icov: 100,  sat: 52,  unsat: 35,  timeout: 0,  worklist: 18
[TT] exec: 35,  icov: 100,  sat: 55,  unsat: 37,  timeout: 0,  worklist: 20
[TT] exec: 36,  icov: 100,  sat: 55,  unsat: 37,  timeout: 0,  worklist: 19
[TT] exec: 37,  icov: 100,  sat: 58,  unsat: 39,  timeout: 0,  worklist: 21
[TT] exec: 38,  icov: 100,  sat: 58,  unsat: 39,  timeout: 0,  worklist: 20
[TT] exec: 39,  icov: 100,  sat: 61,  unsat: 41,  timeout: 0,  worklist: 22
[TT] exec: 40,  icov: 100,  sat: 61,  unsat: 41,  timeout: 0,  worklist: 21
[TT] exec: 41,  icov: 100,  sat: 64,  unsat: 43,  timeout: 0,  worklist: 23
[TT] exec: 42,  icov: 100,  sat: 64,  unsat: 43,  timeout: 0,  worklist: 22
[TT] exec: 43,  icov: 100,  sat: 67,  unsat: 45,  timeout: 0,  worklist: 24
[TT] exec: 44,  icov: 100,  sat: 67,  unsat: 45,  timeout: 0,  worklist: 23
[TT] exec: 45,  icov: 100,  sat: 70,  unsat: 47,  timeout: 0,  worklist: 25
[TT] exec: 46,  icov: 100,  sat: 70,  unsat: 47,  timeout: 0,  worklist: 24
[TT] exec: 47,  icov: 100,  sat: 73,  unsat: 49,  timeout: 0,  worklist: 26
[TT] exec: 48,  icov: 100,  sat: 73,  unsat: 49,  timeout: 0,  worklist: 25
[TT] exec: 49,  icov: 100,  sat: 76,  unsat: 51,  timeout: 0,  worklist: 27
[TT] exec: 50,  icov: 100,  sat: 76,  unsat: 51,  timeout: 0,  worklist: 26
[TT] exec: 51,  icov: 100,  sat: 79,  unsat: 53,  timeout: 0,  worklist: 28
[TT] exec: 52,  icov: 100,  sat: 79,  unsat: 53,  timeout: 0,  worklist: 27
[TT] exec: 53,  icov: 100,  sat: 82,  unsat: 55,  timeout: 0,  worklist: 29
[TT] exec: 54,  icov: 100,  sat: 82,  unsat: 55,  timeout: 0,  worklist: 28
[TT] exec: 55,  icov: 100,  sat: 85,  unsat: 57,  timeout: 0,  worklist: 30
[TT] exec: 56,  icov: 100,  sat: 85,  unsat: 57,  timeout: 0,  worklist: 29
[TT] exec: 57,  icov: 113,  sat: 88,  unsat: 60,  timeout: 0,  worklist: 31
[TT] exec: 58,  icov: 113,  sat: 88,  unsat: 60,  timeout: 0,  worklist: 30
[TT] exec: 59,  icov: 113,  sat: 91,  unsat: 62,  timeout: 0,  worklist: 32
[TT] exec: 60,  icov: 113,  sat: 91,  unsat: 62,  timeout: 0,  worklist: 31
[TT] exec: 61,  icov: 113,  sat: 94,  unsat: 64,  timeout: 0,  worklist: 33
[TT] exec: 62,  icov: 113,  sat: 94,  unsat: 64,  timeout: 0,  worklist: 32
[TT] exec: 63,  icov: 113,  sat: 97,  unsat: 66,  timeout: 0,  worklist: 34
[TT] exec: 64,  icov: 113,  sat: 97,  unsat: 66,  timeout: 0,  worklist: 33
[TT] exec: 65,  icov: 113,  sat: 100,  unsat: 68,  timeout: 0,  worklist: 35
[TT] exec: 66,  icov: 113,  sat: 100,  unsat: 68,  timeout: 0,  worklist: 34
[TT] exec: 67,  icov: 113,  sat: 103,  unsat: 70,  timeout: 0,  worklist: 36
[TT] exec: 68,  icov: 113,  sat: 103,  unsat: 70,  timeout: 0,  worklist: 35
[TT] exec: 69,  icov: 113,  sat: 106,  unsat: 72,  timeout: 0,  worklist: 37
[TT] exec: 70,  icov: 113,  sat: 106,  unsat: 72,  timeout: 0,  worklist: 36
[TT] exec: 71,  icov: 113,  sat: 109,  unsat: 74,  timeout: 0,  worklist: 38
[TT] exec: 72,  icov: 113,  sat: 109,  unsat: 74,  timeout: 0,  worklist: 37
[TT] exec: 73,  icov: 113,  sat: 112,  unsat: 76,  timeout: 0,  worklist: 39
[TT] exec: 74,  icov: 113,  sat: 112,  unsat: 76,  timeout: 0,  worklist: 38
[TT] exec: 75,  icov: 113,  sat: 115,  unsat: 78,  timeout: 0,  worklist: 40
[TT] exec: 76,  icov: 113,  sat: 115,  unsat: 78,  timeout: 0,  worklist: 39
[TT] exec: 77,  icov: 113,  sat: 118,  unsat: 80,  timeout: 0,  worklist: 41
[TT] exec: 78,  icov: 113,  sat: 118,  unsat: 80,  timeout: 0,  worklist: 40
[TT] exec: 79,  icov: 113,  sat: 121,  unsat: 82,  timeout: 0,  worklist: 42
[TT] exec: 80,  icov: 113,  sat: 121,  unsat: 82,  timeout: 0,  worklist: 41
[TT] exec: 81,  icov: 113,  sat: 124,  unsat: 84,  timeout: 0,  worklist: 43
[TT] exec: 82,  icov: 113,  sat: 124,  unsat: 84,  timeout: 0,  worklist: 42
[TT] exec: 83,  icov: 113,  sat: 127,  unsat: 86,  timeout: 0,  worklist: 44
[TT] exec: 84,  icov: 113,  sat: 127,  unsat: 86,  timeout: 0,  worklist: 43
[TT] exec: 85,  icov: 113,  sat: 130,  unsat: 88,  timeout: 0,  worklist: 45
[TT] exec: 86,  icov: 113,  sat: 130,  unsat: 88,  timeout: 0,  worklist: 44
[TT] exec: 87,  icov: 113,  sat: 133,  unsat: 90,  timeout: 0,  worklist: 46
[TT] exec: 88,  icov: 113,  sat: 133,  unsat: 90,  timeout: 0,  worklist: 45
[TT] exec: 89,  icov: 113,  sat: 136,  unsat: 92,  timeout: 0,  worklist: 47
[TT] exec: 90,  icov: 113,  sat: 136,  unsat: 92,  timeout: 0,  worklist: 46
[TT] exec: 91,  icov: 113,  sat: 139,  unsat: 94,  timeout: 0,  worklist: 48
[TT] exec: 92,  icov: 113,  sat: 139,  unsat: 94,  timeout: 0,  worklist: 47
[TT] exec: 93,  icov: 113,  sat: 142,  unsat: 96,  timeout: 0,  worklist: 49
[TT] exec: 94,  icov: 113,  sat: 142,  unsat: 96,  timeout: 0,  worklist: 48
[TT] exec: 95,  icov: 113,  sat: 145,  unsat: 98,  timeout: 0,  worklist: 50
[TT] exec: 96,  icov: 113,  sat: 145,  unsat: 98,  timeout: 0,  worklist: 49
[TT] exec: 97,  icov: 113,  sat: 148,  unsat: 100,  timeout: 0,  worklist: 51
[TT] exec: 98,  icov: 113,  sat: 148,  unsat: 100,  timeout: 0,  worklist: 50
[TT] exec: 99,  icov: 113,  sat: 151,  unsat: 102,  timeout: 0,  worklist: 52
[TT] exec: 100,  icov: 113,  sat: 151,  unsat: 102,  timeout: 0,  worklist: 51
[TT] exec: 101,  icov: 113,  sat: 154,  unsat: 104,  timeout: 0,  worklist: 53
[TT] exec: 102,  icov: 113,  sat: 154,  unsat: 104,  timeout: 0,  worklist: 52
[TT] exec: 103,  icov: 113,  sat: 157,  unsat: 106,  timeout: 0,  worklist: 54
[TT] exec: 104,  icov: 113,  sat: 157,  unsat: 106,  timeout: 0,  worklist: 53
[TT] exec: 105,  icov: 113,  sat: 160,  unsat: 108,  timeout: 0,  worklist: 55
[TT] exec: 106,  icov: 113,  sat: 160,  unsat: 108,  timeout: 0,  worklist: 54
[TT] exec: 107,  icov: 113,  sat: 163,  unsat: 110,  timeout: 0,  worklist: 56
[TT] exec: 108,  icov: 113,  sat: 163,  unsat: 110,  timeout: 0,  worklist: 55
[TT] exec: 109,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 54
[TT] exec: 110,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 53
[TT] exec: 111,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 52
[TT] exec: 112,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 51
[TT] exec: 113,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 50
[TT] exec: 114,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 49
[TT] exec: 115,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 48
[TT] exec: 116,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 47
[TT] exec: 117,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 46
[TT] exec: 118,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 45
[TT] exec: 119,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 44
[TT] exec: 120,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 43
[TT] exec: 121,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 42
[TT] exec: 122,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 41
[TT] exec: 123,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 40
[TT] exec: 124,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 39
[TT] exec: 125,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 38
[TT] exec: 126,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 37
[TT] exec: 127,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 36
[TT] exec: 128,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 35
[TT] exec: 129,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 34
[TT] exec: 130,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 33
[TT] exec: 131,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 32
[TT] exec: 132,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 31
[TT] exec: 133,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 30
[TT] exec: 134,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 29
[TT] exec: 135,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 28
[TT] exec: 136,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 27
[TT] exec: 137,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 26
[TT] exec: 138,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 25
[TT] exec: 139,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 24
[TT] exec: 140,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 23
[TT] exec: 141,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 22
[TT] exec: 142,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 21
[TT] exec: 143,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 20
[TT] exec: 144,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 19
[TT] exec: 145,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 18
[TT] exec: 146,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 17
[TT] exec: 147,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 16
[TT] exec: 148,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 15
[TT] exec: 149,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 14
[TT] exec: 150,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 13
[TT] exec: 151,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 12
[TT] exec: 152,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 11
[TT] exec: 153,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 10
[TT] exec: 154,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 9
[TT] exec: 155,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 8
[TT] exec: 156,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 7
[TT] exec: 157,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 6
[TT] exec: 158,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 5
[TT] exec: 159,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 4
[TT] exec: 160,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 3
[TT] exec: 161,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 2
[TT] exec: 162,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 1
[TT] exec: 163,  icov: 114,  sat: 163,  unsat: 113,  timeout: 0,  worklist: 0
[TT] IDA coverage file has been written in workspace/coverage/ida_cov.py
```

The output format is the following:

* `[TT]`: verbose from TTexplore
* `exec`: number of executions
* `icov`: number of unique instructions covered
* `sat`: number of queries that are sat
* `unsat`: number of queries that are unsat
* `timeout`: number of queries that raise a timeout
* `worklist`: number of seeds that are waiting to be injected into the program

Note that a `workspace/coverage/ida_cov.py` file has been generated. It's an IDA plugin that colors all instructions covered.

## The corpus

All the corpus is stored on the disk into a `workspace` directory. There is one file per execution.

```console
$ ls workspace/corpus
1    102  106  11   113  117  120  124  128  131  135  139  142  146  15   153  157  160  17  20  24  28  31  35  39  42  46  5   53  57  60  64  68  71  75  79  82  86  9   93  97
10   103  107  110  114  118  121  125  129  132  136  14   143  147  150  154  158  161  18  21  25  29  32  36  4   43  47  50  54  58  61  65  69  72  76  8   83  87  90  94  98
100  104  108  111  115  119  122  126  13   133  137  140  144  148  151  155  159  162  19  22  26  3   33  37  40  44  48  51  55  59  62  66  7   73  77  80  84  88  91  95  99
101  105  109  112  116  12   123  127  130  134  138  141  145  149  152  156  16   163  2   23  27  30  34  38  41  45  49  52  56  6   63  67  70  74  78  81  85  89  92  96
```

Regarding [our sample](#harness-your-target), if we print all the corpus once the coverage is done we got the following output:

```console
$ strings workspace/corpus/*
0123@
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgf
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfe
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfe
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfed
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfed
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfedc
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfedc
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfedcb
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfedcb|
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfedcba
01238
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfedcbP
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfedcP
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfedX
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfeA
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgfH
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgA
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihZ
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjiX
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjH
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkP
01238?
012387654321abcdefhiklmnopqrzyxwvutsrqponmlZ
012387654321abcdefhiklmnopqrzyxwvutsrqponmH
012387654321abcdefhiklmnopqrzyxwvutsrqponH
012387654321abcdefhiklmnopqrzyxwvutsrqpoH
012387654321abcdefhiklmnopqrzyxwvutsrqpA
012387654321abcdefhiklmnopqrzyxwvutsrqP
012387654321abcdefhiklmnopqrzyxwvutsrZ
012387654321abcdefhiklmnopqrzyxwvutsX
012387654321abcdefhiklmnopqrzyxwvutZ
012387654321abcdefhiklmnopqrzyxwvuZ
012387
012387654321abcdefhiklmnopqrzyxwvH
012387654321abcdefhiklmnopqrzyxwZ
012387654321abcdefhiklmnopqrzyxA
012387654321abcdefhiklmnopqrzyA
012387654321abcdefhiklmnopqrzH
012387654321abcdefhiklmnopqrA
012387654321abcdefhiklmnopqX
012387654321abcdefhiklmnopH
012387654321abcdefhiklmnoA
012387654321abcdefhiklmnH
012387>
012387654321abcdefhiklmP
012387654321abcdefhiklA
012387654321abcdefhikZ
012387654321abcdefhiH
012387654321abcdefhA
012387654321abcdefA
012387654321abcdeH
012387654321abcdH
012387654321abcA
012387654321abP
0123876
012387654321aZ
012387654321X
01238765432A
0123876543P
012387654Z
01238765A
0123876P
012387H
01238P
0123H
0123876^
012X
01238765
01238765z
012387654
012387654@
0123876543
01238765438
01238765432
01238765432
012387654321
012387654321z
012387654321a
012387654321az
012387654321ab
012387654321abk
012387654321abc
012387654321abc
012387654321abcd
012387654321abcdf
012387654321abcde
012387654321abcdez
012387654321abcdef
012387654321abcdef
012387654321abcdefh
012387654321abcdefh
012387654321abcdefhi
012387654321abcdefhi
012387654321abcdefhik
012387654321abcdefhik
012387654321abcdefhikl
012387654321abcdefhikl
012387654321abcdefhiklm
012387654321abcdefhiklm~
012387654321abcdefhiklmn
012387654321abcdefhiklmnz
012387654321abcdefhiklmno
012387654321abcdefhiklmno|
012387654321abcdefhiklmnop
012387654321abcdefhiklmnop
012387654321abcdefhiklmnopq
012387654321abcdefhiklmnopq|
012387654321abcdefhiklmnopqr
012387654321abcdefhiklmnopqr
012387654321abcdefhiklmnopqrz
012387654321abcdefhiklmnopqrzz
012387654321abcdefhiklmnopqrzy
012387654321abcdefhiklmnopqrzy|
012387654321abcdefhiklmnopqrzyx
012387654321abcdefhiklmnopqrzyxz
012387654321abcdefhiklmnopqrzyxw
012387654321abcdefhiklmnopqrzyxw~
012387654321abcdefhiklmnopqrzyxwv
012387654321abcdefhiklmnopqrzyxwv
012387654321abcdefhiklmnopqrzyxwvu
012387654321abcdefhiklmnopqrzyxwvu|
012387654321abcdefhiklmnopqrzyxwvut
012387654321abcdefhiklmnopqrzyxwvut{
012387654321abcdefhiklmnopqrzyxwvuts
012387654321abcdefhiklmnopqrzyxwvutsz
012387654321abcdefhiklmnopqrzyxwvutsr
012387654321abcdefhiklmnopqrzyxwvutsrz
012387654321abcdefhiklmnopqrzyxwvutsrq
012387654321abcdefhiklmnopqrzyxwvutsrq|
012387654321abcdefhiklmnopqrzyxwvutsrqp
012;
012387654321abcdefhiklmnopqrzyxwvutsrqp
012387654321abcdefhiklmnopqrzyxwvutsrqpo
012387654321abcdefhiklmnopqrzyxwvutsrqpo
012387654321abcdefhiklmnopqrzyxwvutsrqpon
012387654321abcdefhiklmnopqrzyxwvutsrqpon
012387654321abcdefhiklmnopqrzyxwvutsrqponm
012387654321abcdefhiklmnopqrzyxwvutsrqponm
012387654321abcdefhiklmnopqrzyxwvutsrqponml
012387654321abcdefhiklmnopqrzyxwvutsrqponml{
012387654321abcdefhiklmnopqrzyxwvutsrqponmlk
0123
012387654321abcdefhiklmnopqrzyxwvutsrqponmlk
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkj
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkj|
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkji
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkji
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjih
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjih
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihg
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihg
012387654321abcdefhiklmnopqrzyxwvutsrqponmlkjihgf
```

# Sharing corpus between libfuzzer and TTexplore

Nowadays combining multiple sources of fuzzer and sharing seeds is something relevant. This is something that can be quickly done here. Let's consider the following snippet:

```c
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
```

If we compile this snippet with libfuzzer without optimization (`clang++ -g -O0 -fsanitize=fuzzer,memory target.cpp`), libfuzzer will run for a while before finding `r * 2 == 0xdeadbef0`. In other hand, this kind of constraints are really easy to solve using symbolic execution. So, combining dynamic symbolic execution and runtime fuzzing is something very interesting.

The only thing we have to do is to run libfuzzer with 2 jobs and defining a corpus directory (here the TTexplore workspace). Note that we have to run at least 2 jobs, otherwise libfuzzer will not refresh its corpus, which is an issue as we need to share seeds from TTexplore and libfuzzer.

So, in a first console, let's run libfuzzer like this:

```console
$ ./harness/6/target/target-libfuzzer -jobs=2 ./workspace/corpus
```

And in another console, let's run our TTexplore harness like this:

```console
$ ./build/harness6
```

As soon as TTexplore will find a model which solves `r * 2 == 0xdeadbef0`, it will write the seed into the `./workspace/corpus` directory and at the next libfuzzer refresh, libfuzzer will trigger the `__builtin_trap`. 

![tt-and-libfuzzer](https://user-images.githubusercontent.com/991046/197147618-fc09e934-7340-4ebb-aa34-6f77be4422d8.gif)

This is a very straightforward example, but it shows how combining multiple sources of fuzzer enhances our chances of finding new paths.

# The TTexplore config structure

You can quickly configure the exploration. There is a structure for that.

```cpp
struct config_s {
  bool            stats;
  std::string     workspace = "workspace";
  triton::uint64  end_point;
  triton::usize   ea_model;
  triton::usize   jmp_model;
  triton::usize   limit_inst;
  triton::usize   timeout; /* seconds */
};
```

* `stats`: `true` if you want `[TT]` verbosity
* `workspace`: The default workspace name directory
* `end_point`: The instruction address where to stop the execution
* `ea_model`: Number of queries sent to the solver when a symbolic load or store is hit. E.g, `mov rax, [rsi + rdi]` where `rdi` is symbolic.
* `jmp_model`: Number of queries sent to the solver when a symbolic jump is hit. E.g, `jmp rax` where `rax` is symbolic.
* `limit_inst`: The limit of instructions executed per execution.
* `timeout`: The timeout in seconds for solving queries.

There are only few possible configurations as it aims to be a bootstrap code.
