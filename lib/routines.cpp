//! \file
/*
**  This program is under the terms of the Apache License 2.0.
**  Jonathan Salwan
*/

#include <cstdio>
#include <string>

#include <triton/coreUtils.hpp>

#include <routines.hpp>
#include <ttexplore.hpp>

/*
 * This file aims to provide an example about using routines when emulating a target.
 * For example, we provide a very simple printf routine that just prints the string
 * format pointed by rdi. As example, this printf routine is used in the harness5.
 *
 * The idea behind routines is that you can simulate whatever the program calls and
 * update the triton context according to your goals.
 */

namespace triton {
  namespace routines {

    std::string getStringFromAddr(triton::Context* ctx, triton::uint64 addr) {
      std::string s;
      while (triton::uint8 v = ctx->getConcreteMemoryValue(addr++)) {
        s += v;
      }
      return s;
    }


    triton::callbacks::cb_state_e printf(triton::Context* ctx) {
      triton::uint64 rdi_v = triton::utils::cast<triton::uint64>(ctx->getConcreteRegisterValue(ctx->registers.x86_rdi));
      std::cout << getStringFromAddr(ctx, rdi_v);
      return triton::callbacks::PLT_CONTINUE;
    }

  };
};
