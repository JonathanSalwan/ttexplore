#include <map>
#include <iostream>
#include <vector>

#include <LIEF/ELF.hpp>
#include <triton/context.hpp>
#include <triton/cpuSize.hpp>

#include <ttexplore.hpp>


int main(int ac, const char *av[]) {
  /* Init the triton context */
  triton::Context ctx(triton::arch::ARCH_X86_64);

  if (ac != 2) {
    std::cerr << "Usage: " << av[0] << " <binary>" << std::endl;
    return -1;
  }

  std::unique_ptr<const LIEF::ELF::Binary> binary{LIEF::ELF::Parser::parse(av[1])};
  for (const LIEF::ELF::Segment& s : binary->segments()) {
    std::vector<triton::uint8> data;
    data.insert(data.begin(), s.content().begin(), s.content().end());
    std::cout << "[+] Mapping "
              << std::hex << std::setw(16) << std::setfill('0') << s.virtual_address()
              << " "
              << std::hex << std::setw(16) << std::setfill('0') << s.virtual_address() + s.virtual_size()
              << std::endl;
    ctx.setConcreteMemoryAreaValue(s.virtual_address(), data);
  }

  /* Setup mode */
  ctx.setMode(triton::modes::ALIGNED_MEMORY, true);
  ctx.setMode(triton::modes::AST_OPTIMIZATIONS, true);
  ctx.setMode(triton::modes::CONSTANT_FOLDING, true);

  /* Setup symbolic variable */
  ctx.symbolizeMemory(0xdead, 7);

  /* Setup the program counter and arguments */
  ctx.setConcreteRegisterValue(ctx.registers.x86_rip, 0x1125);
  ctx.setConcreteRegisterValue(ctx.registers.x86_rdi, 0x00dead);
  ctx.setConcreteRegisterValue(ctx.registers.x86_rsp, 0x7ffffff0);
  ctx.setConcreteRegisterValue(ctx.registers.x86_rbp, 0x7ffffff0);

  /* Start exploration */
  triton::engines::exploration::SymbolicExplorator explorator;
  explorator.initContext(&ctx);
  explorator.explore();
  //explorator.dumpCoverage();

  return 0;
}
