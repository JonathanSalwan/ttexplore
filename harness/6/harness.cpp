#include <map>
#include <iostream>

#include <triton/context.hpp>
#include <triton/cpuSize.hpp>
#include <ttexplore.hpp>


// The program we want to emulate and explore
std::map<triton::uint64, std::vector<triton::uint8>> program = {
  // .text
  {0x1145, {0x55}},                         // push   rbp
  {0x1146, {0x48, 0x89, 0xe5}},             // mov    rbp,rsp
  {0x1149, {0x48, 0x89, 0x7d, 0xe8}},       // mov    QWORD PTR [rbp-0x18],rdi
  {0x114d, {0x48, 0x89, 0x75, 0xe0}},       // mov    QWORD PTR [rbp-0x20],rsi
  {0x1151, {0x48, 0x83, 0x7d, 0xe0, 0x03}}, // cmp    QWORD PTR [rbp-0x20],0x3
  {0x1156, {0x77, 0x07}},                   // ja     115f <LLVMFuzzerTestOneInput+0x1a>
  {0x1158, {0xb8, 0x00, 0x00, 0x00, 0x00}}, // mov    eax,0x0
  {0x115d, {0xeb, 0x21}},                   // jmp    1180 <LLVMFuzzerTestOneInput+0x3b>
  {0x115f, {0x48, 0x8b, 0x45, 0xe8}},       // mov    rax,QWORD PTR [rbp-0x18]
  {0x1163, {0x8b, 0x00}},                   // mov    eax,DWORD PTR [rax]
  {0x1165, {0x89, 0x45, 0xfc}},             // mov    DWORD PTR [rbp-0x4],eax
  {0x1168, {0x8b, 0x45, 0xfc}},             // mov    eax,DWORD PTR [rbp-0x4]
  {0x116b, {0x01, 0xc0}},                   // add    eax,eax
  {0x116d, {0x3d, 0xf0, 0xbe, 0xad, 0xde}}, // cmp    eax,0xdeadbef0
  {0x1172, {0x75, 0x07}},                   // jne    117b <LLVMFuzzerTestOneInput+0x36>
  {0x1174, {0xb8, 0x01, 0x00, 0x00, 0x00}}, // mov    eax,0x1
  {0x1179, {0xeb, 0x05}},                   // jmp    1180 <LLVMFuzzerTestOneInput+0x3b>
  {0x117b, {0xb8, 0x00, 0x00, 0x00, 0x00}}, // mov    eax,0x0
  {0x1180, {0x5d}},                         // pop    rbp
  {0x1181, {0xc3}},                         // ret

  {0x1182, {0x00, 0x00, 0x00, 0x00, 0x00}}  // padding
};


int main(int ac, const char *av[]) {
  /* Init the triton context */
  triton::Context ctx(triton::arch::ARCH_X86_64);

  /* Setup the concrete state */
  for (const auto& item : program) {
    ctx.setConcreteMemoryAreaValue(item.first, item.second);
  }

  /* Setup symbolic variable */
  ctx.symbolizeMemory(0xdead, 4);

  /* Setup the program counter and arguments */
  ctx.setConcreteRegisterValue(ctx.registers.x86_rip, 0x1145);
  ctx.setConcreteRegisterValue(ctx.registers.x86_rdi, 0xdead);
  ctx.setConcreteRegisterValue(ctx.registers.x86_rsi, 4);

  /* Start exploration */
  triton::engines::exploration::SymbolicExplorator explorator;
  explorator.initContext(&ctx);
  explorator.config.end_point = 0x1181;
  explorator.explore();

  return 0;
}
