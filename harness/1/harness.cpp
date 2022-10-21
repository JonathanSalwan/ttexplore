#include <map>
#include <iostream>

#include <triton/context.hpp>
#include <triton/cpuSize.hpp>
#include <ttexplore.hpp>


// The program we want to emulate and explore
std::map<triton::uint64, std::vector<triton::uint8>> program = {
  // .text
  {0x40056d, {0x55}},                                       // push    rbp
  {0x40056e, {0x48, 0x89, 0xe5}},                           // mov     rbp,rsp
  {0x400571, {0x48, 0x89, 0x7d, 0xe8}},                     // mov     QWORD PTR [rbp-0x18],rdi
  {0x400575, {0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00}},   // mov     DWORD PTR [rbp-0x4],0x0
  {0x40057c, {0xeb, 0x3f}},                                 // jmp     4005bd <check+0x50>
  {0x40057e, {0x8b, 0x45, 0xfc}},                           // mov     eax,DWORD PTR [rbp-0x4]
  {0x400581, {0x48, 0x63, 0xd0}},                           // movsxd  rdx,eax
  {0x400584, {0x48, 0x8b, 0x45, 0xe8}},                     // mov     rax,QWORD PTR [rbp-0x18]
  {0x400588, {0x48, 0x01, 0xd0}},                           // add     rax,rdx
  {0x40058b, {0x0f, 0xb6, 0x00}},                           // movzx   eax,BYTE PTR [rax]
  {0x40058e, {0x0f, 0xbe, 0xc0}},                           // movsx   eax,al
  {0x400591, {0x83, 0xe8, 0x01}},                           // sub     eax,0x1
  {0x400594, {0x83, 0xf0, 0x55}},                           // xor     eax,0x55
  {0x400597, {0x89, 0xc1}},                                 // mov     ecx,eax
  {0x400599, {0x48, 0x8b, 0x15, 0xa0, 0x0a, 0x20, 0x00}},   // mov     rdx,QWORD PTR [rip+0x200aa0]        # 601040 <serial>
  {0x4005a0, {0x8b, 0x45, 0xfc}},                           // mov     eax,DWORD PTR [rbp-0x4]
  {0x4005a3, {0x48, 0x98}},                                 // cdqe
  {0x4005a5, {0x48, 0x01, 0xd0}},                           // add     rax,rdx
  {0x4005a8, {0x0f, 0xb6, 0x00}},                           // movzx   eax,BYTE PTR [rax]
  {0x4005ab, {0x0f, 0xbe, 0xc0}},                           // movsx   eax,al
  {0x4005ae, {0x39, 0xc1}},                                 // cmp     ecx,eax
  {0x4005b0, {0x74, 0x07}},                                 // je      4005b9 <check+0x4c>
  {0x4005b2, {0xb8, 0x01, 0x00, 0x00, 0x00}},               // mov     eax,0x1
  {0x4005b7, {0xeb, 0x0f}},                                 // jmp     4005c8 <check+0x5b>
  {0x4005b9, {0x83, 0x45, 0xfc, 0x01}},                     // add     DWORD PTR [rbp-0x4],0x1
  {0x4005bd, {0x83, 0x7d, 0xfc, 0x04}},                     // cmp     DWORD PTR [rbp-0x4],0x4
  {0x4005c1, {0x7e, 0xbb}},                                 // jle     40057e <check+0x11>
  {0x4005c3, {0xb8, 0x00, 0x00, 0x00, 0x00}},               // mov     eax,0x0
  {0x4005c8, {0x5d}},                                       // pop     rbp
  {0x4005c9, {0xc3}},                                       // ret

  // .data
  {0x601040, {0x00, 0x00, 0x90}},                           // pointer that points on the serial key
  {0x900000, {0x31, 0x3e, 0x3d, 0x26, 0x31}},               // serial key of the program
  {0x00dead, {0x61, 0x61, 0x61, 0x61, 0x61}},               // user input filled with 'aaaaa'
};


int main(int ac, const char *av[]) {
  /* Init the triton context */
  triton::Context ctx(triton::arch::ARCH_X86_64);

  /* Setup the concrete state */
  for (const auto& item : program) {
    ctx.setConcreteMemoryAreaValue(item.first, item.second);
  }

  /* Setup symbolic variable */
  ctx.symbolizeMemory(0xdead, 5);

  /* Setup the program counter and arguments */
  ctx.setConcreteRegisterValue(ctx.registers.x86_rip, 0x40056d);
  ctx.setConcreteRegisterValue(ctx.registers.x86_rdi, 0x00dead);

  /* Start exploration */
  triton::engines::exploration::SymbolicExplorator explorator;
  explorator.initContext(&ctx);
  explorator.explore();

  return 0;
}
