//! \file
/*
**  This program is under the terms of the Apache License 2.0.
**  Jonathan Salwan
*/

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <triton/aarch64Cpu.hpp>
#include <triton/arm32Cpu.hpp>
#include <triton/coreUtils.hpp>
#include <triton/exceptions.hpp>
#include <triton/x8664Cpu.hpp>
#include <triton/x86Cpu.hpp>

#include <ttexplore.hpp>



namespace triton {
  namespace engines {
    namespace exploration {

      SymbolicExplorator::SymbolicExplorator() {
        this->config.ea_model = 1000;
        this->config.jmp_model = 1000;
        this->config.limit_inst = 0;
        this->config.stats = true;
        this->config.timeout = 60;
        this->config.end_point = 0;

        this->bck_ctx = nullptr;
        this->ini_ctx = nullptr;
        this->nbexec = 0;
        this->nbsat = 0;
        this->nbtimeout = 0;
        this->nbunsat = 0;
      }


      SymbolicExplorator::SymbolicExplorator(triton::Context* ini_ctx)
        : SymbolicExplorator() {
        this->ini_ctx = ini_ctx;
      }


      SymbolicExplorator::~SymbolicExplorator() {
        this->ini_ctx = nullptr;
        this->bck_ctx = nullptr;
      }


      void SymbolicExplorator::initContext(triton::Context* ini_ctx) {
        this->ini_ctx = ini_ctx;
      }


      void SymbolicExplorator::initWorklist(void) {
        triton::engines::solver::status_e status;
        auto model = this->ini_ctx->getModel(this->ini_ctx->getPathPredicate(), &status, this->config.timeout);
        if (status == triton::engines::solver::SAT) {
          this->nbsat++;
          /* If the model is SAT and empty, it means that any values satisfy the path predicate */
          if (model.size() == 0) {
            for (const auto& item : this->ini_ctx->getSymbolicVariables()) {
              model[item.first] = triton::engines::solver::SolverModel(item.second, 0x00);
            }
          }
          this->worklist.push_back(model);
        }
        else if (status == triton::engines::solver::TIMEOUT) {
          this->nbtimeout++;
        }
        else {
          this->nbunsat++;
        }
        std::filesystem::create_directories(config.workspace + "/corpus");
        std::filesystem::create_directories(config.workspace + "/crashes");
        std::filesystem::create_directories(config.workspace + "/coverage");
      }


      void SymbolicExplorator::dumpCoverage(void) {
        std::ofstream f;
        f.open(this->config.workspace + "/coverage/ida_cov.py");
        for (const auto& item : this->coverage) {
          f << std::hex << "idc.set_color(0x" << item.first << ", idc.CIC_ITEM, 0x024701)" << std::endl;
        }
        f.close();
        std::cout << "[TT] IDA coverage file has been written in " << this->config.workspace << "/coverage/ida_cov.py" << std::endl;
      }


      void SymbolicExplorator::writeSeedOnDisk(const std::string& dir, const Seed& seed) {
        std::ofstream f;
        auto v = this->seed2vector(seed);
        f.open(this->config.workspace + "/" + dir + "/" + std::to_string(this->nbexec));
        f.write(reinterpret_cast<const char*>(v.data()), v.size());
        f.close();
      }


      void SymbolicExplorator::asmret(void) {
        switch (this->ini_ctx->getArchitecture()) {
          case triton::arch::ARCH_X86:
          case triton::arch::ARCH_X86_64: {
            auto ret = triton::arch::Instruction("\xc3", 1);
            this->ini_ctx->processing(ret);
            break;
          }
          default:
            throw triton::exceptions::Engines("SymbolicExplorator::asmret(): Invalid architecture");
        }
      }


      void SymbolicExplorator::run(const Seed& seed) {
        triton::arch::CpuInterface* cpu = this->ini_ctx->getCpuInstance();

        /* Init the program counter */
        triton::arch::Register pcreg = cpu->getProgramCounter();
        triton::uint64 pcval = 0;
        triton::usize count = 0;

        do {
          if (this->config.limit_inst && count >= this->config.limit_inst) {
            break;
          }

          pcval = triton::utils::cast<triton::uint64>(cpu->getConcreteRegisterValue(pcreg));
          if (this->instHooks.find(pcval) != this->instHooks.end()) {
            auto state = this->instHooks.at(pcval)(this->ini_ctx);
            switch (state) {
              case triton::callbacks::CONTINUE:      continue;
              case triton::callbacks::BREAK:         goto stop_execution;
              case triton::callbacks::PLT_CONTINUE:  this->asmret() ; continue;
            }
          }
          else if (this->config.end_point && pcval == 0 || cpu->isConcreteMemoryValueDefined(pcval, 1) == false) {
            std::cout << "[TT] Invalid control flow, pc = 0x" << std::hex << pcval << " (writing seed on disk)" << std::endl;
            this->writeSeedOnDisk("crashes", seed);
            break;
          }

          /* Fetch opcodes */
          auto opcodes = this->ini_ctx->getConcreteMemoryAreaValue(pcval, 16);

          /* Execute instruction */
          triton::arch::Instruction inst(pcval, opcodes.data(), opcodes.size());
          if (this->ini_ctx->processing(inst) != triton::arch::NO_FAULT) {
            std::cout << "[TT] Invalid instruction, pc = 0x" << std::hex << pcval << " (writing seed on disk)" << std::endl;
            this->writeSeedOnDisk("crashes", seed);
            break;
          }

          //std::cout << inst << std::endl;

          this->symbolizeEffectiveAddress(inst);

          /* Update the code coverage */
          if (this->coverage.find(pcval) != this->coverage.end()) {
            this->coverage[pcval] += 1;
          }
          else {
            this->coverage[pcval] = 1;
          }

          count++;
        }
        while (this->config.end_point != pcval);

        stop_execution:
        this->nbexec += 1;
        this->writeSeedOnDisk("corpus", seed);
      }


      void SymbolicExplorator::snapshotContext(triton::Context* dst, triton::Context* src) {
        /* Synch concrete state */
        switch (src->getArchitecture()) {
          case triton::arch::ARCH_X86_64:
            *static_cast<triton::arch::x86::x8664Cpu*>(dst->getCpuInstance()) = *static_cast<triton::arch::x86::x8664Cpu*>(src->getCpuInstance());
            break;
          case triton::arch::ARCH_X86:
            *static_cast<triton::arch::x86::x86Cpu*>(dst->getCpuInstance()) = *static_cast<triton::arch::x86::x86Cpu*>(src->getCpuInstance());
            break;
          case triton::arch::ARCH_ARM32:
            *static_cast<triton::arch::arm::arm32::Arm32Cpu*>(dst->getCpuInstance()) = *static_cast<triton::arch::arm::arm32::Arm32Cpu*>(src->getCpuInstance());
            break;
          case triton::arch::ARCH_AARCH64:
            *static_cast<triton::arch::arm::aarch64::AArch64Cpu*>(dst->getCpuInstance()) = *static_cast<triton::arch::arm::aarch64::AArch64Cpu*>(src->getCpuInstance());
            break;
          default:
            throw triton::exceptions::Engines("SymbolicExplorator::snapshotContext(): Invalid architecture");
        }

        /* Synch symbolic register */
        dst->concretizeAllRegister();
        for (const auto& item : src->getSymbolicRegisters()) {
          dst->assignSymbolicExpressionToRegister(item.second, dst->getRegister(item.first));
        }

        /* Synch symbolic memory */
        dst->concretizeAllMemory();
        for (const auto& item : src->getSymbolicMemory()) {
          dst->assignSymbolicExpressionToMemory(item.second, triton::arch::MemoryAccess(item.first, triton::size::byte));
        }

        /* Synch path predicate */
        dst->clearPathConstraints();
        for (const auto& pc : src->getPathConstraints()) {
          dst->pushPathConstraint(pc);
        }
      }


      std::list<triton::uint64> SymbolicExplorator::buildPathAddrs(void) {
        std::list<triton::uint64> pathaddrs;
        for (const auto& pc : this->ini_ctx->getPathConstraints()) {
          pathaddrs.push_back(pc.getSourceAddress());
        }
        return pathaddrs;
      }


      void SymbolicExplorator::symbolizeEffectiveAddress(const triton::arch::Instruction& inst) {
        triton::engines::solver::status_e status;
        /* Iterate over operands */
        for (const auto& operand : inst.operands) {
          if (operand.getType() == triton::arch::OP_MEM) {
            auto ea = operand.getConstMemory().getLeaAst();
            if (ea != nullptr && ea->isSymbolized()) {
              auto ast = this->ini_ctx->getAstContext();
              /* Build the path addrs encoding and check if we already asked for this model */
              auto pathaddrs = this->buildPathAddrs();
              pathaddrs.push_back(inst.getAddress());
              if (this->donelist.find(pathaddrs) == this->donelist.end()) {
                /* Adding the path encoding to the donelist */
                this->donelist.insert(pathaddrs);
                /* constraint := (pc && ea != ea.eval) */
                auto c = ast->land(this->ini_ctx->getPathPredicate(), ast->distinct(ea, ast->bv(ea->evaluate(), ea->getBitvectorSize())));
                auto models = this->ini_ctx->getModels(c, this->config.ea_model, &status, this->config.timeout);
                if (status == triton::engines::solver::SAT) {
                  for (auto model : models) {
                    this->nbsat++;
                    this->worklist.push_front(model);
                  }
                }
                else if (status == triton::engines::solver::TIMEOUT) {
                  this->nbtimeout++;
                }
                else {
                  this->nbunsat++;
                }
              }
              // Enforce the value of the EA into the current path predicate
              this->ini_ctx->pushPathConstraint(ast->equal(ea, ast->bv(ea->evaluate(), ea->getBitvectorSize())));
            }
          }
        }
      }


      void SymbolicExplorator::findNewInputs(void) {
        triton::engines::solver::status_e status;
        std::list<triton::uint64> pathaddrs;
        auto pcs = this->ini_ctx->getPathConstraints();
        auto ast = this->ini_ctx->getAstContext();

        /* Building path predicate. Starting wite True. */
        auto predicate = ast->equal(ast->bvtrue(), ast->bvtrue());

        for (const auto& pc : pcs) {
          pathaddrs.push_back(pc.getSourceAddress());
          for (const auto& branch : pc.getBranchConstraints()) {
            /* Do we already generated a model? */
            std::list<triton::uint64> copy(pathaddrs);
            copy.push_back(std::get<2>(branch));
            if (this->donelist.find(copy) != this->donelist.end())
              continue;

            /* Insert the path encoding to the donelist */
            this->donelist.insert(copy);

            /* MultipleBranches is true if the instruction is like jz, jb etc. */
            if (pc.isMultipleBranches()) {
              if (std::get<0>(branch) == false) {
                auto c = ast->land(predicate, std::get<3>(branch));
                auto model = this->ini_ctx->getModel(c, &status, this->config.timeout);
                if (status == triton::engines::solver::SAT) {
                  this->nbsat++;
                  this->worklist.push_front(model);
                }
                else if (status == triton::engines::solver::TIMEOUT) {
                  this->nbtimeout++;
                }
                else {
                  this->nbunsat++;
                }
              }
            }
            /* MultipleBranches is false if the instruction is like jmp rax */
            else {
              auto c = ast->land(predicate, ast->lnot(std::get<3>(branch)));
              auto models = this->ini_ctx->getModels(c, this->config.jmp_model, &status, this->config.timeout);
              if (status == triton::engines::solver::SAT) {
                for (const auto& model : models) {
                  this->nbsat++;
                  this->worklist.push_front(model);
                }
              }
              else if (status == triton::engines::solver::TIMEOUT) {
                this->nbtimeout++;
              }
              else {
                this->nbunsat++;
              }
            }
          }
        predicate = ast->land(predicate, pc.getTakenPredicate());
        }
      }


      std::vector<triton::uint8> SymbolicExplorator::seed2vector(const Seed& seed) {
        std::vector<triton::uint8> ret;

        const auto vars = this->ini_ctx->getSymbolicVariables();
        ret.resize(vars.size());
        for (triton::usize i = 0; i < vars.size(); i++) {
          if (seed.find(i) == seed.end())
            ret[i] = 0x00;
          else
            ret[i] = triton::utils::cast<triton::uint8>(seed.at(i).getValue());
        }

        return ret;
      }


      void SymbolicExplorator::injectSeed(const Seed& seed) {
        for (const auto& item : seed) {
          auto var = this->ini_ctx->getSymbolicVariable(item.first);
          this->ini_ctx->setConcreteVariableValue(var, item.second.getValue());
        }
      }


      std::stringstream SymbolicExplorator::seedRepr(void) {
        std::stringstream ss;
        auto vars = this->ini_ctx->getSymbolicVariables();
        for (triton::usize i = 0; i < vars.size(); i++) {
          ss << std::hex << std::setw(2) << std::setfill('0') << this->ini_ctx->getConcreteVariableValue(vars[i]) << " ";
        }
        return ss;
      }


      void SymbolicExplorator::printStat(void) {
        std::cout << "[TT] exec: " << std::dec << this->nbexec
                  << ",  icov: " << this->coverage.size()
                  << ",  sat: " << this->nbsat
                  << ",  unsat: " << this->nbunsat
                  << ",  timeout: " << this->nbtimeout
                  << ",  worklist: " << this->worklist.size()
                  << std::endl;
      }


      void SymbolicExplorator::hookInstruction(triton::uint64 addr, instCallback fn) {
        this->instHooks.insert(std::pair<triton::uint64, instCallback>(addr, fn));
      }


      void SymbolicExplorator::explore(void) {
        if (this->ini_ctx == nullptr) {
          throw triton::exceptions::Engines("SymbolicExplorator::explore(): The initial context cannot be null.");
        }

        /* Alocate and init a backup context */
        this->bck_ctx = new triton::Context(this->ini_ctx->getArchitecture());
        this->snapshotContext(this->bck_ctx, this->ini_ctx);

        this->initWorklist();
        while (this->worklist.size()) {
          /* Pickup a seed */
          auto seed = *(this->worklist.begin());
          if (this->config.stats) {
            this->printStat();
          }

          /* Remove the seed from the worklist */
          this->worklist.erase(this->worklist.begin());

          /* Inject seed into the context */
          this->injectSeed(seed);

          /* Execute the target */
          this->run(seed);

          /* Generate new seeds */
          this->findNewInputs();

          /* Restore initial context */
          this->snapshotContext(this->ini_ctx, this->bck_ctx);
        }

        /* Last stats */
        if (this->config.stats) {
          this->printStat();
        }

        /* Delete the allocated backup context */
        delete this->bck_ctx;
      }

    }; /* exploration namespace */
  }; /* engines namespace */
}; /*triton namespace */
