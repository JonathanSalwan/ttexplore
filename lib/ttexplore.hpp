//! \file
/*
**  This program is under the terms of the Apache License 2.0.
**  Jonathan Salwan
*/

#ifndef TRITON_TTEXPLORE_H
#define TRITON_TTEXPLORE_H


#include <list>
#include <map>
#include <sstream>
#include <unordered_map>
#include <vector>

#include <triton/comparableFunctor.hpp>
#include <triton/context.hpp>
#include <triton/dllexport.hpp>
#include <triton/pathConstraint.hpp>
#include <triton/solverModel.hpp>
#include <triton/tritonTypes.hpp>



//! The Triton namespace
namespace triton {
/*!
 *  \addtogroup triton
 *  @{
 */

  //! The Callbacks namespace
  namespace callbacks {
  /*!
   *  \ingroup triton
   *  \addtogroup callbacks
   *  @{
   */

    //! State of callback
    enum cb_state_e {
      CONTINUE,
      BREAK,
      PLT_CONTINUE,
    };

  };

  //! The Engines namespace
  namespace engines {
  /*!
   *  \ingroup triton
   *  \addtogroup engines
   *  @{
   */

    //! The Symbolic Exploration namespace
    namespace exploration {
    /*!
     *  \ingroup engines
     *  \addtogroup symbolic
     *  @{
     */

      //! Shortcut for a seed.
      using Seed = std::unordered_map<triton::usize, triton::engines::solver::SolverModel>;

      //! Config of the exploration.
      struct config_s {
        bool            stats;
        std::string     workspace = "workspace";
        triton::uint64  end_point;
        triton::usize   ea_model;
        triton::usize   jmp_model;
        triton::usize   limit_inst;
        triton::usize   timeout; /* seconds */
      };

      //! Instruction callback signature
      using instCallback = triton::ComparableFunctor<triton::callbacks::cb_state_e(triton::Context*)>;

      /*! \class SymbolicExplorator
          \brief The symbolic explorator class. */
      class SymbolicExplorator {
        private:
          //! Execute one trace.
          void run(const Seed& seed);

          //! Init the worklist.
          void initWorklist(void);

          //! Snaptshot context from src to dst.
          void snapshotContext(triton::Context* dst, triton::Context* src);

          //! Find new inputs and update the path tree.
          void findNewInputs(void);

          //! Inject a seed into the state.
          void injectSeed(const Seed& seed);

          //! Pretty print a seed.
          std::stringstream seedRepr(void);

          //! Print stats at each execution
          void printStat(void);

          //! Symbolize LOAD and STORE accesses.
          void symbolizeEffectiveAddress(const triton::arch::Instruction& inst);

          //! Build the path encoding
          std::list<triton::uint64> buildPathAddrs(void);

          //! Convert a seed to a vector.
          std::vector<triton::uint8> seed2vector(const Seed& seed);

          //! Write the seed into the given directory
          void writeSeedOnDisk(const std::string& dir, const Seed& seed);

          //! Execute a ret instruction according to the architecture
          void asmret(void);

        protected:
          //! Number of executions
          triton::usize nbexec;

          //! Number of sat
          triton::usize nbsat;

          //! Number of unsat
          triton::usize nbunsat;

          //! Number of timeout
          triton::usize nbtimeout;

          //! Initial context.
          triton::Context* ini_ctx;

          //! Backup context.
          triton::Context* bck_ctx;

          //! Worklist.
          std::list<Seed> worklist;

          //! Donelist
          std::set<std::list<triton::uint64>> donelist;

          //! The coverage map <inst addr: number of hits>
          std::unordered_map<triton::uint64, triton::usize> coverage;

          //! Hook instructions: <plt addr : cb>
          std::map<triton::uint64, instCallback> instHooks;

        public:
          struct config_s config;

          //! Constructor.
          TRITON_EXPORT SymbolicExplorator();

          //! Constructor.
          TRITON_EXPORT SymbolicExplorator(triton::Context* ctx);

          //! Destructor.
          TRITON_EXPORT ~SymbolicExplorator();

          //! Init context.
          TRITON_EXPORT void initContext(triton::Context* ctx);

          //! Explore the program.
          TRITON_EXPORT void explore(void);

          //! Dump the code coverage
          TRITON_EXPORT void dumpCoverage(void);

          //! Add callback
          TRITON_EXPORT void hookInstruction(triton::uint64 addr, instCallback fn);
      };

    /*! @} End of exploration namespace */
    };
  /*! @} End of engines namespace */
  };
/*! @} End of triton namespace */
};

#endif /* TRITON_TTEXPLORE_H */
