//! \file
/*
**  This program is under the terms of the Apache License 2.0.
**  Jonathan Salwan
*/

#ifndef TRITON_ROUTINES_H
#define TRITON_ROUTINES_H


#include <triton/context.hpp>
#include <ttexplore.hpp>



//! The Triton namespace
namespace triton {
/*!
 *  \addtogroup triton
 *  @{
 */

  //! The Routines namespace
  namespace routines {
  /*!
   *  \ingroup triton
   *  \addtogroup routines
   *  @{
   */

    //! printf routine
    triton::callbacks::cb_state_e printf(triton::Context* ctx);

  /*! @} End of routines namespace */
  };
/*! @} End of triton namespace */
};

#endif /* TRITON_ROUTINES_H */
