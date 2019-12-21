// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

#ifndef _ASMTK_GLOBALS_H
#define _ASMTK_GLOBALS_H

#include <asmjit/asmjit.h>

#include <stdint.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>

// DEPRECATED: Will be removed in the future.
#if defined(ASMTK_BUILD_STATIC)
  #pragma message("'ASMTK_BUILD_STATIC' is deprecated, use 'ASMTK_STATIC'")
  #if !defined(ASMTK_STATIC)
    #define ASMTK_STATIC
  #endif
#endif

// API (Export / Import).
#if !defined(ASMTK_STATIC)
  #if defined(_WIN32) && (defined(_MSC_VER) || defined(__MINGW32__))
    #if defined(ASMTK_EXPORTS)
      #define ASMTK_API __declspec(dllexport)
    #else
      #define ASMTK_API __declspec(dllimport)
    #endif
  #elif defined(_WIN32) && defined(__GNUC__)
    #if defined(ASMTK_EXPORTS)
      #define ASMTK_API __attribute__((__dllexport__))
    #else
      #define ASMTK_API __attribute__((__dllimport__))
    #endif
  #elif defined(__GNUC__)
    #define ASMTK_API __attribute__((__visibility__("default")))
  #endif
#endif

#if !defined(ASMTK_API)
  #define ASMTK_API
#endif

namespace asmtk {

// ============================================================================
// [asmtk::Types]
// ============================================================================

using asmjit::Error;

} // {asmtk}

#endif // _ASMTK_GLOBALS_H
