// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

#ifndef _ASMTK_STRTOD_H
#define _ASMTK_STRTOD_H

#include "./globals.h"

#if defined(_WIN32)
  #define ASMTK_STRTOD_MSLOCALE
  #include <locale.h>
  #include <stdlib.h>
#else
  #define ASMTK_STRTOD_XLOCALE
  #include <locale.h>
  #include <stdlib.h>
  // xlocale.h is not available on Linux anymore, it uses <locale.h>.
  #if defined(__APPLE__    ) || \
      defined(__bsdi__     ) || \
      defined(__DragonFly__) || \
      defined(__FreeBSD__  ) || \
      defined(__NetBSD__   ) || \
      defined(__OpenBSD__  )
    #include <xlocale.h>
  #endif
#endif

namespace asmtk {

// ============================================================================
// [asmtk::StrToD]
// ============================================================================

class StrToD {
public:
#if defined(ASMTK_STRTOD_MSLOCALE)
  inline StrToD() { handle = _create_locale(LC_ALL, "C"); }
  inline ~StrToD() { _free_locale(handle); }

  inline bool isOk() const { return handle != NULL; }
  inline double conv(const char* s, char** end) const { return _strtod_l(s, end, handle); }

  _locale_t handle;
#elif defined(ASMTK_STRTOD_XLOCALE)
  inline StrToD() { handle = newlocale(LC_ALL_MASK, "C", NULL); }
  inline ~StrToD() { freelocale(handle); }

  inline bool isOk() const { return handle != NULL; }
  inline double conv(const char* s, char** end) const { return strtod_l(s, end, handle); }

  locale_t handle;
#else
  // Time bomb!
  inline bool isOk() const { return true; }
  inline double conv(const char* s, char** end) const { return strtod(s, end); }
#endif
};

} // {asmtk}

#endif // _ASMTK_STRTOD_H
