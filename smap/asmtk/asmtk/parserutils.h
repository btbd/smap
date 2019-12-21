// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

#ifndef _ASMTK_PARSERUTILS_H
#define _ASMTK_PARSERUTILS_H

#include <asmjit/asmjit.h>

#include <stdint.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace asmtk {
namespace ParserUtils {

// ============================================================================
// [asmtk::ParserUtils::WordParser]
// ============================================================================

class WordParser {
public:
  #if ASMJIT_ARCH_BITS == 32
  typedef uint32_t Value;
  #else
  typedef uint64_t Value;
  #endif

  static constexpr uint32_t kNumValues =
    uint32_t((8 + sizeof(Value) - 1) / sizeof(Value));

  constexpr WordParser() noexcept
    : _value { 0 } {}

  inline void reset() noexcept {
    for (size_t i = 0; i < ASMJIT_ARRAY_SIZE(_value); i++)
      _value[i] = 0;
  }

  template<typename T>
  inline void addChar(const T* input, size_t i) noexcept {
    size_t nIndex = i / sizeof(Value);
    size_t nByte  = i % sizeof(Value);
    _value[nIndex] |= Value(uint8_t(input[i])) << (nByte * 8u);
  }

  template<typename T>
  inline void addLowercasedChar(const T* input, size_t i) noexcept {
    size_t nIndex = i / sizeof(Value);
    size_t nByte  = i % sizeof(Value);
    _value[nIndex] |= Value(asmjit::Support::asciiToLower(uint8_t(input[i]))) << (nByte * 8u);
  }

  inline bool test(char x0, char x1 = '\0', char x2 = '\0', char x3 = '\0') const noexcept {
    uint32_t pattern0 = (uint32_t(uint8_t(x0)) <<  0) |
                        (uint32_t(uint8_t(x1)) <<  8) |
                        (uint32_t(uint8_t(x2)) << 16) |
                        (uint32_t(uint8_t(x3)) << 24) ;
    return uint32_t(_value[0] & 0xFFFFFFFFu) == pattern0;
  }

  inline bool test(char x0, char x1, char x2, char x3,
                   char x4, char x5 = '\0', char x6 = '\0', char x7 = '\0') const noexcept {
    uint32_t pattern0 = (uint32_t(uint8_t(x0)) <<  0) |
                        (uint32_t(uint8_t(x1)) <<  8) |
                        (uint32_t(uint8_t(x2)) << 16) |
                        (uint32_t(uint8_t(x3)) << 24) ;
    uint32_t pattern1 = (uint32_t(uint8_t(x4)) <<  0) |
                        (uint32_t(uint8_t(x5)) <<  8) |
                        (uint32_t(uint8_t(x6)) << 16) |
                        (uint32_t(uint8_t(x7)) << 24) ;
    #if ASMJIT_ARCH_BITS == 32
    return (_value[0] == pattern0) &
           (_value[1] == pattern1) ;
    #else
    return (_value[0] == (uint64_t(pattern0) | (uint64_t(pattern1) << 32)));
    #endif
  }

  Value _value[kNumValues];
};

} // {ParserUtils}
} // {asmtk}

#endif // _ASMTK_PARSERUTILS_H
