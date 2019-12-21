// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

#ifndef _ASMTK_ASMTOKENIZER_H
#define _ASMTK_ASMTOKENIZER_H

#include "./globals.h"
#include "./strtod.h"

namespace asmtk {

// ============================================================================
// [asmtk::AsmToken]
// ============================================================================

//! Token.
struct AsmToken {
  enum Type : uint32_t {
    kEnd,
    kNL,
    kSym,
    kNSym,
    kU64,
    kF64,
    kLCurl,
    kRCurl,
    kLBracket,
    kRBracket,
    kLParen,
    kRParen,
    kAdd,
    kSub,
    kMul,
    kDiv,
    kComma,
    kColon,
    kOther,
    kInvalid
  };

  template<typename... Args>
  inline bool _isImpl(size_t index, char c) noexcept {
    return data[index] == c;
  }

  template<typename... Args>
  inline bool _isImpl(size_t index, char c, Args&&... args) noexcept {
    return data[index] == c && _isImpl(index + 1, args...);
  }

  template<typename... Args>
  inline bool is(Args&&... args) noexcept {
    return size == sizeof...(args) && _isImpl(0, args...);
  }

  inline void reset() noexcept {
    type = kEnd;
    data = nullptr;
    size = 0;
    u64 = 0;
  }

  inline uint32_t setData(uint32_t type, const uint8_t* data, size_t size) noexcept {
    this->data = data;
    this->size = size;
    this->type = type;
    return type;
  }

  inline uint32_t setData(uint32_t type, const uint8_t* data, const uint8_t* end) noexcept {
    return setData(type, data, (size_t)(end - data));
  }

  uint32_t type;
  const uint8_t* data;
  size_t size;

  union {
    double f64;
    int64_t i64;
    uint64_t u64;
    uint8_t valueBytes[8];
  };
};

// ============================================================================
// [asmtk::AsmTokenizer]
// ============================================================================

//! Tokenizer.
class AsmTokenizer {
public:
  //! Tokenizer options.
  enum ParseFlags : uint32_t {
    kParseSymbol          = 0x00000001u, //!< Don't attempt to parse number (always parse symbol).
    kParseDashes          = 0x00000002u  //!< Consider dashes as text in a parsed symbol.
  };

  //! Flags used during tokenization (cannot be used as options).
  enum StateFlags : uint32_t {
    kStateDotPrefix       = 0x10000000u, //!< Parsed '.' prefix.
    kStateDollarPrefix    = 0x20000000u, //!< Parsed '$' prefix.
    kStateNumberPrefix    = 0x40000000u, //!< Parsed number prefix [0b|0x].
    kStateNumberSuffix    = 0x80000000u  //!< Parsed number suffix [b|o|q|h].
  };

  //! Creates a tokanizer.
  ASMTK_API AsmTokenizer() noexcept;
  //! Destroys the tokanizer.
  ASMTK_API ~AsmTokenizer() noexcept;

  //! Parses a next `token` and advances.
  ASMTK_API uint32_t next(AsmToken* token, uint32_t flags = 0) noexcept;

  //! Puts a token back to the tokenizer so that `next()` would parse it again.
  inline void putBack(AsmToken* token) noexcept {
    _cur = token->data;
  }

  //! Sets the input of the tokenizer to `input` and `size`. The input doesn't
  //! have to be null terminated as the tokenizer would never go beyond the
  //! `size` specified. This means that the tokenizer can be used with string
  //! views.
  inline void setInput(const uint8_t* input, size_t size) noexcept {
    _input = input;
    _end = input + size;
    _cur = input;
  }

  const uint8_t* _input;
  const uint8_t* _end;
  const uint8_t* _cur;

  StrToD _stodctx;
};

} // {asmtk}

#endif // _ASMTK_ASMTOKENIZER_H
