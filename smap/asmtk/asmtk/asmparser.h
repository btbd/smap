// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

#ifndef _ASMTK_ASMPARSER_H
#define _ASMTK_ASMPARSER_H

#include "./strtod.h"
#include "./asmtokenizer.h"

namespace asmtk {

// ============================================================================
// [asmtk::AsmParser]
// ============================================================================

//! Asm parser.
class AsmParser {
public:
  typedef Error (ASMJIT_CDECL* UnknownSymbolHandler)(
    AsmParser* parser, asmjit::Operand* out, const char* name, size_t size);

  asmjit::BaseEmitter* _emitter;
  AsmTokenizer _tokenizer;

  size_t _currentCommandOffset;
  bool _endOfInput;

  UnknownSymbolHandler _unknownSymbolHandler;
  void* _unknownSymbolHandlerData;

  //! \name Construction & Destruction
  //! \{

  ASMTK_API AsmParser(asmjit::BaseEmitter* emitter) noexcept;
  ASMTK_API ~AsmParser() noexcept;

  //! \}

  //! \name Accessors
  //! \{

  inline asmjit::BaseEmitter* emitter() const noexcept { return _emitter; }

  //! \}

  //! \name Input Buffer
  //! \{

  inline const char* input() const noexcept {
    return reinterpret_cast<const char*>(_tokenizer._input);
  }

  inline bool setInput(const char* input, size_t size = SIZE_MAX) noexcept {
    if (size == SIZE_MAX)
      size = strlen(input);

    _tokenizer.setInput(reinterpret_cast<const uint8_t*>(input), size);
    _currentCommandOffset = 0;
    _endOfInput = (size == 0);

    return _endOfInput;
  }

  inline bool isEndOfInput() const noexcept { return _endOfInput; }
  inline size_t currentCommandOffset() const noexcept { return _currentCommandOffset; }

  ASMTK_API uint32_t nextToken(AsmToken* token, uint32_t flags = 0) noexcept;
  ASMTK_API void putTokenBack(AsmToken* token) noexcept;

  //! \}

  //! \name Unknown Symbol Handler
  //! \{

  inline UnknownSymbolHandler unknownSymbolHandler() const noexcept { return _unknownSymbolHandler; }
  inline void* unknownSymbolHandlerData() const noexcept { return _unknownSymbolHandlerData; }

  inline void setUnknownSymbolHandler(UnknownSymbolHandler handler, void* data = nullptr) noexcept {
    _unknownSymbolHandler = handler;
    _unknownSymbolHandlerData = data;
  }

  inline void resetUnknownSymbolHandler() noexcept {
    setUnknownSymbolHandler((UnknownSymbolHandler)nullptr, nullptr);
  }

  //! \}

  //! \name Parser
  //! \{

  //! Universal method that setups the input and then calls `parseLine()` until
  //! the end is reached. It returns `kErrorOk` on success (which means that all
  //! commands were parsed successfully), otherwise and error code describing
  //! the problem.
  ASMTK_API Error parse(const char* input, size_t size = SIZE_MAX) noexcept;

  ASMTK_API Error parseCommand() noexcept;

  //! \}
};

} // {asmtk}

#endif // _ASMTK_ASMPARSER_H
