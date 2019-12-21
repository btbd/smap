// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

#ifndef _ASMTK_ELFDEFS_H
#define _ASMTK_ELFDEFS_H

#include "./globals.h"

namespace asmtk {

enum ElfFileType : uint32_t {
  kElfFileType_NONE         = 0,
  kElfFileType_REL          = 1,
  kElfFileType_EXEC         = 2,
  kElfFileType_DYN          = 3,
  kElfFileType_CORE         = 4,
  kElfFileType_LOPROC       = 0xFF00,
  kElfFileType_HIPROC       = 0xFFFF
};

enum ElfFileVersion : uint32_t {
  kElfFileVersion_NONE      = 0,
  kElfFileVersion_CURRENT   = 1
};

enum ElfFileClass : uint32_t {
  kElfFileClass_NONE        = 0,
  kElfFileClass_32          = 1,
  kElfFileClass_64          = 2
};

enum ElfFileEncoding : uint32_t {
  ElfFileEncoding_NONE      = 0,
  ElfFileEncoding_LE        = 1,
  ElfFileEncoding_BE        = 2
};

enum ElfMachineType : uint32_t {
  kElfMachineType_NONE      = 0,
  kElfMachineType_X86       = 3,
  kElfMachineType_ARM       = 40,
  kElfMachineType_X86_64    = 62
};

enum ElfOSABI : uint32_t {
  kElfOSABI_NONE            = 0,         //!< UNIX System V ABI.
  kElfOSABI_HPUX            = 1,
  kElfOSABI_NETBSD          = 2,
  kElfOSABI_GNU             = 3,         //!< GNU/Linux.
  kElfOSABI_HURD            = 4,
  kElfOSABI_SOLARIS         = 6,
  kElfOSABI_AIX             = 7,
  kElfOSABI_IRIX            = 8,
  kElfOSABI_FREEBSD         = 9,
  kElfOSABI_TRU64           = 10,
  kElfOSABI_MODESTO         = 11,
  kElfOSABI_OPENBSD         = 12,
  kElfOSABI_OPENVMS         = 13,
  kElfOSABI_NSK             = 14,
  kElfOSABI_AROS            = 15,
  kElfOSABI_FENIXOS         = 16,
  kElfOSABI_CLOUDABI        = 17,
  kElfOSABI_ARM             = 97,
  kElfOSABI_STANDALONE      = 255
};

struct ElfIdentData {
  uint8_t magic[4];
  uint8_t classType;
  uint8_t dataType;
  uint8_t version;
  uint8_t abi;
  uint8_t abiVersion;
  uint8_t reserved[7];
};

template<typename ElfPtrT>
struct ElfFileData {
  ElfIdentData ident;
  uint16_t type;
  uint16_t machine;
  uint32_t version;
  ElfPtrT entry;
  ElfPtrT phOffset;
  ElfPtrT shOffset;
  uint32_t flags;
  uint16_t ehSize;
  uint16_t phEntSize;
  uint16_t phNum;
  uint16_t shEndSize;
  uint16_t shNum;
  uint16_t shStrNdx;
};

typedef ElfFileData<uint32_t> ElfFileData32;
typedef ElfFileData<uint64_t> ElfFileData64;

template<typename ElfPtrT>
struct ElfProgramData {};

template<>
struct ElfProgramData<uint32_t> {
  uint32_t type;     //!< Segment type.
  uint32_t offset;   //!< Segment offset.
  uint32_t vaddr;    //!< Virtual address.
  uint32_t paddr;    //!< Physical address.
  uint32_t fileSize; //!< Size of file image (or zero).
  uint32_t memSize;  //!< Size of memory image (or zero).
  uint32_t flags;    //!< Segment flags.
  uint32_t align;    //!< Segment alignment.
};

template<>
struct ElfProgramData<uint64_t> {
  uint32_t type;     //!< Segment type.
  uint32_t flags;    //!< Segment flags.
  uint64_t offset;   //!< Segment offset.
  uint64_t vaddr;    //!< Virtual address.
  uint64_t paddr;    //!< Physical address.
  uint64_t fileSize; //!< Size of file image (or zero).
  uint64_t memSize;  //!< Size of memory image (or zero).
  uint64_t align;    //!< Segment alignment.
};

typedef ElfProgramData<uint32_t> ElfProgramData32;
typedef ElfProgramData<uint64_t> ElfProgramData64;

template<typename ElfPtrT>
struct ElfSectionData {
  uint32_t name;     //!< Section name (index).
  uint32_t type;     //!< Section type.
  ElfPtrT flags;     //!< Section flags.
  ElfPtrT addr;      //!< Section address.
  ElfPtrT offset;    //!< Section file-offset.
  ElfPtrT size;      //!< Section size.
  uint32_t link;
  uint32_t info;
  ElfPtrT addrAlign;
  ElfPtrT entSize;
};
typedef ElfSectionData<uint32_t> ElfSectionData32;
typedef ElfSectionData<uint64_t> ElfSectionData64;

template<typename ElfPtrT>
struct ElfSymbolData {};

template<>
struct ElfSymbolData<uint32_t> {
  uint32_t name;     //!< Symbol name (index).
  uint32_t value;    //!< Symbol address.
  uint32_t size;     //!< Symbol size.
  uint8_t info;      //!< Symbol information.
  uint8_t reserved;  //!< Reserved (zero).
  uint16_t shndx;    //!< Section index.
};

template<>
struct ElfSymbolData<uint64_t> {
  uint32_t name;     //!< Symbol name (index).
  uint8_t info;      //!< Symbol information.
  uint8_t other;     //!< Reserved (zero).
  uint16_t shndx;    //!< Section index.
  uint64_t value;    //!< Symbol address.
  uint64_t size;     //!< Symbol size.
};

typedef ElfSymbolData<uint32_t> ElfSymbolData32;
typedef ElfSymbolData<uint64_t> ElfSymbolData64;

} // {asmtk}

#endif // _ASMTK_ELFDEFS_H
