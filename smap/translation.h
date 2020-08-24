#pragma once

#include "region.h"
#include "util.h"
#include <memory>

#define TranslatorException() (1)

class Translator;

class Translation {
private:
    Region VirtualAddress;
    PBYTE MappedAddress = nullptr;
    BOOLEAN FreeMappedOnFail = FALSE;

public:
    // Returns this translation's relative virtual address and size
    inline Region RVA() noexcept { return this->VirtualAddress; }

    // Updates this translation's RVA
    inline VOID RVA(Region rva) noexcept { this->VirtualAddress = rva; }

    // Returns the mapped address of this translation
    inline PBYTE Mapped() noexcept { return this->MappedAddress; }

    // Updates the mapped address for this translation
    inline VOID Mapped(PVOID mapped, BOOLEAN freeMappedOnFail = FALSE) noexcept {
        this->MappedAddress = reinterpret_cast<PBYTE>(mapped);
        this->FreeMappedOnFail = freeMappedOnFail;
    }

    // Returns whether the mapped address should be freed on failure
    inline BOOLEAN FreeOnFail() noexcept { return this->FreeMappedOnFail; }

    // Returns a pointer to this translations raw buffer
    virtual PVOID Buffer() noexcept = 0;

    // Returns this translations buffer size
    virtual DWORD BufferSize() noexcept = 0;

    // Returns whether this translation is executable code
    virtual BOOLEAN Executable() noexcept = 0;

    // Resolves all relative addresses to point to the mapped addresses
    virtual BOOLEAN Resolve(Translator &translator) = 0;

    // Undoes up any changes done to the external process
    virtual VOID Fail(Translator &translator) = 0;
};

class DefaultTranslation : public Translation {
private:
    PVOID PointerToRawData = nullptr;
    DWORD SizeOfRawData = 0;

public:
    inline DefaultTranslation(Region rva, PVOID buffer, DWORD size) noexcept
        : PointerToRawData{ buffer }, SizeOfRawData{ size } {
        this->RVA(rva);
    }

    inline PVOID Buffer() noexcept { return this->PointerToRawData; }
    inline DWORD BufferSize() noexcept { return this->SizeOfRawData; }
    inline BOOLEAN Executable() noexcept { return TRUE; }

    inline BOOLEAN Resolve(Translator &) noexcept { return TRUE; }

    VOID Fail(Translator &translator);
};

class RegionTranslation : public Translation {
private:
    PVOID PointerToRawData = nullptr;
    DWORD SizeOfRawData = 0;

public:
    inline RegionTranslation(Region rva, PVOID mapped, PVOID buffer,
        DWORD size) noexcept
        : PointerToRawData{ buffer }, SizeOfRawData{ size } {
        this->RVA(rva);
        this->Mapped(mapped, TRUE);
    }

    inline PVOID Buffer() noexcept { return this->PointerToRawData; }
    inline DWORD BufferSize() noexcept { return this->SizeOfRawData; }
    inline BOOLEAN Executable() noexcept { return FALSE; }

    inline BOOLEAN Resolve(Translator &) noexcept { return TRUE; }

    VOID Fail(Translator &translator);
};

class ModifiedTranslation : public Translation {
private:
    std::unique_ptr<BYTE[]> RawData;
    DWORD SizeOfRawData = 0;

public:
    inline ModifiedTranslation(Region rva, PVOID buffer,
        DWORD bufferSize) noexcept
        : RawData{ std::unique_ptr<BYTE[]>(reinterpret_cast<PBYTE>(buffer)) },
        SizeOfRawData{ bufferSize } {
        this->RVA(rva);
    }

    template <typename... Args>
    ModifiedTranslation(Region rva, LPCSTR fmt, Args... args) {
        PBYTE buffer = 0;
        auto bufferSize = 0UL;

        auto success = Util::Assemble(buffer, bufferSize, fmt, args...);
        if (!success) {
            errorf("failed to generate valid assembly for modified translation\n\t");
            fprintf(stderr, fmt, args...);
            fprintf(stderr, "\n\tat %p\n", rva.Start());

            throw TranslatorException();
        }

        this->RVA(rva);
        this->RawData = std::unique_ptr<BYTE[]>(buffer);
        this->SizeOfRawData = bufferSize;
    }

    inline PVOID Buffer() noexcept { return this->RawData.get(); }
    inline DWORD BufferSize() noexcept { return this->SizeOfRawData; }
    inline BOOLEAN Executable() noexcept { return TRUE; }

    inline BOOLEAN Resolve(Translator &) { return TRUE; }

    VOID Fail(Translator &translator);
};

class RelativeTranslation : public Translation {
private:
    std::unique_ptr<BYTE[]> RawData;
    DWORD SizeOfRawData = 0;
    DWORD RvaOffset = 0;

public:
    inline RelativeTranslation(Region rva, PBYTE buffer, DWORD bufferSize,
        DWORD rvaOffset) noexcept
        : RawData{ std::unique_ptr<BYTE[]>(buffer) },
        SizeOfRawData{ bufferSize }, RvaOffset{ rvaOffset } {
        this->RVA(rva);
    }

    template <typename... Args>
    RelativeTranslation(Region rva, PVOID absoluteAddr, LPCSTR fmt,
        Args... args) {
        PBYTE buffer = nullptr;
        auto bufferSize = 0UL;

        auto success = Util::Assemble(buffer, bufferSize, fmt, args...);
        if (!success) {
            errorf("failed to generate valid assembly for relative translation\n\t");
            fprintf(stderr, fmt, args...);
            fprintf(stderr, "\n\tat %p\n", rva.Start());

            throw TranslatorException();
        }

        this->RVA(rva);
        this->RawData = std::unique_ptr<BYTE[]>(buffer);
        this->SizeOfRawData = bufferSize;
        this->RvaOffset = Util::GetAbsoluteSigOffset(buffer, bufferSize);

        if (!this->RvaOffset) {
            errorf("relative translation assembly does not contain absolute sig\n");
            throw TranslatorException();
        }

        this->Pointer() = absoluteAddr;
    }

    inline PVOID Buffer() noexcept { return this->RawData.get(); }
    inline DWORD BufferSize() noexcept { return this->SizeOfRawData; }
    inline PVOID &Pointer() noexcept {
        return *reinterpret_cast<PVOID *>(reinterpret_cast<PBYTE>(this->Buffer()) +
            this->RvaOffset);
    }
    inline BOOLEAN Executable() noexcept { return TRUE; }

    BOOLEAN Resolve(Translator &translator);
    VOID Fail(Translator &translator);
};

class SwitchTranslation : public Translation {
private:
    PVOID PointerToRawData = nullptr;
    DWORD SizeOfRawData = 0;
    std::vector<PVOID> JumpTable;
    PVOID MappedJumpTable = nullptr;
    PVOID MappedIndirectJumpTable = nullptr;

public:
    inline SwitchTranslation(Region rva, PBYTE buffer, DWORD bufferSize,
        std::vector<PVOID> jumpTable, PVOID mappedJumpTable,
        PVOID mappedIndirectJumpTable = nullptr) noexcept
        : PointerToRawData{ buffer }, SizeOfRawData{ bufferSize },
        JumpTable{ jumpTable }, MappedJumpTable{ mappedJumpTable },
        MappedIndirectJumpTable{ mappedIndirectJumpTable } {
        this->RVA(rva);
    }

    inline PVOID Buffer() noexcept { return this->PointerToRawData; }
    inline DWORD BufferSize() noexcept { return this->SizeOfRawData; }
    inline BOOLEAN Executable() noexcept { return TRUE; }

    BOOLEAN Resolve(Translator &translator);
    VOID Fail(Translator &translator);
};