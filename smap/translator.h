#pragma once

#include <Zydis/Zydis.h>
#include "translation.h"
#include "region.h"
#include <memory>
#include <map>

class Translation;

class Translator {
private:
    HANDLE ProcessHandle = nullptr;
    PBYTE ImageBase = nullptr;
    PIMAGE_NT_HEADERS NtHeaders = nullptr;
    std::vector<std::unique_ptr<Translation>> Translations;
    std::map<PVOID, PVOID> Branches;

    BOOLEAN MapHeaders();
    std::vector<PVOID> GetExports();
    BOOLEAN ResolveImports();
    BOOLEAN ResolveRelocations();
    Translation *AlignExport(SIZE_T &translationIndex, SIZE_T translationsCount,
        std::vector<Region> &regions, SIZE_T regionStart,
        SIZE_T regionEnd);
    VOID TraceBranch(INT &translationIndex, INT startingIndex);
    BOOLEAN IsRegisterAbsolute(ZydisRegister reg, INT translationIndex,
        INT startingIndex, PVOID &absolute);
    BOOLEAN AddSwitchTranslation(Region &rva, PBYTE jumpBuffer,
        ZydisDecodedInstruction &jumpInstruction);
    VOID AddRelativeTranslation(Region &rva, PBYTE instructionBuffer,
        ZydisDecodedInstruction &instruction);
    BOOLEAN IsRegisterBase(ZydisRegister reg, INT translationIndex,
        INT startingIndex);
    VOID FixSIB(INT translationIndex, INT startingIndex);
    VOID AddSection(PBYTE base, PIMAGE_SECTION_HEADER section);
    VOID AddExecuteSection(PBYTE base, PIMAGE_SECTION_HEADER section);

    // Removes a translation at the specified index
    inline VOID RemoveTranslation(SIZE_T index) {
        this->Translations.erase(this->Translations.begin() + index);
    }

    // Adds a new translation
    inline VOID AddTranslation(Translation *translation) {
        this->Translations.push_back(std::unique_ptr<Translation>(translation));
    }

    // Inserts a translation at the specified index
    inline VOID InsertTranslation(SIZE_T index, Translation *translation) {
        this->Translations.insert(this->Translations.begin() + index,
            std::unique_ptr<Translation>(translation));
    }

    // Replaces the translation at specified index
    inline VOID ReplaceTranslation(SIZE_T index, Translation *translation) {
        this->Translations[index] = std::unique_ptr<Translation>(translation);
    }

    // Adds a branch pointing from src to dest
    inline VOID AddBranch(PVOID dest, PVOID src) {
        if (this->Branches.find(dest) == this->Branches.end())
            this->Branches[dest] = src;
    }

public:
    BOOLEAN Initialize(HANDLE process, PBYTE base);
    BOOLEAN Align(std::vector<Region> &regions, DWORD scatterThreshold = 1);
    BOOLEAN Resolve();
    BOOLEAN Map(PVOID &entry);

    PVOID Translate(PVOID rva);
    inline PVOID Translate(UINT_PTR rva) {
        return this->Translate(reinterpret_cast<PVOID>(rva));
    }

    PVOID TranslateRaw(PVOID rva);
    inline PVOID TranslateRaw(UINT_PTR rva) {
        return this->TranslateRaw(reinterpret_cast<PVOID>(rva));
    }
    template <typename Tr, typename Ta> inline Tr TranslateRaw(Ta rva) {
        return reinterpret_cast<Tr>(this->TranslateRaw(rva));
    }

    PIMAGE_SECTION_HEADER TranslateRawSection(PVOID rva);

    inline HANDLE Process() noexcept { return this->ProcessHandle; }
    inline VOID Fail() {
        for (auto &t : this->Translations)
            t->Fail(*this);
    }
};