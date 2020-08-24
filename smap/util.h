#pragma once

#define ASMJIT_STATIC
#define ASMJIT_BUILD_RELEASE
#define ASMJIT_BUILD_X86

#include <Zydis/Zydis.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>

#define GP_REGISTER_COUNT ((ZYDIS_REGISTER_R15 - ZYDIS_REGISTER_RAX) + 1)
#define ABSOLUTE_SIG (reinterpret_cast<PVOID>(0x123456789ABCDEFULL))
#define errorf(fmt, ...)                                                       \
  fprintf(stderr, "\n[error at %s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

typedef struct {
    MODULEENTRY32 Module;
    std::vector<IMAGE_SECTION_HEADER> Sections;
} MODULE;

namespace Util {
    PROCESSENTRY32 GetProcessInfoByName(LPCWSTR name);
    MODULEENTRY32 GetModuleInfoByName(HANDLE process, LPCWSTR name);
    std::vector<MODULE> GetProcessModules(HANDLE process);
    std::vector<IMAGE_SECTION_HEADER> GetModuleSections(HANDLE process,
        MODULEENTRY32 &module);
    ZydisDecodedInstruction Disassemble(PVOID buffer, DWORD length);
    std::vector<ZydisDecodedOperand>
        GetInstructionOperands(ZydisDecodedInstruction &instruction);
    BOOLEAN IsSameRegister(ZydisRegister a, ZydisRegister b);
    std::string FormatInstruction(ZydisDecodedInstruction &instruction,
        PVOID address);
    BOOLEAN Assemble(LPCSTR text, PBYTE &buffer, DWORD &bufferSize);
    ZydisRegister GetUnusedRegister(ZydisDecodedInstruction &instruction);
    PVOID GetInstructionAbsoluteAddress(PVOID rva,
        ZydisDecodedInstruction &instruction);
    DWORD GetAbsoluteSigOffset(PVOID buffer, DWORD size);

    template <typename... Args>
    BOOLEAN Assemble(PBYTE &buffer, DWORD &bufferSize, LPCSTR fmt, Args... args) {
        auto size = static_cast<SIZE_T>(snprintf(nullptr, 0, fmt, args...));
        if (!size) {
            return FALSE;
        }

        ++size;
        auto formatted = new CHAR[size];
        sprintf_s(formatted, size, fmt, args...);

        auto success = Assemble(formatted, buffer, bufferSize);

        delete[] formatted;

        return success;
    }
}