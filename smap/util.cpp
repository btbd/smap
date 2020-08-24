#include "util.h"
#include <mutex>

#pragma warning(push, 0)
#include <asmtk/asmtk.h>
#pragma comment(lib, "Zydis.lib")
#pragma warning(pop)

PROCESSENTRY32 Util::GetProcessInfoByName(LPCWSTR name) {
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return { 0 };
    }

    PROCESSENTRY32 entry = { 0 };
    entry.dwSize = sizeof(entry);
    if (Process32First(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name) == 0) {
                CloseHandle(snapshot);
                return entry;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return { 0 };
}

MODULEENTRY32 Util::GetModuleInfoByName(HANDLE process, LPCWSTR name) {
    auto snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));
    if (snapshot == INVALID_HANDLE_VALUE) {
        return { 0 };
    }

    MODULEENTRY32 entry = { 0 };
    entry.dwSize = sizeof(entry);
    if (Module32First(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, name) == 0) {
                CloseHandle(snapshot);
                return entry;
            }
        } while (Module32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return { 0 };
}

std::vector<MODULE> Util::GetProcessModules(HANDLE process) {
    std::vector<MODULE> modules;

    auto snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));
    if (snapshot == INVALID_HANDLE_VALUE) {
        return modules;
    }

    MODULEENTRY32 entry = { 0 };
    entry.dwSize = sizeof(entry);
    if (Module32First(snapshot, &entry)) {
        do {
            MODULE module = { 0 };
            module.Module = entry;
            module.Sections = GetModuleSections(process, entry);

            modules.push_back(module);
        } while (Module32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return modules;
}

std::vector<IMAGE_SECTION_HEADER>
Util::GetModuleSections(HANDLE process, MODULEENTRY32 &module) {
    std::vector<IMAGE_SECTION_HEADER> sections;

    IMAGE_DOS_HEADER dosHeader = { 0 };
    IMAGE_NT_HEADERS ntHeaders = { 0 };

    if (!ReadProcessMemory(process, module.modBaseAddr, &dosHeader,
        sizeof(dosHeader), nullptr)) {
        return sections;
    }

    if (!ReadProcessMemory(process, module.modBaseAddr + dosHeader.e_lfanew,
        &ntHeaders, sizeof(ntHeaders), nullptr)) {
        return sections;
    }

    auto sectionPtr = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        module.modBaseAddr + dosHeader.e_lfanew +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader);
    for (auto i = 0; i < ntHeaders.FileHeader.NumberOfSections;
        ++i, ++sectionPtr) {
        IMAGE_SECTION_HEADER section = { 0 };
        ReadProcessMemory(process, sectionPtr, &section, sizeof(section), nullptr);
        sections.push_back(section);
    }

    return sections;
}

ZydisDecodedInstruction Util::Disassemble(PVOID buffer, DWORD length) {
    static ZydisDecoder decoder;
    static std::once_flag decoderInitialized;

    std::call_once(decoderInitialized, []() {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
            ZYDIS_ADDRESS_WIDTH_64);
    });

    ZydisDecodedInstruction instruction;
    ZydisDecoderDecodeBuffer(&decoder, buffer, length, &instruction);
    return instruction;
}

std::vector<ZydisDecodedOperand>
Util::GetInstructionOperands(ZydisDecodedInstruction &instruction) {
    std::vector<ZydisDecodedOperand> operands;

    for (BYTE i = 0; i < instruction.operand_count; ++i) {
        auto &op = instruction.operands[i];
        if (op.visibility != ZYDIS_OPERAND_VISIBILITY_HIDDEN) {
            operands.push_back(op);
        }
    }

    return operands;
}

BOOLEAN Util::IsSameRegister(ZydisRegister a, ZydisRegister b) {
    if (a == b) {
        return TRUE;
    }

    if (a <= ZYDIS_REGISTER_R15 && a >= ZYDIS_REGISTER_AX) {
        for (auto i =
            ((a - ZYDIS_REGISTER_AX) % GP_REGISTER_COUNT) + ZYDIS_REGISTER_AX;
            i <= std::max(a, b); i += GP_REGISTER_COUNT) {
            if (b == i) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

std::string Util::FormatInstruction(ZydisDecodedInstruction &instruction,
    PVOID address) {
    static ZydisFormatter formatter;
    static std::once_flag formatterInitialized;

    std::call_once(formatterInitialized, []() {
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
        ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE,
            ZYAN_TRUE);
    });

    CHAR buffer[0xFF] = { 0 };
    ZydisFormatterFormatInstruction(&formatter, &instruction, buffer,
        sizeof(buffer),
        reinterpret_cast<ULONG64>(address));
    return std::string(buffer);
}

BOOLEAN Util::Assemble(LPCSTR text, PBYTE &buffer, DWORD &bufferSize) {
    asmjit::CodeInfo codeInfo(asmjit::ArchInfo::kIdX64);
    asmjit::CodeHolder code;
    code.init(codeInfo);

    asmjit::x86::Assembler assembler(&code);
    asmtk::AsmParser parser(&assembler);

    auto error = parser.parse(text);
    if (error) {
        buffer = 0;
        bufferSize = 0;
        return FALSE;
    }

    auto &output = code.sectionById(0)->buffer();
    auto outputBuffer = new BYTE[output.size()];

    memcpy(outputBuffer, output.data(), output.size());

    buffer = outputBuffer;
    bufferSize = static_cast<DWORD>(output.size());

    return TRUE;
}

static inline ZydisRegister ConvertRegisterTo64(ZydisRegister reg) noexcept {
    return static_cast<ZydisRegister>(
        ((reg - ZYDIS_REGISTER_AX) % GP_REGISTER_COUNT) + ZYDIS_REGISTER_RAX);
}

ZydisRegister Util::GetUnusedRegister(ZydisDecodedInstruction &instruction) {
    std::vector<ZydisRegister> unused{
        ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
        ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_RSI,
        ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_R8,  ZYDIS_REGISTER_R9,
        ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R12,
        ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15,
    };

    auto operands = GetInstructionOperands(instruction);

    for (auto &op : operands) {
        switch (op.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                unused.erase(remove(unused.begin(), unused.end(),
                    ConvertRegisterTo64(op.reg.value)),
                    unused.end());
                break;
            case ZYDIS_OPERAND_TYPE_MEMORY:
                unused.erase(remove(unused.begin(), unused.end(),
                    ConvertRegisterTo64(op.mem.base)),
                    unused.end());
                unused.erase(remove(unused.begin(), unused.end(),
                    ConvertRegisterTo64(op.mem.index)),
                    unused.end());
                break;
        }
    }

    if (unused.size() == 0) {
        return ZYDIS_REGISTER_NONE;
    }

    return unused[0];
}

PVOID Util::GetInstructionAbsoluteAddress(
    PVOID rva, ZydisDecodedInstruction &instruction) {
    auto ops = Util::GetInstructionOperands(instruction);

    auto ret = 0ULL;
    for (auto &op : ops) {
        if ((op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) ||
            op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            ZydisCalcAbsoluteAddress(&instruction, &op,
                reinterpret_cast<UINT_PTR>(rva), &ret);
            break;
        }
    }

    return reinterpret_cast<PVOID>(ret);
}

DWORD Util::GetAbsoluteSigOffset(PVOID buffer, DWORD size) {
    if (sizeof(PVOID) > size) {
        return 0;
    }

    size -= sizeof(PVOID);
    for (DWORD i = 0; i <= size; ++i) {
        if (*reinterpret_cast<PVOID *>((reinterpret_cast<PBYTE>(buffer) + i)) ==
            ABSOLUTE_SIG) {
            return i;
        }
    }

    return 0;
}