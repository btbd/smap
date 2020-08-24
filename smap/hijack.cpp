#include "hijack.h"
#include "util.h"
#include <psapi.h>

// Returns a pointer to the ITE for the specified import
static PVOID GetImportTableEntry(HANDLE process, LPCWSTR module,
    LPCSTR import) {
    auto base = Util::GetModuleInfoByName(process, module).modBaseAddr;
    if (!base) {
        errorf("failed to get module base for %ws\n", module);
        return nullptr;
    }

    IMAGE_DOS_HEADER dosHeader = { 0 };
    IMAGE_NT_HEADERS ntHeaders = { 0 };

    ReadProcessMemory(process, base, &dosHeader, sizeof(dosHeader), nullptr);
    ReadProcessMemory(process, base + dosHeader.e_lfanew, &ntHeaders,
        sizeof(ntHeaders), nullptr);

    auto importDescriptorOffset =
        ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        .VirtualAddress;
    if (!importDescriptorOffset) {
        errorf("no IAT found for %ws\n", module);
        return nullptr;
    }

    for (;; importDescriptorOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        IMAGE_IMPORT_DESCRIPTOR importDescriptor = { 0 };
        ReadProcessMemory(process, base + importDescriptorOffset, &importDescriptor,
            sizeof(importDescriptor), nullptr);

        auto thunkOffset = importDescriptor.OriginalFirstThunk;
        if (!thunkOffset) {
            break;
        }

        for (auto i = 0UL;; thunkOffset += sizeof(IMAGE_THUNK_DATA), ++i) {
            IMAGE_THUNK_DATA thunk = { 0 };
            ReadProcessMemory(process, base + thunkOffset, &thunk, sizeof(thunk),
                nullptr);
            if (!thunk.u1.AddressOfData) {
                break;
            }

            CHAR name[0xFF] = { 0 };
            ReadProcessMemory(process,
                base + thunk.u1.AddressOfData +
                FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name),
                name, sizeof(name), nullptr);
            if (strcmp(name, import) == 0) {
                return base + importDescriptor.FirstThunk + (i * sizeof(PVOID));
            }
        }
    }

    errorf("failed to find import %s in %ws\n", import, module);
    return nullptr;
}

// Hijacks code execution via a temporary IAT change
BOOLEAN Hijack::HijackViaIAT(HANDLE process, PVOID entry, LPCSTR importName,
    LPCWSTR module) {
    printf("\n[-] hijacking execution via IAT\n");

    PVOID importEntry = nullptr;
    if (module && *module) {
        printf("[+] using %ws:%s\n", module, importName);

        importEntry = GetImportTableEntry(process, module, importName);
    } else {
        WCHAR baseModule[0xFF] = { 0 };
        GetModuleBaseName(process, 0, baseModule,
            sizeof(baseModule) / sizeof(baseModule[0]));

        printf("[+] using %ws:%s\n", baseModule, importName);

        importEntry = GetImportTableEntry(process, baseModule, importName);
    }

    if (!importEntry) {
        return FALSE;
    }

    BYTE shellcode[] = {
        0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48,
        0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x10,
        0x48, 0x83, 0xEC, 0x28, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0x48, 0x31,
        0xC0, 0x80, 0x05, 0xBC, 0xFF, 0xFF, 0xFF, 0x01, 0xC3 };

    *reinterpret_cast<PVOID *>(&shellcode[3]) = importEntry;
    ReadProcessMemory(process, importEntry, &shellcode[13], sizeof(PVOID),
        nullptr);
    *reinterpret_cast<PVOID *>(&shellcode[46]) = entry;

    auto mappedShellcode = reinterpret_cast<PBYTE>(
        VirtualAllocEx(process, nullptr, sizeof(shellcode),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!mappedShellcode) {
        errorf("failed to allocate virtual memory for IAT hijack shellcode\n");
        return FALSE;
    }

    WriteProcessMemory(process, mappedShellcode, shellcode, sizeof(shellcode),
        nullptr);

    auto oldProtect = 0UL;
    VirtualProtectEx(process, importEntry, sizeof(importEntry), PAGE_READWRITE,
        &oldProtect);

    auto shellcodeEntry = mappedShellcode + 1;
    WriteProcessMemory(process, importEntry, &shellcodeEntry,
        sizeof(shellcodeEntry), nullptr);

    printf("[+] waiting for shellcode to execute...\n");

    for (PVOID importValue = nullptr;; Sleep(1)) {
        if (!ReadProcessMemory(process, importEntry, &importValue,
            sizeof(importValue), nullptr)) {
            errorf("failed to read import entry at %p\n", importEntry);
            return FALSE;
        }

        if (importValue != shellcodeEntry) {
            break;
        }
    }

    VirtualProtectEx(process, importEntry, sizeof(importEntry), oldProtect,
        &oldProtect);

    for (BYTE status = 0;; Sleep(1)) {
        if (!ReadProcessMemory(process, mappedShellcode, &status, sizeof(status),
            nullptr)) {
            errorf("failed to read shellcode status at %p\n", mappedShellcode);
            return FALSE;
        }

        if (status) {
            break;
        }
    }

    VirtualFreeEx(process, mappedShellcode, 0, MEM_RELEASE);

    printf("[+] executed\n");

    return TRUE;
}

// Hijacks execution via a temporary hook
BOOLEAN Hijack::HijackViaHook(HANDLE process, PVOID entry, LPCWSTR moduleName,
    LPCSTR functionName) {
    printf("\n[-] hijacking execution via hook\n");

    auto remoteModule = Util::GetModuleInfoByName(process, moduleName);
    if (!remoteModule.modBaseAddr) {
        errorf("failed to find module %ws in process\n", moduleName);
        return FALSE;
    }

    auto module = LoadLibrary(moduleName);
    if (!module) {
        errorf("failed to load module %ws\n", moduleName);
        return FALSE;
    }

    auto function = reinterpret_cast<PBYTE>(GetProcAddress(module, functionName));
    if (!function) {
        errorf("failed to find function %ws:%s\n", moduleName, functionName);
        return FALSE;
    }

    printf("[+] using %ws:%s\n", moduleName, functionName);

    auto remoteFunction =
        remoteModule.modBaseAddr + (function - reinterpret_cast<PBYTE>(module));

    BYTE shellcode[] = {
        0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48,
        0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x10,
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89,
        0x50, 0x08, 0x48, 0x83, 0xEC, 0x28, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28,
        0x48, 0x31, 0xC0, 0xC6, 0x05, 0xAE, 0xFF, 0xFF, 0xFF, 0x01, 0xC3 };

    *reinterpret_cast<PVOID *>(&shellcode[3]) = remoteFunction;
    ReadProcessMemory(process, remoteFunction, &shellcode[13], sizeof(ULONG64),
        nullptr);
    ReadProcessMemory(process, remoteFunction + sizeof(ULONG64), &shellcode[26],
        sizeof(ULONG64), nullptr);
    *reinterpret_cast<PVOID *>(&shellcode[60]) = entry;

    auto mappedShellcode = reinterpret_cast<PBYTE>(
        VirtualAllocEx(process, nullptr, sizeof(shellcode),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!mappedShellcode) {
        errorf("failed to allocate virtual memory for hook hijack shellcode\n");
        return FALSE;
    }

    WriteProcessMemory(process, mappedShellcode, shellcode, sizeof(shellcode),
        nullptr);

    BYTE jump[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    *reinterpret_cast<PVOID *>(&jump[6]) = mappedShellcode + 1;

    auto oldProtect = 0UL;
    VirtualProtectEx(process, remoteFunction, 2 * sizeof(ULONG64),
        PAGE_EXECUTE_READWRITE, &oldProtect);

    WriteProcessMemory(process, remoteFunction, jump, sizeof(jump), nullptr);

    printf("[+] waiting for shellcode to execute...\n");
    for (auto functionBytes = 0ULL;; Sleep(1)) {
        if (!ReadProcessMemory(process, remoteFunction + 6, &functionBytes,
            sizeof(functionBytes), nullptr)) {
            errorf("failed to function bytes at %p\n", remoteFunction + 6);
            return FALSE;
        }

        if (functionBytes != *reinterpret_cast<PULONG64>(&jump[6])) {
            break;
        }
    }

    VirtualProtectEx(process, remoteFunction, sizeof(jump), oldProtect,
        &oldProtect);

    for (BYTE status = 0;; Sleep(1)) {
        if (!ReadProcessMemory(process, mappedShellcode, &status, sizeof(status),
            nullptr)) {
            errorf("failed to read shellcode status at %p\n", mappedShellcode);
            return FALSE;
        }

        if (status) {
            break;
        }
    }

    VirtualFreeEx(process, mappedShellcode, 0, MEM_RELEASE);

    printf("[+] executed\n");

    return TRUE;
}
