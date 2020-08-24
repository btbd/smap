#pragma once

#include <Windows.h>

namespace Hijack {
    BOOLEAN HijackViaIAT(HANDLE process, PVOID entry, LPCSTR importName,
        LPCWSTR module = nullptr);
    BOOLEAN HijackViaHook(HANDLE process, PVOID entry, LPCWSTR moduleName,
        LPCSTR functionName);
}