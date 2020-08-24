#pragma once

#include <Windows.h>

class SMap {
private:
    HANDLE ProcessHandle = nullptr;

    DWORD ProcessId = 0;
    LPCWSTR DllPath = nullptr;
    LPCWSTR TargetModule = nullptr;
    LPCSTR TargetFunction = nullptr;
    DWORD ScatterThreshold = 1;
    BOOLEAN UseIAT = FALSE;

public:
    inline SMap(DWORD processId, LPCWSTR dllPath, LPCWSTR targetModule,
        LPCSTR targetFunction, DWORD scatterThreshold,
        BOOLEAN useIat) noexcept
        : ProcessId{ processId }, DllPath{ dllPath }, TargetModule{ targetModule },
        TargetFunction{ targetFunction },
        ScatterThreshold{ scatterThreshold }, UseIAT{ useIat } {
        if (!this->TargetFunction || !*this->TargetFunction) {
            this->TargetFunction = "PeekMessageW";
        }

        if (!this->UseIAT && (!this->TargetModule || !*this->TargetModule)) {
            this->TargetModule = L"user32.dll";
        }

        if (!this->ScatterThreshold) {
            this->ScatterThreshold = 1;
        }
    }

    inline ~SMap() {
        if (this->ProcessHandle) {
            CloseHandle(this->ProcessHandle);
        }
    }

    BOOLEAN Inject();
};