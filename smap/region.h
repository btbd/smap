#pragma once

#include <Windows.h>
#include <vector>

class Region {
private:
    PBYTE BaseAddress = nullptr;
    DWORD RegionSize = 0;

public:
    inline Region(PVOID address = nullptr, SIZE_T size = 0) noexcept
        : BaseAddress{ reinterpret_cast<PBYTE>(address) },
        RegionSize{ static_cast<DWORD>(size) } {}

    inline Region(UINT_PTR address, SIZE_T size) noexcept
        : BaseAddress{ reinterpret_cast<PBYTE>(address) },
        RegionSize{ static_cast<DWORD>(size) } {}

    inline Region(PVOID start, PVOID end) noexcept
        : BaseAddress{ reinterpret_cast<PBYTE>(start) },
        RegionSize{ static_cast<DWORD>(
            (reinterpret_cast<PBYTE>(end) - reinterpret_cast<PBYTE>(start))) } {}

    inline VOID Start(PVOID start) noexcept {
        this->BaseAddress = reinterpret_cast<PBYTE>(start);
    }

    inline PBYTE Start() noexcept { return this->BaseAddress; }

    inline VOID End(PVOID end) noexcept {
        this->RegionSize =
            static_cast<DWORD>(reinterpret_cast<PBYTE>(end) - this->Start());
    }

    inline PBYTE End() noexcept { return this->Start() + this->Size(); }

    inline DWORD Size() noexcept { return this->RegionSize; }

    inline VOID Size(DWORD size) noexcept { this->RegionSize = size; }

    inline BOOLEAN Contains(PVOID address) noexcept {
        return address >= this->Start() && address < this->End();
    }

    inline BOOLEAN ContainsInclusive(PVOID address) noexcept {
        return address >= this->Start() && address <= this->End();
    }

    std::vector<Region> ResolveConflict(Region &region);
    std::vector<Region> ResolveConflicts(std::vector<Region> &regions);
};
