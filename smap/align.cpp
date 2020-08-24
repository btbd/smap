#include "align.h"
#include "util.h"
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

// Returns true if the given section should not be used for alignments
static BOOLEAN IsInvalidSection(IMAGE_SECTION_HEADER &section) {
    static LPCSTR invalidSectionNames[] = { "text" };

    for (auto &name : invalidSectionNames) {
        section.Name[sizeof(section.Name) - 1] = 0;

        if (StrStrIA(reinterpret_cast<PCHAR>(section.Name), name)) {
            return TRUE;
        }
    }

    return (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0;
}

// Returns invalid section regions within a given module
static inline std::vector<Region> 
GetInvalidSectionRegions(std::vector<MODULE> &modules) {
    std::vector<Region> regions;

    for (auto &module : modules) {
        for (auto &section : module.Sections) {
            if (IsInvalidSection(section)) {
                regions.push_back(
                    Region(module.Module.modBaseAddr + section.VirtualAddress,
                        section.Misc.VirtualSize));
            }
        }
    }

    return regions;
}

// Returns all function alignments within a specified region
static std::vector<Region> FindRegionAlignments(HANDLE process,
    Region &region) {
    std::vector<Region> alignments;

    if (region.Size() >= MIN_ALIGNMENT) {
        auto buffer = new BYTE[region.Size()];

        if (ReadProcessMemory(process, region.Start(), buffer, region.Size(),
            nullptr)) {
            auto length = region.Size() - MIN_ALIGNMENT;

            for (auto i = 0UL; i <= length;) {
                Region alignment(region.Start() + i, MIN_ALIGNMENT);

                for (auto a = 0UL; a < MIN_ALIGNMENT; ++a, ++i) {
                    if (buffer[i] != ALIGNMENT_BYTE) {
                        goto next;
                    }
                }

                for (; i <= length && buffer[i] == ALIGNMENT_BYTE;
                    ++i, alignment.Size(alignment.Size() + 1))
                    ;

                alignments.push_back(alignment);

            next:
                ++i;
            }
        }

        delete[] buffer;
    }

    return alignments;
}

// Returns whether the given protection constant represents executable memory
static inline BOOLEAN IsExecutable(DWORD protect) noexcept {
    return protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ ||
        protect == PAGE_EXECUTE_READWRITE;
}

// Returns all the functon alignments in a process
std::vector<Region> Align::FindAlignments(HANDLE process) {
    printf("[-] searching for all alignments in %d\n", GetProcessId(process));

    std::vector<Region> alignments;

    auto modules = Util::GetProcessModules(process);
    auto invalidRegions = GetInvalidSectionRegions(modules);

    PBYTE start = nullptr;
    MEMORY_BASIC_INFORMATION info = { 0 };

    for (; VirtualQueryEx(process, start, &info, sizeof(info));
        start += info.RegionSize) {
        if (!IsExecutable(info.Protect)) {
            continue;
        }

        auto validRegions = Region(info.BaseAddress, info.RegionSize)
            .ResolveConflicts(invalidRegions);
        for (auto &validRegion : validRegions) {
            auto regionAlignments = FindRegionAlignments(process, validRegion);
            alignments.insert(alignments.end(), regionAlignments.begin(),
                regionAlignments.end());
        }
    }

    printf("[+] found %lld alignments\n\n", alignments.size());

    return alignments;
}

// Returns all the function alignments in process modules
std::vector<Region> Align::FindAlignmentsInModules(HANDLE process) {
    printf("[-] searching for module alignments in %d\n", GetProcessId(process));

    std::vector<Region> alignments;

    auto modules = Util::GetProcessModules(process);
    auto invalidRegions = GetInvalidSectionRegions(modules);

    for (auto &module : modules) {
        MEMORY_BASIC_INFORMATION info = { 0 };

        for (auto start = module.Module.modBaseAddr,
            end = start + module.Module.modBaseSize;
            start < end && VirtualQueryEx(process, start, &info, sizeof(info));
            start += info.RegionSize) {
            if (!IsExecutable(info.Protect)) {
                continue;
            }

            Region region(info.BaseAddress, info.RegionSize);
            if (region.End() > end) {
                region.End(end);
            }

            auto validRegions = region.ResolveConflicts(invalidRegions);
            for (auto &validRegion : validRegions) {
                auto regionAlignments = FindRegionAlignments(process, validRegion);
                alignments.insert(alignments.end(), regionAlignments.begin(),
                    regionAlignments.end());
            }
        }
    }

    printf("[+] found %lld alignments\n\n", alignments.size());

    return alignments;
}
