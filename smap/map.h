#pragma once

#include "region.h"

namespace Map {
    PVOID MapIntoRegions(HANDLE process, PBYTE base, std::vector<Region> &regions,
        DWORD scatterThreshold = 1);
    PVOID MapIntoRegions(HANDLE process, LPCWSTR filePath,
        std::vector<Region> &regions, DWORD scatterThreshold = 1);
}