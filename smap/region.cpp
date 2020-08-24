#include "region.h"

// Resolves a region conflict with this region
std::vector<Region> Region::ResolveConflict(Region &region) {
    std::vector<Region> resolvedRegions;

    if (region.ContainsInclusive(this->Start()) &&
        region.ContainsInclusive(this->End())) {
        return resolvedRegions;
    }

    auto containsStart = this->ContainsInclusive(region.Start());
    auto containsEnd = this->ContainsInclusive(region.End());

    if (this->Start() == region.Start() && containsEnd) {
        resolvedRegions.push_back(Region(region.End() + 1, this->End()));
    } else if (this->End() == region.End() && containsStart) {
        resolvedRegions.push_back(Region(this->Start(), region.Start() - 1));
    } else if (containsStart && containsEnd) {
        resolvedRegions.push_back(Region(this->Start(), region.Start() - 1));
        resolvedRegions.push_back(Region(region.End() + 1, this->End()));
    } else if (containsStart) {
        resolvedRegions.push_back(Region(this->Start(), region.Start() - 1));
    } else if (containsEnd) {
        resolvedRegions.push_back(Region(region.End() + 1, this->End()));
    } else {
        resolvedRegions.push_back(*this);
    }

    return resolvedRegions;
}

// Resolves multiple region conflicts with this region
std::vector<Region> Region::ResolveConflicts(std::vector<Region> &regions) {
    std::vector<Region> resolvedRegions;
    resolvedRegions.push_back(*this);

    for (auto &region : regions) {
        std::vector<Region> newResolvedRegions;

        for (auto &resolvedRegion : resolvedRegions) {
            auto r = resolvedRegion.ResolveConflict(region);
            newResolvedRegions.insert(newResolvedRegions.end(), r.begin(), r.end());
        }

        resolvedRegions = newResolvedRegions;
    }

    return resolvedRegions;
}