#pragma once

#include "region.h"

#define MIN_ALIGNMENT (14)
#define ALIGNMENT_BYTE (0xCC)

namespace Align {
	std::vector<Region> FindAlignments(HANDLE process);
	std::vector<Region> FindAlignmentsInModules(HANDLE process);
}