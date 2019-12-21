#pragma once

#define ASMJIT_STATIC
#define ASMJIT_BUILD_RELEASE
#define ASMJIT_BUILD_X86

#pragma warning(push, 0)

#include <asmtk/asmtk.h>
#include <Zydis/Zydis.h>
#pragma comment(lib, "Zydis.lib")

#pragma warning(pop)

#define errorf(fmt, ...) fprintf(stderr, "\n[error at %s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <regex>
#include <map>

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#include "util.h"

#include "region.h"
#include "align.h"
#include "translation.h"
#include "translator.h"
#include "map.h"
#include "hijack.h"
#include "smap.h"