#include "stdafx.h"

namespace Map {
	PVOID MapIntoRegions(HANDLE process, PBYTE base, std::vector<Region> &regions, DWORD scatterThreshold) {
		PVOID entryPoint = nullptr;

		Translator translator;
		if (!translator.Initialize(process, base)) {
			translator.Fail();
			return entryPoint;
		}

		if (!translator.Align(regions, scatterThreshold)) {
			translator.Fail();
			return entryPoint;
		}

		if (!translator.Resolve()) {
			translator.Fail();
			return entryPoint;
		}
		
		if (!translator.Map(entryPoint)) {
			translator.Fail();
			return entryPoint;
		}

		return entryPoint;
	}
	
	PVOID MapIntoRegions(HANDLE process, LPCWSTR filePath, std::vector<Region> &regions, DWORD scatterThreshold) {
		std::ifstream file(filePath, std::ios::ate | std::ios::binary);
		if (!file) {
			errorf("failed to open file: \"%ws\"\n", filePath);
			return 0;
		}

		auto size = file.tellg();
		auto buffer = new BYTE[size];

		file.seekg(0, std::ios::beg);
		file.read(reinterpret_cast<PCHAR>(buffer), size);
		file.close();

		auto entryPoint = MapIntoRegions(process, buffer, regions, scatterThreshold);

		delete[] buffer;

		return entryPoint;
	}
}