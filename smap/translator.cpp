#include "stdafx.h"

BOOLEAN Translator::Initialize(HANDLE process, PBYTE base) {
	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		errorf("invalid DOS signature\n");
		return FALSE;
	}

	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		errorf("invalid NT signature\n");
		return FALSE;
	}

	nt->Signature = dos->e_magic = 0;

	this->ProcessHandle = process;
	this->ImageBase = base;
	this->NtHeaders = nt;

	if (!this->MapHeaders()) {
		return FALSE;
	}

	printf("[-] analyzing sections...\n");
	auto section = IMAGE_FIRST_SECTION(nt);
	for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
		try {
			this->AddSection(base, section);
		} catch (INT) {
			return FALSE;
		}
	}

	return TRUE;
}

BOOLEAN Translator::MapHeaders() {
	auto sizeOfHeaders = static_cast<DWORD>(sizeof(this->NtHeaders->Signature) + sizeof(this->NtHeaders->FileHeader) + this->NtHeaders->FileHeader.SizeOfOptionalHeader);
	auto mapped = VirtualAllocEx(this->Process(), nullptr, sizeOfHeaders, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!mapped) {
		errorf("failed to allocate virtual memory for headers\n");
		return FALSE;
	}

	this->AddTranslation(new RegionTranslation(Region(0ULL, sizeOfHeaders), mapped, this->ImageBase, sizeOfHeaders));
	return TRUE;
}

std::vector<PVOID> Translator::GetExports() {
	std::vector<PVOID> exports;

	auto rva = this->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!rva) {
		return exports;
	}

	auto exportDirectory = this->TranslateRaw<PIMAGE_EXPORT_DIRECTORY>(rva);
	if (!exportDirectory) {
		return exports;
	}

	auto addressOfFunctions = this->TranslateRaw<PULONG>(exportDirectory->AddressOfFunctions);
	if (!addressOfFunctions) {
		return exports;
	}

	auto addressOfNameOrdinals = this->TranslateRaw<PUSHORT>(exportDirectory->AddressOfNameOrdinals);
	if (!addressOfNameOrdinals) {
		return exports;
	}

	for (auto i = 0UL; i < exportDirectory->NumberOfNames; ++i) {
		exports.push_back(reinterpret_cast<PVOID>(static_cast<UINT_PTR>(addressOfFunctions[addressOfNameOrdinals[i]])));
	}

	return exports;
}

BOOLEAN Translator::ResolveImports() {
	printf("[+] imports\n");

	auto rva = this->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!rva) {
		return TRUE;
	}

	auto importDescriptor = this->TranslateRaw<PIMAGE_IMPORT_DESCRIPTOR>(rva);
	if (!importDescriptor) {
		return TRUE;
	}

	for (; importDescriptor->FirstThunk; ++importDescriptor) {
		auto moduleName = this->TranslateRaw<PCHAR>(importDescriptor->Name);
		if (!moduleName) {
			break;
		}

		auto module = LoadLibraryA(moduleName);
		if (!module) {
			errorf("failed to load module: %s\n", moduleName);
			return FALSE;
		}

		auto processModule = Util::GetModuleInfoByName(this->Process(), std::wstring(moduleName, &moduleName[strlen(moduleName)]).c_str()).modBaseAddr;
		if (!processModule) {
			errorf("target process does not have %s loaded\n", moduleName);
			return FALSE;
		}

		for (auto thunk = this->TranslateRaw<PIMAGE_THUNK_DATA>(importDescriptor->FirstThunk); thunk->u1.AddressOfData; ++thunk) {
			auto importByName = this->TranslateRaw<PIMAGE_IMPORT_BY_NAME>(thunk->u1.AddressOfData);
			thunk->u1.Function = reinterpret_cast<UINT_PTR>(processModule + (reinterpret_cast<PBYTE>(GetProcAddress(module, importByName->Name)) - reinterpret_cast<PBYTE>(module)));
		}
	}

	return TRUE;
}

VOID Translator::ResolveRelocations() {
	printf("[+] relocations\n");

	auto &baseRelocDir = this->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!baseRelocDir.VirtualAddress) {
		return;
	}

	auto reloc = this->TranslateRaw<PIMAGE_BASE_RELOCATION>(baseRelocDir.VirtualAddress);
	if (!reloc) {
		return;
	}

	for (auto currentSize = 0UL; currentSize < baseRelocDir.Size; ) {
		auto relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		auto relocData = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
		auto relocBase = this->TranslateRaw<PBYTE>(reloc->VirtualAddress);

		for (auto i = 0UL; i < relocCount; ++i, ++relocData) {
			auto data = *relocData;
			auto type = data >> 12;
			auto offset = data & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64) {
				auto &rva = *reinterpret_cast<PVOID *>(relocBase + offset);
				rva = this->Translate(reinterpret_cast<PBYTE>(rva) - reinterpret_cast<PBYTE>(this->NtHeaders->OptionalHeader.ImageBase));
			}
		}

		currentSize += reloc->SizeOfBlock;
		reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(relocData);
	}
}

DWORD GetNextJumpSize(std::vector<Region> &regions, SIZE_T regionIndex, SIZE_T regionEnd) {
	if (regionIndex >= regionEnd - 1) {
		return 14;
	}

	auto diff = regions[regionIndex + 1].Start() - regions[regionIndex].End();
	if (abs(diff) <= 0x7F) {
		return 2;
	}

	if (abs(diff) <= 0x7FFFFFFF) {
		return 5;
	}

	return 14;
}

PVOID *Translator::AlignExport(SIZE_T &translationIndex, SIZE_T translationsCount, std::vector<Region> &regions, SIZE_T regionStart, SIZE_T regionEnd) {
	auto regionIndex = regionStart;
	auto regionOffset = 0UL;

	for (; translationIndex < translationsCount; ++translationIndex) {
		auto translation = this->Translations[translationIndex].get();
		if (!translation->Executable()) {
			continue;
		}

		auto region = &regions[regionIndex];
		auto jumpSize = GetNextJumpSize(regions, regionIndex, regionEnd);
		while (regionOffset + translation->BufferSize() + jumpSize > region->Size()) {
			if (regionIndex == regionEnd - 1) {
				goto leftover;
			}

			auto leftoverSize = region->Size() - regionOffset;
			auto jumpBuffer = new BYTE[leftoverSize];
			auto jumpIndex = leftoverSize - jumpSize;

			memset(jumpBuffer, 0x90, jumpIndex);

			auto jumpInst = &jumpBuffer[jumpIndex];
			auto jumpDest = regions[regionIndex + 1].Start();

			switch (jumpSize) {
				case 2:
					jumpInst[0] = 0xEB;
					jumpInst[1] = static_cast<BYTE>(jumpDest - region->End());
					break;
				case 5:
					jumpInst[0] = 0xE9;
					*reinterpret_cast<PINT>(&jumpInst[1]) = static_cast<INT>(jumpDest - region->End());
					break;
				case 14:
					memcpy(jumpInst, "\xFF\x25\x00\x00\x00\x00", 6);
					*reinterpret_cast<PVOID *>(&jumpInst[6]) = jumpDest;
					break;
			}

			auto jump = new ModifiedTranslation(Region(-1, 0UL), jumpBuffer, leftoverSize);
			jump->Mapped(region->Start() + regionOffset);
			this->AddTranslation(jump);

			region = &regions[++regionIndex];
			regionOffset = 0;
			jumpSize = GetNextJumpSize(regions, regionIndex, regionEnd);
		}

		translation->Mapped(region->Start() + regionOffset);
		regionOffset += translation->BufferSize();
	}

	return nullptr;

leftover:
	auto jumpBuffer = new BYTE[14]{ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
	auto jump = new ModifiedTranslation(Region(-1, 0UL), jumpBuffer, 14);
	jump->Mapped(regions[regionIndex].Start() + regionOffset);
	this->AddTranslation(jump);

	return reinterpret_cast<PVOID *>(&jumpBuffer[6]);
}

BOOLEAN Translator::Align(std::vector<Region> &regions, DWORD scatterThreshold) {
	printf("\n[-] aligning code map\n");

	auto exports = this->GetExports();
	if (exports.size() == 0) {
		printf("[+] no exports found\n");
	} else {
		printf("[+] found %lld exports\n", exports.size());

		if (regions.size() < exports.size()) {
			errorf("needed at least %lld regions, had %lld\n", exports.size(), regions.size());
			return FALSE;
		}
	}

	auto translationsCount = this->Translations.size();
	auto regionIncrement = exports.size() == 0 ? 0 : regions.size() / exports.size(); 
	PBYTE scatterBase = nullptr;
	auto scatterIndex = 0ULL;
	PVOID *lastJump = nullptr;

	for (auto i = 0ULL; i < translationsCount; ++i) {
		auto translation = this->Translations[i].get();
		if (!translation->Executable()) {
			continue;
		}

		for (auto e = 0ULL; e < exports.size(); ++e) {
			if (exports[e] == translation->RVA().Start()) {
				auto regionStart = e * regionIncrement;
				auto regionEnd = (e == exports.size() - 1 ? regions.size() : (e + 1) * regionIncrement);

				auto exportStart = regions[regionStart].Start();
				printf("[+] export %lld > %p\n", e, exportStart);

				lastJump = this->AlignExport(i, translationsCount, regions, regionStart, regionEnd);
				if (!lastJump) {
					return TRUE;
				}
				
				translation = this->Translations[i].get();
				scatterIndex = 0;
				scatterBase = nullptr;
				break;
			}
		}
		
		if (scatterIndex == scatterThreshold) {
			auto jumpBuffer = new BYTE[14]{ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
			auto jump = new ModifiedTranslation(Region(-1, 0UL), jumpBuffer, 14);
			jump->Mapped(scatterBase);
			this->AddTranslation(jump);

			lastJump = reinterpret_cast<PVOID *>(&jumpBuffer[6]);
			scatterIndex = 0;
			scatterBase = nullptr;
		}

		if (scatterBase) {
			translation->Mapped(scatterBase);

			++scatterIndex;
			scatterBase += translation->BufferSize();
		} else {
			auto scatterSize = 14ULL;
			for (auto e = i; e < i + scatterThreshold && e < translationsCount; ++e) {
				auto t = this->Translations[e].get();
				if (e > i && std::find(exports.begin(), exports.end(), t->RVA().Start()) != exports.end()) {
					break;
				}

				scatterSize += t->BufferSize();
			}

			scatterBase = reinterpret_cast<PBYTE>(VirtualAllocEx(this->Process(), nullptr, scatterSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ));
			if (!scatterBase) {
				errorf("failed to allocate virtual memory\n");
				return FALSE;
			}

			if (lastJump) {
				*lastJump = scatterBase;
			}

			translation->Mapped(scatterBase, TRUE);

			++scatterIndex;
			scatterBase += translation->BufferSize();
		}
	}

	return TRUE;
}

BOOLEAN Translator::Resolve() {
	printf("\n[-] resolving...\n");

	if (!this->ResolveImports()) {
		return FALSE;
	}

	this->ResolveRelocations();

	printf("[+] relative instructions and jump tables\n");
	for (auto &ptr : this->Translations) {
		auto translation = ptr.get();
		if (!translation->Resolve(*this)) {
			errorf("failed to resolve %p\n", translation->RVA().Start());
			return FALSE;
		}
	}

	return TRUE;
}

BOOLEAN Translator::Map(PVOID &entry) {
	printf("\n[-] mapping sections and code map\n");

	for (auto &ptr : this->Translations) {
		auto t = ptr.get();
		if (!t->BufferSize()) {
			continue;
		}

		auto oldProtect = 0UL;
		if (!VirtualProtectEx(this->Process(), t->Mapped(), t->BufferSize(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
			errorf("failed to set protection to RWX for %p\n", t->Mapped());
			return FALSE;
		}

		if (!WriteProcessMemory(this->Process(), t->Mapped(), t->Buffer(), t->BufferSize(), nullptr)) {
			errorf("failed to write buffer to %p\n", t->Mapped());
			return FALSE;
		}

		VirtualProtectEx(this->Process(), t->Mapped(), t->BufferSize(), oldProtect, &oldProtect);
	}

	printf("[+] mapped %lld translations\n", this->Translations.size());

	entry = this->Translate(this->NtHeaders->OptionalHeader.AddressOfEntryPoint);

	printf("[+] entry point: %p\n", entry);

	return TRUE;
}

PIMAGE_SECTION_HEADER Translator::TranslateRawSection(PVOID rva) {
	auto section = IMAGE_FIRST_SECTION(this->NtHeaders);
	for (auto i = 0; i < this->NtHeaders->FileHeader.NumberOfSections; ++i, ++section) {
		if (Region(section->VirtualAddress, section->Misc.VirtualSize).Contains(rva)) {
			return section;
		}
	}

	return nullptr;
}

PVOID Translator::TranslateRaw(PVOID rva) {
	auto section = this->TranslateRawSection(rva);
	if (!section) {
		return nullptr;
	}

	return this->ImageBase + section->PointerToRawData + (reinterpret_cast<PBYTE>(rva) - reinterpret_cast<PBYTE>(static_cast<UINT_PTR>(section->VirtualAddress)));
}

PVOID Translator::Translate(PVOID rva) {
	auto size = this->Translations.size();
	if (size == 0) {
		return nullptr;
	}

	auto left = 0ULL;
	auto right = size - 1;
	while (left <= right) {
		auto middle = (left + right) / 2;
		auto trans = this->Translations[middle].get();
		if (trans->RVA().Contains(rva)) {
			while (middle - 1 >= 0 && this->Translations[middle - 1].get()->RVA().Contains(rva)) {
				--middle;
			}

			trans = this->Translations[middle].get();
			return trans->Mapped() + (reinterpret_cast<PBYTE>(rva) - trans->RVA().Start());
		}

		if (trans->RVA().Start() > rva) {
			right = middle - 1;
		} else {
			left = middle + 1;
		}
	}

	return nullptr;
}

VOID Translator::AddSection(PBYTE base, PIMAGE_SECTION_HEADER section) {
	if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
		printf("[+] %-8s > (0x%X, 0x%X)\n", section->Name, section->VirtualAddress, section->SizeOfRawData);
		this->AddExecuteSection(base, section);
	} else {
		auto mapped = VirtualAllocEx(this->Process(), nullptr, section->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!mapped) {
			errorf("failed to allocate virtual memory for %s section\n", section->Name);
			throw TranslatorException();
		}

		printf("[+] %-8s > %p (0x%X, 0x%X)\n", section->Name, mapped, section->VirtualAddress, section->Misc.VirtualSize);
		this->AddTranslation(new RegionTranslation(Region(section->VirtualAddress, section->Misc.VirtualSize), mapped, base + section->PointerToRawData, std::min(section->Misc.VirtualSize, section->SizeOfRawData)));
	}
}

VOID Translator::TraceBranch(INT &translationIndex, INT startingIndex) {
	auto rva = this->Translations[translationIndex].get()->RVA();

	auto branch = this->Branches.find(rva.Start());
	if (branch != this->Branches.end()) {
		auto xref = branch->second;
		if (xref < rva.Start()) {
			for (; translationIndex >= startingIndex; --translationIndex) {
				if (this->Translations[translationIndex].get()->RVA().Start() == xref) {
					break;
				}
			}

			while (translationIndex - 1 >= startingIndex && this->Translations[static_cast<SIZE_T>(translationIndex) - 1].get()->RVA().Start() == xref) {
				--translationIndex;
			}
		}
	}
}

BOOLEAN Translator::IsRegisterAbsolute(ZydisRegister reg, INT translationIndex, INT startingIndex, PVOID &absolute) {
	if (Util::IsSameRegister(reg, ZYDIS_REGISTER_RSP)) {
		return FALSE;
	}

	for (auto i = translationIndex; i >= startingIndex; --i) {
		auto prevTrans = this->Translations[i].get();
		if (!prevTrans->Executable()) {
			continue;
		}

		if (i != translationIndex) {
			auto prevInst = Util::Disassemble(prevTrans->Buffer(), prevTrans->BufferSize());
			if (prevInst.mnemonic == ZYDIS_MNEMONIC_INT3 || prevInst.mnemonic == ZYDIS_MNEMONIC_INVALID) {
				return FALSE;
			}

			auto relativeTrans = dynamic_cast<RelativeTranslation *>(prevTrans);
			auto prevInstOperands = Util::GetInstructionOperands(prevInst);
			switch (prevInstOperands.size()) {
				case 1:
					if (prevInstOperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && Util::IsSameRegister(prevInstOperands[0].reg.value, reg)) {
						return FALSE;
					}

					break;
				case 2:
					if (prevInstOperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && Util::IsSameRegister(prevInstOperands[0].reg.value, reg)) {
						if (relativeTrans && prevInstOperands[1].imm.value.u != 0) {
							absolute = reinterpret_cast<PVOID>(prevInstOperands[1].imm.value.u);
							return TRUE;
						} else {
							return FALSE;
						}
					}

					break;
			}
		}

		this->TraceBranch(i, startingIndex);
	}

	return FALSE;
}

BOOLEAN Translator::AddSwitchTranslation(Region &rva, PBYTE jumpBuffer, ZydisDecodedInstruction &jumpInst) {
	auto jumpOperands = Util::GetInstructionOperands(jumpInst);
	if (jumpOperands.size() != 1 || jumpOperands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
		return FALSE;
	}

	auto jumpRegister = jumpOperands[0].reg.value;

	struct {
		ZydisRegister Register;
		INT TranslationIndex;
	} offset = { ZYDIS_REGISTER_NONE };

	struct {
		PVOID RVA;
		ZydisDecodedOperand IndexOperand;
		std::vector<PVOID> Entries;
		INT LookupTranslationIndex;
		ZydisDecodedInstruction LookupInstruction;
		std::vector<ZydisDecodedOperand> LookupOperands;
		ULONG64 Cases;
		PVOID Mapped;
		BOOLEAN JumpAbove, IsRelative;
	} jumpTable = { 0 };

	struct {
		PVOID RVA;
		BYTE EntrySize;
		INT LookupTranslationIndex;
		ZydisRegister LookupIndexRegister;
		BYTE LookupScale;
		ZydisDecodedInstruction LookupInstruction;
		ULONG64 Cases;
		PVOID Mapped;
	} indirectJumpTable = { 0 };

	for (INT i = static_cast<INT>(this->Translations.size()) - 1; i >= 0 && !jumpTable.Cases && !indirectJumpTable.Cases; --i) {
		auto prevTrans = this->Translations[i].get();
		if (!prevTrans->Executable()) {
			continue;
		}

		auto prevInst = Util::Disassemble(prevTrans->Buffer(), prevTrans->BufferSize());
		if (prevInst.mnemonic == ZYDIS_MNEMONIC_INT3 || prevInst.mnemonic == ZYDIS_MNEMONIC_INVALID) {
			return FALSE;
		}

		auto prevInstOperands = Util::GetInstructionOperands(prevInst);
		if (prevInstOperands.size() != 2) {
			if (!jumpTable.JumpAbove && prevInst.mnemonic == ZYDIS_MNEMONIC_JNBE) {
				jumpTable.JumpAbove = TRUE;
			}
			
			continue;
		}

		auto &op0 = prevInstOperands[0];
		auto &op1 = prevInstOperands[1];
		if (offset.Register == ZYDIS_REGISTER_NONE) {
			if (op0.type != ZYDIS_OPERAND_TYPE_REGISTER || !Util::IsSameRegister(op0.reg.value, jumpRegister)) {
				continue;
			}

			if (prevInst.mnemonic != ZYDIS_MNEMONIC_ADD) {
				return FALSE;
			}
				
			if (op1.type != ZYDIS_OPERAND_TYPE_REGISTER) {
				errorf("unexpected instruction with jump register at %p (%p)\n", prevTrans->RVA().Start(), rva.Start());
				throw TranslatorException();
			}

			offset.Register = op1.reg.value;
			offset.TranslationIndex = i;
		} else if (jumpTable.IndexOperand.type == ZYDIS_OPERAND_TYPE_UNUSED) {
			if (op0.type != ZYDIS_OPERAND_TYPE_REGISTER || (!Util::IsSameRegister(op0.reg.value, jumpRegister) && !Util::IsSameRegister(op0.reg.value, offset.Register))) {
				continue;
			}
			
			// (#5) MSVC - optimization for jump cases that use cs:0
			auto prevRelative = dynamic_cast<RelativeTranslation *>(prevTrans);
			if (prevRelative && prevRelative->Pointer() == nullptr && Util::IsSameRegister(op0.reg.value, offset.Register)) {
				continue;
			}

			if (op1.type != ZYDIS_OPERAND_TYPE_MEMORY || op1.mem.index == ZYDIS_REGISTER_NONE || op1.mem.scale != 4) {
				errorf("unexpected instruction with jump/offset register at %p (%p)\n", prevTrans->RVA().Start(), rva.Start());
				throw TranslatorException();
			}

			if (op1.mem.disp.has_displacement) {
				jumpTable.RVA = reinterpret_cast<PVOID>(op1.mem.disp.value);
			} else {
				if (this->IsRegisterAbsolute(op1.mem.base, i, 0, jumpTable.RVA)) {
					jumpTable.IsRelative = TRUE;
				} else {
					errorf("failed to trace jump table base register to a valid table (%p)\n", rva.Start());
					throw TranslatorException();
				}
			}

			jumpTable.IndexOperand = jumpOperands[0];
			jumpTable.IndexOperand.reg.value = op1.mem.index;
			
			jumpTable.LookupTranslationIndex = i;
			jumpTable.LookupInstruction = prevInst;
			jumpTable.LookupOperands = prevInstOperands;
		} else {
			if (jumpTable.JumpAbove) {
				// LLVM - override the current index operand if we found a JA and receive a CMP or SUB
				switch (prevInst.mnemonic) {
					case ZYDIS_MNEMONIC_CMP: case ZYDIS_MNEMONIC_SUB:
						jumpTable.JumpAbove = FALSE;
						jumpTable.IndexOperand = op0;
						break;
				}
			}
			
			if (op0 == jumpTable.IndexOperand || (op0.type == jumpTable.IndexOperand.type && op0.type == ZYDIS_OPERAND_TYPE_REGISTER && Util::IsSameRegister(op0.reg.value, jumpTable.IndexOperand.reg.value))) {
				switch (prevInst.mnemonic) {
					case ZYDIS_MNEMONIC_CMP: case ZYDIS_MNEMONIC_AND: case ZYDIS_MNEMONIC_MOV: case ZYDIS_MNEMONIC_MOVSX: case ZYDIS_MNEMONIC_MOVSXD: case ZYDIS_MNEMONIC_MOVZX: case ZYDIS_MNEMONIC_SUB:
						if (op1.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
							if (indirectJumpTable.RVA) {
								indirectJumpTable.Cases = op1.imm.value.u + 1;
							} else {
								jumpTable.Cases = op1.imm.value.u + 1;
							}
						} else if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY && op1.mem.disp.has_displacement && op1.mem.index != ZYDIS_REGISTER_NONE) {
							jumpTable.IndexOperand = jumpOperands[0];
							jumpTable.IndexOperand.reg.value = (op1.mem.index == jumpTable.LookupOperands[1].mem.base ? op1.mem.base : op1.mem.index);

							indirectJumpTable.RVA = reinterpret_cast<PVOID>(op1.mem.disp.value);
							indirectJumpTable.EntrySize = op1.mem.scale;
							indirectJumpTable.LookupTranslationIndex = i;
							indirectJumpTable.LookupInstruction = prevInst;
							indirectJumpTable.LookupIndexRegister = jumpTable.IndexOperand.reg.value;
							indirectJumpTable.LookupScale = op1.mem.scale;
						} else {
							jumpTable.IndexOperand = op1;			
						}				

						break;
					case ZYDIS_MNEMONIC_LEA:
						// LLVM - may decide to use LEA for the case count
						if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY && op1.mem.base != ZYDIS_REGISTER_NONE && op1.mem.disp.has_displacement) {
							if (indirectJumpTable.RVA) {
								indirectJumpTable.Cases = op1.mem.disp.value + 1;
							} else {
								jumpTable.Cases = op1.mem.disp.value + 1;
							}

							break;
						}

						// Intentional fallthrough
					default:
						errorf("unexpected instruction (%p, %s) with index operand while parsing jump table (%p)", prevTrans->RVA().Start(), Util::FormatInstruction(prevInst, prevTrans->RVA().Start()).c_str(), rva.Start());
						throw TranslatorException();
				}
			}
		}

		if (!jumpTable.Cases && !indirectJumpTable.Cases) {
			this->TraceBranch(i, 0);
		}
	}

	if (!jumpTable.Cases && !indirectJumpTable.Cases) {
		errorf("failed to find all necessary data for jump table (%p)\n", rva.Start());
		throw TranslatorException();
	}

	if (indirectJumpTable.RVA) {
		auto rawIndirectJumpTable = this->TranslateRaw<PBYTE>(indirectJumpTable.RVA);
		if (!rawIndirectJumpTable) {
			errorf("failed to translate raw indirect jump table\n");
			throw TranslatorException();
		}

		for (auto i = 0ULL; i < indirectJumpTable.Cases; ++i) {
			auto entry = rawIndirectJumpTable + (i * indirectJumpTable.EntrySize);

			switch (indirectJumpTable.EntrySize) {
				case 1:
					jumpTable.Cases = std::max(static_cast<UINT_PTR>(*reinterpret_cast<PBYTE>(entry)), jumpTable.Cases);
					break;
				case 2:
					jumpTable.Cases = std::max(static_cast<UINT_PTR>(*reinterpret_cast<PUSHORT>(entry)), jumpTable.Cases);
					break;
				case 4:
					jumpTable.Cases = std::max(static_cast<UINT_PTR>(*reinterpret_cast<PUINT>(entry)), jumpTable.Cases);
					break;
				default:
					errorf("bad indirect jump table scale\n");
					throw TranslatorException();
			}
		}

		++jumpTable.Cases;

		auto rawIndirectJumpTableSize = indirectJumpTable.Cases * indirectJumpTable.EntrySize;
		indirectJumpTable.Mapped = VirtualAllocEx(this->Process(), nullptr, rawIndirectJumpTableSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!indirectJumpTable.Mapped) {
			errorf("failed to allocate virtual memory\n");
			throw TranslatorException();
		}

		WriteProcessMemory(this->Process(), indirectJumpTable.Mapped, rawIndirectJumpTable, rawIndirectJumpTableSize, nullptr);
		
		if (this->TranslateRawSection(indirectJumpTable.RVA)->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			memset(rawIndirectJumpTable, 0xCC, rawIndirectJumpTableSize);
		}
	}

	try {
		for (auto i = 0ULL; i < jumpTable.Cases; ++i) {
			auto entryRva = reinterpret_cast<PBYTE>(jumpTable.RVA) + i * 4;
			auto &entry = *this->TranslateRaw<PULONG>(entryRva);
			if (!entry) {
				errorf("found invalid jump table entry (%p)\n", rva.Start());
				throw TranslatorException();
			}

			if (jumpTable.IsRelative) {
				entry = static_cast<LONG>(entry) + static_cast<LONG>(reinterpret_cast<UINT_PTR>(jumpTable.RVA));
			}

			auto dest = reinterpret_cast<PVOID>(static_cast<UINT_PTR>(entry));
			this->AddBranch(dest, rva.Start());
			jumpTable.Entries.push_back(dest);

			if (this->TranslateRawSection(entryRva)->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				entry = 0xCCCCCCCC;
			}
		}

		jumpTable.Mapped = VirtualAllocEx(this->Process(), nullptr, jumpTable.Entries.size() * sizeof(PVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!jumpTable.Mapped) {
			errorf("failed to allocate virtual memory\n");
			throw TranslatorException();
		}
	} catch (INT e) {
		if (indirectJumpTable.Mapped) {
			VirtualFreeEx(this->Process(), indirectJumpTable.Mapped, 0, MEM_RELEASE);
		}

		throw e;
	}

	this->AddTranslation(new SwitchTranslation(rva, jumpBuffer, jumpInst.length, jumpTable.Entries, jumpTable.Mapped, indirectJumpTable.Mapped));
	this->RemoveTranslation(offset.TranslationIndex);

	auto lookupRva = this->Translations[jumpTable.LookupTranslationIndex].get()->RVA();
	auto unusedStr = ZydisRegisterGetString(Util::GetUnusedRegister(jumpTable.LookupInstruction));

	this->ReplaceTranslation(jumpTable.LookupTranslationIndex++, new ModifiedTranslation(lookupRva, "push %s", unusedStr));
	this->InsertTranslation(jumpTable.LookupTranslationIndex++, new ModifiedTranslation(lookupRva, "mov %s, 0x%p", unusedStr, jumpTable.Mapped));
	this->InsertTranslation(jumpTable.LookupTranslationIndex++, new ModifiedTranslation(lookupRva, "mov %s, [%s+%s*8]", ZydisRegisterGetString(jumpRegister), unusedStr, ZydisRegisterGetString(jumpTable.LookupOperands[1].mem.index)));
	this->InsertTranslation(jumpTable.LookupTranslationIndex, new ModifiedTranslation(lookupRva, "pop %s", unusedStr));

	if (indirectJumpTable.RVA) {
		lookupRva = this->Translations[indirectJumpTable.LookupTranslationIndex].get()->RVA();
		unusedStr = ZydisRegisterGetString(Util::GetUnusedRegister(indirectJumpTable.LookupInstruction));

		this->ReplaceTranslation(indirectJumpTable.LookupTranslationIndex++, new ModifiedTranslation(lookupRva, "push %s", unusedStr));
		this->InsertTranslation(indirectJumpTable.LookupTranslationIndex++, new ModifiedTranslation(lookupRva, "mov %s, 0x%p", unusedStr, indirectJumpTable.Mapped));
		
		auto lookupStr = Util::FormatInstruction(indirectJumpTable.LookupInstruction, lookupRva.Start());
		lookupStr = std::regex_replace(lookupStr, std::regex("\\[.*"), "");
		this->InsertTranslation(indirectJumpTable.LookupTranslationIndex++, new ModifiedTranslation(lookupRva, "%s[%s+%s*%d]", lookupStr.c_str(), unusedStr, ZydisRegisterGetString(indirectJumpTable.LookupIndexRegister), indirectJumpTable.LookupScale));
		
		this->InsertTranslation(indirectJumpTable.LookupTranslationIndex, new ModifiedTranslation(lookupRva, "pop %s", unusedStr));
	}

	return TRUE;
}

VOID Translator::AddRelativeTranslation(Region &rva, PBYTE instructionBuffer, ZydisDecodedInstruction &instruction) {
	auto operands = Util::GetInstructionOperands(instruction);
	auto absoluteAddr = Util::GetInstructionAbsoluteAddress(rva.Start(), instruction);

	switch (instruction.mnemonic) {
		case ZYDIS_MNEMONIC_LEA:
			this->AddTranslation(new RelativeTranslation(rva, absoluteAddr, "mov %s, 0x%p", ZydisRegisterGetString(operands[0].reg.value), ABSOLUTE_SIG));
			break;
		case ZYDIS_MNEMONIC_JMP:
			if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				auto sizeOfRawData = 14;
				auto rawData = new BYTE[sizeOfRawData]{ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				auto rvaOffset = 6;
				*reinterpret_cast<PVOID *>(&rawData[rvaOffset]) = absoluteAddr;

				this->AddBranch(absoluteAddr, rva.Start());
				this->AddTranslation(new RelativeTranslation(rva, rawData, sizeOfRawData, rvaOffset));
			} else {
				this->AddTranslation(new RelativeTranslation(rva, absoluteAddr, "mov r11, 0x%p", ABSOLUTE_SIG));
				this->AddTranslation(new ModifiedTranslation(rva, "jmp [r11]"));
			}
			
			break;
		case ZYDIS_MNEMONIC_CALL:
			if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				auto sizeOfRawData = 16;
				auto rawData = new BYTE[sizeOfRawData]{ 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				auto rvaOffset = 8;
				*reinterpret_cast<PVOID *>(&rawData[rvaOffset]) = absoluteAddr;

				this->AddTranslation(new RelativeTranslation(rva, rawData, sizeOfRawData, rvaOffset));
			} else {
				this->AddTranslation(new RelativeTranslation(rva, absoluteAddr, "mov r11, 0x%p", ABSOLUTE_SIG));
				this->AddTranslation(new ModifiedTranslation(rva, "call [r11]"));
			}

			break;
		case ZYDIS_MNEMONIC_JB:
		case ZYDIS_MNEMONIC_JBE:
		case ZYDIS_MNEMONIC_JCXZ:
		case ZYDIS_MNEMONIC_JECXZ:
		case ZYDIS_MNEMONIC_JKNZD:
		case ZYDIS_MNEMONIC_JKZD:
		case ZYDIS_MNEMONIC_JL:
		case ZYDIS_MNEMONIC_JLE:
		case ZYDIS_MNEMONIC_JNB:
		case ZYDIS_MNEMONIC_JNBE:
		case ZYDIS_MNEMONIC_JNL:
		case ZYDIS_MNEMONIC_JNLE:
		case ZYDIS_MNEMONIC_JNO:
		case ZYDIS_MNEMONIC_JNP:
		case ZYDIS_MNEMONIC_JNS:
		case ZYDIS_MNEMONIC_JNZ:
		case ZYDIS_MNEMONIC_JO:
		case ZYDIS_MNEMONIC_JP:
		case ZYDIS_MNEMONIC_JRCXZ:
		case ZYDIS_MNEMONIC_JS:
		case ZYDIS_MNEMONIC_JZ: {
			PBYTE rawData = nullptr;
			PBYTE buffer = nullptr;
			auto sizeOfRawData = 2 + 14;

			if (instruction.length > 3) {
				if (*instructionBuffer == 0xF2 || *instructionBuffer == 0xF3) {
					sizeOfRawData += 3;
					buffer = rawData = new BYTE[sizeOfRawData];
					*buffer = *instructionBuffer;

					++instructionBuffer;
					++buffer;
				} else {
					sizeOfRawData += 2;
					buffer = rawData = new BYTE[sizeOfRawData];
				}

				if (*instructionBuffer != 0x0F) {
					errorf("found malformed relative long jump (%p)\n", rva.Start());
					throw TranslatorException();
				}

				++instructionBuffer;

				*buffer = *instructionBuffer - 0x10;
				++buffer;
			} else {
				sizeOfRawData += instruction.length;
				buffer = rawData = new BYTE[sizeOfRawData];

				memcpy(buffer, instructionBuffer, instruction.length - 1);
				buffer += (instruction.length - 1);
			}

			*buffer = 0x02;
			++buffer;

			memcpy(buffer, "\xEB\x0E\xFF\x25\x00\x00\x00\x00", 8);
			buffer += 8;

			auto rvaOffset = static_cast<DWORD>(buffer - &rawData[0]);
			*reinterpret_cast<PVOID *>(buffer) = absoluteAddr;

			this->AddBranch(absoluteAddr, rva.Start());
			this->AddTranslation(new RelativeTranslation(rva, rawData, sizeOfRawData, rvaOffset));

			break;
		}
		default: {
			auto unusedStr = ZydisRegisterGetString(Util::GetUnusedRegister(instruction));

			this->AddTranslation(new ModifiedTranslation(rva, "push %s", unusedStr));
			this->AddTranslation(new RelativeTranslation(rva, absoluteAddr, "mov %s, 0x%p", unusedStr, ABSOLUTE_SIG));

			auto instructionStr = Util::FormatInstruction(instruction, rva.Start());
			instructionStr = std::regex_replace(instructionStr, std::regex("\\[.*\\]"), "[" + std::string(unusedStr) + "]");
			this->AddTranslation(new ModifiedTranslation(rva, "%s", instructionStr.c_str()));

			this->AddTranslation(new ModifiedTranslation(rva, "pop %s", unusedStr));

			break;
		}
	}
}

BOOLEAN Translator::IsRegisterBase(ZydisRegister reg, INT translationIndex, INT startingIndex) {
	if (Util::IsSameRegister(reg, ZYDIS_REGISTER_RSP)) {
		return FALSE;
	}

	for (auto i = translationIndex; i >= startingIndex; --i) {
		auto prevTrans = this->Translations[i].get();
		if (!prevTrans->Executable()) {
			continue;
		}

		if (i != translationIndex) {
			auto prevInst = Util::Disassemble(prevTrans->Buffer(), prevTrans->BufferSize());
			if (prevInst.mnemonic == ZYDIS_MNEMONIC_INT3 || prevInst.mnemonic == ZYDIS_MNEMONIC_INVALID) {
				return FALSE;
			}
		
			auto relativeTrans = dynamic_cast<RelativeTranslation *>(prevTrans);
			auto prevInstOperands = Util::GetInstructionOperands(prevInst);
			switch (prevInstOperands.size()) {
				case 1:
					if (prevInstOperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && Util::IsSameRegister(prevInstOperands[0].reg.value, reg)) {
						return FALSE;
					}

					break;
				case 2:
					if (prevInstOperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && Util::IsSameRegister(prevInstOperands[0].reg.value, reg)) {
						return relativeTrans && relativeTrans->Pointer() == nullptr;
					}

					break;
			}
		}

		this->TraceBranch(i, startingIndex);
	}

	return FALSE;
}

VOID Translator::FixSIB(INT translationIndex, INT startingIndex) {
	auto trans = dynamic_cast<DefaultTranslation *>(this->Translations[translationIndex].get());
	if (!trans) {
		return;
	}

	auto rva = trans->RVA();
	auto inst = Util::Disassemble(trans->Buffer(), trans->BufferSize());
	auto operands = Util::GetInstructionOperands(inst);
	if (operands.size() != 2) {
		return;
	}

	ZydisDecodedOperand sibOperand = { 0 };
	for (auto &op : operands) {
		if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.disp.has_displacement && op.mem.disp.value > 0) {
			sibOperand = op;
			break;
		}
	}

	if (sibOperand.type == ZYDIS_OPERAND_TYPE_UNUSED) {
		return;
	}

	if (this->IsRegisterBase(sibOperand.mem.base, translationIndex, startingIndex)) {
		auto unusedStr = ZydisRegisterGetString(Util::GetUnusedRegister(inst));

		this->ReplaceTranslation(translationIndex++, new ModifiedTranslation(rva, "push %s", unusedStr));
		this->InsertTranslation(translationIndex++, new RelativeTranslation(rva, reinterpret_cast<PVOID>(sibOperand.mem.disp.value), "mov %s, 0x%p", unusedStr, ABSOLUTE_SIG));

		auto instructionStr = Util::FormatInstruction(inst, rva.Start());
		instructionStr = std::regex_replace(instructionStr, std::regex("\\[[^\\+]*"), "[" + std::string(unusedStr));
		instructionStr = std::regex_replace(instructionStr, std::regex("\\+0x(.*)\\]"), "]");
		this->InsertTranslation(translationIndex++, new ModifiedTranslation(rva, "%s", instructionStr.c_str()));

		this->InsertTranslation(translationIndex, new ModifiedTranslation(rva, "pop %s", unusedStr));
	} else if (sibOperand.mem.scale == 1 && this->IsRegisterBase(sibOperand.mem.index, translationIndex, startingIndex)) {
		auto unusedStr = ZydisRegisterGetString(Util::GetUnusedRegister(inst));

		this->ReplaceTranslation(translationIndex++, new ModifiedTranslation(rva, "push %s", unusedStr));
		this->InsertTranslation(translationIndex++, new RelativeTranslation(rva, reinterpret_cast<PVOID>(sibOperand.mem.disp.value), "mov %s, 0x%p", unusedStr, ABSOLUTE_SIG));

		auto instructionStr = Util::FormatInstruction(inst, rva.Start());
		instructionStr = std::regex_replace(instructionStr, std::regex("\\+.*\\*1.*\\]"), "+" + std::string(unusedStr) + "]");
		this->InsertTranslation(translationIndex++, new ModifiedTranslation(rva, "%s", instructionStr.c_str()));

		this->InsertTranslation(translationIndex, new ModifiedTranslation(rva, "pop %s", unusedStr));
	}
}

VOID Translator::AddExecuteSection(PBYTE base, PIMAGE_SECTION_HEADER section) {
	// Do an initial pass to create a code map
	auto startingSize = static_cast<INT>(this->Translations.size());
	for (auto i = 0UL; i < section->SizeOfRawData; ) {
		auto instBuffer = base + section->PointerToRawData + i;
		auto inst = Util::Disassemble(instBuffer, section->SizeOfRawData - i);

		Region rva(section->VirtualAddress + i, inst.length);
		if (inst.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
			this->AddRelativeTranslation(rva, instBuffer, inst);
		} else if (inst.mnemonic == ZYDIS_MNEMONIC_JMP && this->AddSwitchTranslation(rva, instBuffer, inst)) {
			// Success
		} else {
			this->AddTranslation(new DefaultTranslation(rva, instBuffer, inst.length));
		}

		i += inst.length;
	}

	// Do a second pass analyzing relative SIB instructions utilizing the code map
	for (auto i = startingSize; i < this->Translations.size(); ++i) {
		this->FixSIB(i, startingSize);
	}
}