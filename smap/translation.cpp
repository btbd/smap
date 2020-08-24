#include "translation.h"
#include "translator.h"
#include "align.h"

// Resets the mapped region, either by freeing it or restoring the function alignment
static VOID ResetMappedRegion(Translator &translator, Translation &translation) {
    auto size = translation.BufferSize();
    if (!size) {
        return;
    }

    auto mapped = translation.Mapped();
    if (!mapped) {
        return;
    }

    if (translation.FreeOnFail()) {
        VirtualFreeEx(translator.Process(), mapped, 0, MEM_RELEASE);
    } else {
        auto buffer = new BYTE[size];
        memset(buffer, ALIGNMENT_BYTE, size);

        WriteProcessMemory(translator.Process(), mapped, buffer, size, nullptr);

        delete[] buffer;
    }

    translation.Mapped(nullptr);
}

VOID DefaultTranslation::Fail(Translator &translator) {
    ResetMappedRegion(translator, *this);
}

VOID RegionTranslation::Fail(Translator &translator) {
    ResetMappedRegion(translator, *this);
}

VOID ModifiedTranslation::Fail(Translator &translator) {
    ResetMappedRegion(translator, *this);
}

BOOLEAN RelativeTranslation::Resolve(Translator &translator) {
    auto &rva = this->Pointer();
    rva = translator.Translate(rva);
    return rva != nullptr;
}

VOID RelativeTranslation::Fail(Translator &translator) {
    ResetMappedRegion(translator, *this);
}

BOOLEAN SwitchTranslation::Resolve(Translator &translator) {
    for (auto &rva : this->JumpTable) {
        rva = translator.Translate(rva);
        if (!rva) {
            return FALSE;
        }
    }

    if (!WriteProcessMemory(translator.Process(), this->MappedJumpTable,
        &this->JumpTable[0],
        this->JumpTable.size() * sizeof(PVOID), nullptr)) {
        return FALSE;
    }

    return TRUE;
}

VOID SwitchTranslation::Fail(Translator &translator) {
    if (this->MappedJumpTable) {
        VirtualFreeEx(translator.Process(), this->MappedJumpTable, 0, MEM_RELEASE);
        this->MappedJumpTable = nullptr;
    }

    if (this->MappedIndirectJumpTable) {
        VirtualFreeEx(translator.Process(), this->MappedIndirectJumpTable, 0,
            MEM_RELEASE);
        this->MappedIndirectJumpTable = nullptr;
    }

    ResetMappedRegion(translator, *this);
}