#include "smap.h"
#include "align.h"
#include "map.h"
#include "hijack.h"
#include "util.h"

// Scatter manual maps the DLL into the process
BOOLEAN SMap::Inject() {
    this->ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->ProcessId);
    if (!this->ProcessHandle) {
        errorf("failed to open a handle to the process\n");
        return FALSE;
    }

    auto alignments = Align::FindAlignmentsInModules(this->ProcessHandle);
    auto entry = Map::MapIntoRegions(this->ProcessHandle, this->DllPath,
        alignments, this->ScatterThreshold);
    if (!entry) {
        return FALSE;
    }

    if (this->UseIAT) {
        if (!Hijack::HijackViaIAT(this->ProcessHandle, entry, this->TargetFunction,
            this->TargetModule)) {
            return FALSE;
        }
    } else if (!Hijack::HijackViaHook(this->ProcessHandle, entry,
        this->TargetModule, this->TargetFunction)) {
        return FALSE;
    }

    printf("\n[-] done!\n");
    return TRUE;
}