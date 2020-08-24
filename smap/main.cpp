#include "smap.h"
#include "util.h"

INT main(INT argc, LPCSTR *argv) {
    auto processId = 0UL;
    std::wstring dllPath, targetModule;
    LPCSTR targetFunction = nullptr;
    auto scatterThreshold = 1UL;
    BOOLEAN useIat = FALSE;

    for (auto i = 1, ri = 0; i < argc; ++i) {
        auto arg = argv[i];
        if (arg[0] == '-') {
            for (auto c = &arg[1]; *c; ++c) {
                switch (tolower(*c)) {
                    case 's':
                        if (i != argc - 1) {
                            scatterThreshold = atoi(argv[++i]);
                        }

                        break;
                    case 'i':
                        useIat = TRUE;
                        break;
                    case 'm':
                        if (i != argc - 1) {
                            ++i;
                            targetModule = std::wstring(argv[i], &argv[i][strlen(argv[i])]);
                        }

                        break;
                    case 'n':
                        if (i != argc - 1) {
                            targetFunction = argv[++i];
                        }

                        break;
                }
            }
        } else {
            switch (ri++) {
                case 0:
                    processId = atoi(arg);
                    if (!processId) {
                        processId = Util::GetProcessInfoByName(
                            std::wstring(arg, &arg[strlen(arg)]).c_str())
                            .th32ProcessID;
                    }

                    break;
                case 1:
                    dllPath = std::wstring(arg, &arg[strlen(arg)]);
                    break;
            }
        }
    }

    if (dllPath.size() == 0) {
        printf("usage: smap [OPTIONS]... <PID|PROCESS> <DLL>\n");
        printf("options:\n");
        printf("  -s int      scatter threshold (default 1)\n");
        printf("  -i          use an IAT change instead of a hook\n");
        printf("  -m string   name of the target module (default user32.dll for hook, process base for IAT)\n");
        printf("  -n string   name of the target function (default PeekMessageW)\n");
        return 1;
    }

    if (!processId) {
        errorf("process not found\n");
        return 1;
    }

    return 1 - SMap(processId, dllPath.c_str(), targetModule.c_str(), targetFunction,
        scatterThreshold, useIat)
        .Inject();
}