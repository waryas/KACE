#pragma once
#include <unordered_map>
#include <windows.h>
#include "ntoskrnl_struct.h"
#include "utils.h"

namespace Environment {
    inline std::unordered_map<uintptr_t, LDR_DATA_TABLE_ENTRY> environment_module{};
    inline PLDR_DATA_TABLE_ENTRY PsLoadedModuleList;

    void InitializeSystemModules();
    void CheckPtr(uint64_t ptr);

    namespace ThreadManager {
        inline std::unordered_map<uintptr_t, _ETHREAD*> environment_threads{};

    }
} 