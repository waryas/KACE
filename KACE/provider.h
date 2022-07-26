#pragma once

#include <string>
#include <unordered_map>

namespace Provider {
    uintptr_t FindFuncImpl(uintptr_t ptr);
    uintptr_t FindDataImpl(uintptr_t ptr);

    uintptr_t AddFuncImpl(const char* nameFunc, PVOID hookFunc);
    uintptr_t AddDataImpl(const char* nameExport, PVOID hookExport, size_t exportSize);

    uint64_t unimplemented_stub();
}; // namespace Provider