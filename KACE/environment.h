#pragma once
#include <unordered_map>
#include <windows.h>

struct windows_module {
    ULONG Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
    ULONG Checksum;
    ULONG Timestamp;
    PVOID Defaultbase;
    bool overriden;
};

namespace Environment {
    static std::unordered_map<uintptr_t, windows_module> environment_module;

    void InitializeSystemModules();
    void CheckPtr(uint64_t ptr);
} // namespace Environment