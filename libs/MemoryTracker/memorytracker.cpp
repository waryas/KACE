#pragma once

#include "memorytracker.h"

static __declspec(align(0x1000)) unsigned char PreAllocatedMemory[64 * 1024 * 1024] = { 0 }; //64MB - 15360 variables trackable, should be enough.

unsigned long MemoryTracker::usedPage = 0;

inline std::unordered_map<uint64_t, uint64_t> GVAMapping{};

bool MemoryTracker::AddMapping(uintptr_t GVA, size_t size, uintptr_t HVA) {

    if (GVA != PAGE_ALIGN_DOWN(GVA)) {
        DebugBreak(); //Can only track variables that are page_aligned;
    }
    uint64_t totalPage = (size / 4096) + ((size % 4096) ? 1 : 0); //No matter how small, a variable will always use 0x1000 memory for easier tracking.

    for (int i = 0; i < totalPage; i++) {
        GVAMapping.insert(std::pair(GVA + (i * 0x1000), HVA + (i * 0x1000)));
    }
    return true;
}

uint64_t MemoryTracker::GetHVA(uintptr_t GVA) {

    uint64_t pageStart = PAGE_ALIGN_DOWN(GVA);
    uint64_t offset = GVA - pageStart;
    if (GVAMapping.contains(pageStart)) {
        return GVAMapping[pageStart] + offset;
    } else {
        return 0;
    }
}

void MemoryTracker::Initiate() {

    if (!mem)
        mem = new MemoryTracker();
};

bool MemoryTracker::TrackVariable(uint64_t ptr, uint64_t size, std::string name) {

    if (ptr != PAGE_ALIGN_DOWN(ptr)) {
        DebugBreak(); //Can only track variables that are page_aligned;
    }
    DWORD oldProtect = 0;
    uint64_t totalPage = (size / 4096) + ((size % 4096) ? 1 : 0);

    for (int i = 0; i < totalPage; i++) {
        mem->mapping.insert(std::pair(ptr + (i * 0x1000), name));
        auto shadowmemory = (uintptr_t)_aligned_malloc(0x1000, 0x1000);
        AddMapping(ptr + (i * 0x1000), 0x1000, shadowmemory);
        memcpy((PVOID)shadowmemory, (PVOID)(ptr + (i * 0x1000)), 0x1000);
        VirtualProtect((PVOID)(ptr + (i * 0x1000)), 0x1000, PAGE_NOACCESS, &oldProtect);
    }

    mem->firstAlloc.insert(std::pair(name, ptr));
    return true;
}


bool MemoryTracker::TrackVariable(uint64_t ptr, uint64_t size, std::string name, uintptr_t gva) {

    if (ptr != PAGE_ALIGN_DOWN(ptr)) {
        DebugBreak(); //Can only track variables that are page_aligned;
    }
    if (gva != PAGE_ALIGN_DOWN(gva)) {
        DebugBreak(); //Can only track variables that are page_aligned;
    }
    DWORD oldProtect = 0;
    uint64_t totalPage = (size / 4096) + ((size % 4096) ? 1 : 0);

    for (int i = 0; i < totalPage; i++) {
        mem->mapping.insert(std::pair(ptr + (i * 0x1000), name));
        mem->mapping.insert(std::pair(gva + (i * 0x1000), name));
        auto shadowmemory = (uintptr_t)_aligned_malloc(0x1000, 0x1000);
        AddMapping(ptr + (i * 0x1000), 0x1000, shadowmemory);
        AddMapping(gva + (i * 0x1000), 0x1000, shadowmemory);
        memcpy((PVOID)shadowmemory, (PVOID)(ptr + (i * 0x1000)), 0x1000);
        VirtualProtect((PVOID)(ptr + (i * 0x1000)), 0x1000, PAGE_NOACCESS, &oldProtect);
    }

    mem->firstAlloc.insert(std::pair(name, gva));
    return true;
}


bool MemoryTracker::isTracked(uint64_t ptr) { return mem->mapping.contains(PAGE_ALIGN_DOWN(ptr)); }

uintptr_t MemoryTracker::AllocateVariable(uint64_t size) {
    uint64_t totalPage = (size / 4096) + ((size % 4096) ? 1 : 0); //No matter how small, a variable will always use 0x1000 memory for easier tracking.
    auto ptr = &PreAllocatedMemory[0x1000 * usedPage];

    usedPage += totalPage;
    return (uintptr_t)ptr;
}

std::string MemoryTracker::getName(uint64_t ptr) { return mem->mapping[PAGE_ALIGN_DOWN(ptr)]; }

uint64_t MemoryTracker::getStart(std::string name) { return mem->firstAlloc[name]; }

MemoryTracker* MemoryTracker::mem = nullptr;
