#pragma once

#include <unordered_map>
#include <windows.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & PAGE_MASK)

#define PAGE_ALIGN_DOWN(addr) (((addr)) & PAGE_MASK)

class MemoryTracker {


public:
    static void Initiate() {
        if (!mem)
            mem = new MemoryTracker();
    };
    static bool TrackVariable(uint64_t ptr, uint64_t size, char* name) {
        DWORD oldProtect = 0;
        uint64_t totalPage = (size / 4096) + ((size % 4096) ? 1 : 0);
        for (int i = 0; i < totalPage; i++) {
            mem->mapping.insert(std::pair(ptr + (i * 0x1000), name));
            VirtualProtect((PVOID)(ptr + (i * 0x1000)), 0x1000, PAGE_READWRITE | PAGE_GUARD, &oldProtect);
        }
        mem->firstAlloc.insert(std::pair(name, ptr));;
        return true;
    }

    static bool isTracked(uint64_t ptr) {
        return mem->mapping.contains(PAGE_ALIGN_DOWN(ptr));
    }

    static std::string getName(uint64_t ptr) {
        return mem->mapping[PAGE_ALIGN_DOWN(ptr)];
    }
    static uint64_t getStart(std::string name) {
        return mem->firstAlloc[name];
    }

private:
    static MemoryTracker* mem; //singleton

    std::unordered_map<uint64_t, std::string> mapping;
    std::unordered_map<std::string, uint64_t> firstAlloc;

    MemoryTracker() {
        return;
    };

};

MemoryTracker* MemoryTracker::mem = nullptr;
