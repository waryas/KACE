#pragma once
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
    static void Initiate();
    static bool TrackVariable(uint64_t ptr, uint64_t size, char* name);
    static bool isTracked(uint64_t ptr);
    static std::string getName(uint64_t ptr);
    static uint64_t getStart(std::string name);

private:
    static MemoryTracker* mem; //singleton

    std::unordered_map<uint64_t, std::string> mapping;
    std::unordered_map<std::string, uint64_t> firstAlloc;

};
