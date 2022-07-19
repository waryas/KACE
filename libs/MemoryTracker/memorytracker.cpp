#pragma once

#include "memorytracker.h"

static __declspec(align(0x1000)) unsigned char PreAllocatedMemory[64 * 1024 * 1024] = { 0 }; //64MB - 15360 variables trackable, should be enough.


unsigned long MemoryTracker::usedPage = 0;

void MemoryTracker::Initiate() {
	
	if (!mem)
		mem = new MemoryTracker();
};

bool MemoryTracker::TrackVariable(uint64_t ptr, uint64_t size, std::string name) {
	DWORD oldProtect = 0;
	uint64_t totalPage = (size / 4096) + ((size % 4096) ? 1 : 0);
	for (int i = 0; i < totalPage; i++) {
		mem->mapping.insert(std::pair(ptr + (i * 0x1000), name));
		VirtualProtect((PVOID)(ptr + (i * 0x1000)), 0x1000, PAGE_READWRITE | PAGE_GUARD, &oldProtect);
	}
	mem->firstAlloc.insert(std::pair(name, ptr));;
	return true;
}

bool MemoryTracker::isTracked(uint64_t ptr) {
	return mem->mapping.contains(PAGE_ALIGN_DOWN(ptr));
}

uintptr_t MemoryTracker::AllocateVariable(uint64_t size) {
	uint64_t totalPage = (size / 4096) + ((size % 4096) ? 1 : 0); //No matter how small, a variable will always use 0x1000 memory for easier tracking.
	auto ptr = &PreAllocatedMemory[0x1000 * usedPage];
	usedPage += totalPage;
	return (uintptr_t)ptr;
}

std::string MemoryTracker::getName(uint64_t ptr) {
	return mem->mapping[PAGE_ALIGN_DOWN(ptr)];
}

uint64_t MemoryTracker::getStart(std::string name) {
	return mem->firstAlloc[name];
}

MemoryTracker* MemoryTracker::mem = nullptr;
