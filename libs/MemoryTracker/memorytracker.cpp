#pragma once

#include "memorytracker.h"

void MemoryTracker::Initiate() {
	if (!mem)
		mem = new MemoryTracker();
};
bool MemoryTracker::TrackVariable(uint64_t ptr, uint64_t size, char* name) {
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

std::string MemoryTracker::getName(uint64_t ptr) {
	return mem->mapping[PAGE_ALIGN_DOWN(ptr)];
}
uint64_t MemoryTracker::getStart(std::string name) {
	return mem->firstAlloc[name];
}

MemoryTracker* MemoryTracker::mem = nullptr;
