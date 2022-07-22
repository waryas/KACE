#include "memory_translation.h"

/*
namespace MemoryTranslation { //Used for Kernel<->User dynamic address translation
	std::unordered_map<uint64_t, uint64_t> GVAMapping; //Guest Memory(key) -> Host Memory page
	bool AddMapping(uintptr_t GVA, size_t bytes, uintptr_t HVA);
	uint64_t GetHVA(uintptr_t GVA);
};
*/

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & PAGE_MASK)

#define PAGE_ALIGN_DOWN(addr) (((addr)) & PAGE_MASK)

static std::unordered_map<uint64_t, uint64_t> GVAMapping;

bool MemoryTranslation::AddMapping(uintptr_t GVA, size_t size, uintptr_t HVA) {
	uint64_t totalPage = (size / 4096) + ((size % 4096) ? 1 : 0); //No matter how small, a variable will always use 0x1000 memory for easier tracking.

	for (int i = 0; i < totalPage; i++) {
		GVAMapping.insert(std::pair(GVA + (i * 0x1000), HVA + (i * 0x1000)));
	}
	return true;
}

uint64_t MemoryTranslation::GetHVA(uintptr_t GVA) {
	
	uint64_t pageStart = PAGE_ALIGN_DOWN(GVA);
	uint64_t offset = GVA - pageStart;
	if (GVAMapping.contains(pageStart)) {
		return GVAMapping[pageStart] + offset;
	}
	else {
		return 0;
	}
}