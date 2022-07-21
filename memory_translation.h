
#include <unordered_map>

namespace MemoryTranslation { //Used for Kernel<->User dynamic address translation
	bool AddMapping(uintptr_t GVA, size_t bytes,  uintptr_t HVA);
	uint64_t GetHVA(uintptr_t GVA);
};