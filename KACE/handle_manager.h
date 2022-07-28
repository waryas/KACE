#include <unordered_map>
#include "ntoskrnl_struct.h"

namespace HandleManager {
    bool AddMap(uintptr_t, uintptr_t);
    uintptr_t GetHandle(uintptr_t);
} // namespace HandleManager

#pragma comment(lib, "Onecore.lib")

namespace TimerManager {
    inline std::unordered_map<_KTIMER*, uint64_t> timer_manager;
}

namespace MutexManager {
    inline std::unordered_map<uintptr_t, uint64_t> mutex_manager;
}