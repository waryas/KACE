#include "handle_manager.h"
#include <windows.h>
static std::unordered_map<uintptr_t, uintptr_t> HandleMap;

bool HandleManager::AddMap(uintptr_t kernelObject, uintptr_t umHandle) {
    if (HandleMap.contains(kernelObject))
        return false;
    HandleMap.insert(std::pair(kernelObject, umHandle));
    return true;
}

uintptr_t HandleManager::GetHandle(uintptr_t kernelObject) {
    if (!HandleMap.contains(kernelObject)) { //Why would we request a non existing opened handle? Bad Impl somewhere, let's investigate
        DebugBreak();
    }
    return HandleMap[kernelObject];
}