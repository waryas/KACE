#include "module_layout.h"

#include "static_export_provider.h"
#include "ntoskrnl_provider.h"
#include "provider.h"

namespace ntoskrnl_export {


    void Initialize() {
        InitializeExport();
    }


    void InitializePsProcessType() {
        PsProcessType = (_OBJECT_TYPE*)MemoryTracker::AllocateVariable(sizeof(_OBJECT_TYPE) * 2);
        PsProcessType->TotalNumberOfObjects = 1;
        MemoryTracker::TrackVariable((uint64_t)PsProcessType, sizeof(_OBJECT_TYPE) * 2, (char*)"NTOSKRNL.PsProcessType");
    }

    void InitializePsLoadedModuleList() {

        PsLoadedModuleList = (_KLDR_DATA_TABLE_ENTRY*)MemoryTracker::AllocateVariable(sizeof(_KLDR_DATA_TABLE_ENTRY) * 2);
        PsLoadedModuleList->InLoadOrderLinks.Blink = &PsLoadedModuleList->InLoadOrderLinks;
        PsLoadedModuleList->InLoadOrderLinks.Flink = &PsLoadedModuleList->InLoadOrderLinks;
        h_RtlInitUnicodeString(&PsLoadedModuleList->BaseDllName, L"C:\\Windows\\system32\\ntoskrnl.exe");
        h_RtlInitUnicodeString(&PsLoadedModuleList->FullDllName, L"C:\\Windows\\system32\\ntoskrnl.exe");
        PsLoadedModuleList->LoadCount = 1;
        MemoryTracker::TrackVariable((uint64_t)PsLoadedModuleList, sizeof(_KLDR_DATA_TABLE_ENTRY) * 2, (char*)"NTOSKRNL.PsLoadedModuleList");

    }

    void InitializeExport() {
        PsInitialSystemProcess = (uint64_t)&FakeSystemProcess;

        ntoskrnl_export::InitializePsProcessType();
        ntoskrnl_export::InitializePsLoadedModuleList();

        Provider::AddDataImpl("SeExports", (PVOID)SeExport, sizeof(SeExport));
        Provider::AddDataImpl("KdDebuggerNotPresent", &KdDebuggerNotPresent, sizeof(KdDebuggerNotPresent));
        Provider::AddDataImpl("KdDebuggerEnabled", &KdDebuggerEnabled, sizeof(KdDebuggerEnabled));
        Provider::AddDataImpl("KdEnteredDebugger", &KdEnteredDebugger, sizeof(KdEnteredDebugger));
        Provider::AddDataImpl("PsInitialSystemProcess", &PsInitialSystemProcess, sizeof(PsInitialSystemProcess));
        Provider::AddDataImpl("PsLoadedModuleList", &PsLoadedModuleList, sizeof(PsLoadedModuleList));
        Provider::AddDataImpl("PsProcessType", &PsProcessType, sizeof(PsProcessType));
        Provider::AddDataImpl("PsThreadType", &PsThreadType, sizeof(PsThreadType));

    }
  
}



