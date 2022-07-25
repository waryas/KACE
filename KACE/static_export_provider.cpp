#include "module_layout.h"

#include "static_export_provider.h"
#include "ntoskrnl_provider.h"

std::unordered_map<std::string, void*> constantTimeExportProvider;

namespace ntoskrnl_export {

    /*

    void Initialize() {
        InitializeExport();
        InitializePsProcessType();
        InitializePsLoadedModuleList();

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

        constantTimeExportProvider.insert({ "SeExports", (PVOID)SeExport });
        constantTimeExportProvider.insert({ "InitSafeBootMode", &InitSafeBootMode });
        constantTimeExportProvider.insert({ "KdDebuggerNotPresent", &KdDebuggerNotPresent });
        constantTimeExportProvider.insert({ "CcFastMdlReadWait", &CcFastMdlReadWait });
        constantTimeExportProvider.insert({ "CmKeyObjectType", &CmKeyObjectType });
        constantTimeExportProvider.insert({ "ExActivationObjectType", &ExActivationObjectType });
        constantTimeExportProvider.insert({ "ExCompositionObjectType", &ExCompositionObjectType });
        constantTimeExportProvider.insert({ "ExCoreMessagingObjectType", &ExCoreMessagingObjectType });
        constantTimeExportProvider.insert({ "ExDesktopObjectType", &ExDesktopObjectType });
        constantTimeExportProvider.insert({ "ExEventObjectType", &ExEventObjectType });
        constantTimeExportProvider.insert({ "ExRawInputManagerObjectType", &ExRawInputManagerObjectType });
        constantTimeExportProvider.insert({ "ExSemaphoreObjectType", &ExSemaphoreObjectType });
        constantTimeExportProvider.insert({ "ExTimerObjectType", &ExTimerObjectType });
        constantTimeExportProvider.insert({ "ExWindowStationObjectType", &ExWindowStationObjectType });
        constantTimeExportProvider.insert({ "FsRtlLegalAnsiCharacterArray", &FsRtlLegalAnsiCharacterArray });
        constantTimeExportProvider.insert({ "HalDispatchTable", &HalDispatchTable });
        constantTimeExportProvider.insert({ "HalPrivateDispatchTable", &HalPrivateDispatchTable });
        constantTimeExportProvider.insert({ "IoAdapterObjectType", &IoAdapterObjectType });
        constantTimeExportProvider.insert({ "IoCompletionObjectType", &IoCompletionObjectType });
        constantTimeExportProvider.insert({ "IoDeviceHandlerObjectSize", &IoDeviceHandlerObjectSize });
        constantTimeExportProvider.insert({ "IoDeviceHandlerObjectType", &IoDeviceHandlerObjectType });
        constantTimeExportProvider.insert({ "IoDeviceObjectType", &IoDeviceObjectType });
        constantTimeExportProvider.insert({ "IoDriverObjectType", &IoDriverObjectType });
        constantTimeExportProvider.insert({ "IoFileObjectType", &IoFileObjectType });
        constantTimeExportProvider.insert({ "IoReadOperationCount", &IoReadOperationCount });
        constantTimeExportProvider.insert({ "IoReadTransferCount", &IoReadTransferCount });
        constantTimeExportProvider.insert({ "IoStatisticsLock", &IoStatisticsLock });
        constantTimeExportProvider.insert({ "IoWriteOperationCount", &IoWriteOperationCount });
        constantTimeExportProvider.insert({ "IoWriteTransferCount", &IoWriteTransferCount });
        constantTimeExportProvider.insert({ "KdComPortInUse", &KdComPortInUse });
        constantTimeExportProvider.insert({ "KdDebuggerEnabled", &KdDebuggerEnabled });
        constantTimeExportProvider.insert({ "KdEnteredDebugger", &KdEnteredDebugger });
        constantTimeExportProvider.insert({ "KdEventLoggingEnabled", &KdEventLoggingEnabled });
        constantTimeExportProvider.insert({ "KdHvComPortInUse", &KdHvComPortInUse });
        constantTimeExportProvider.insert({ "KeDynamicPartitioningSupported", &KeDynamicPartitioningSupported });
        constantTimeExportProvider.insert({ "KeLastBranchMSR", &KeLastBranchMSR });
        constantTimeExportProvider.insert({ "KeLoaderBlock", &KeLoaderBlock });
        constantTimeExportProvider.insert({ "KeNumberProcessors", &KeNumberProcessors });
        constantTimeExportProvider.insert({ "KiBugCheckData", &KiBugCheckData });
        constantTimeExportProvider.insert({ "LpcPortObjectType", &LpcPortObjectType });
        constantTimeExportProvider.insert({ "Mm64BitPhysicalAddress", &Mm64BitPhysicalAddress });
        constantTimeExportProvider.insert({ "MmBadPointer", &MmBadPointer });
        constantTimeExportProvider.insert({ "MmHighestUserAddress", &MmHighestUserAddress });
        constantTimeExportProvider.insert({ "MmSectionObjectType", &MmSectionObjectType });
        constantTimeExportProvider.insert({ "MmSystemRangeStart", &MmSystemRangeStart });
        constantTimeExportProvider.insert({ "MmUserProbeAddress", &MmUserProbeAddress });
        constantTimeExportProvider.insert({ "NlsAnsiCodePage", &NlsAnsiCodePage });
        constantTimeExportProvider.insert({ "NlsMbCodePageTag", &NlsMbCodePageTag });
        constantTimeExportProvider.insert({ "NlsMbOemCodePageTag", &NlsMbOemCodePageTag });
        constantTimeExportProvider.insert({ "NlsOemCodePage", &NlsOemCodePage });
        constantTimeExportProvider.insert({ "NtBuildGUID", &NtBuildGUID });
        constantTimeExportProvider.insert({ "NtBuildLab", &NtBuildLab });
        constantTimeExportProvider.insert({ "NtBuildNumber", &NtBuildNumber });
        constantTimeExportProvider.insert({ "NtGlobalFlag", &NtGlobalFlag });
        constantTimeExportProvider.insert({ "POGOBuffer", &POGOBuffer });
        constantTimeExportProvider.insert({ "PsInitialSystemProcess", &PsInitialSystemProcess });
        constantTimeExportProvider.insert({ "PsJobType", &PsJobType });
        constantTimeExportProvider.insert({ "PsLoadedModuleList", &PsLoadedModuleList });
        constantTimeExportProvider.insert({ "PsLoadedModuleResource", &PsLoadedModuleResource });
        constantTimeExportProvider.insert({ "PsPartitionType", &PsPartitionType });
        constantTimeExportProvider.insert({ "PsProcessType", &PsProcessType });
        constantTimeExportProvider.insert({ "PsSiloContextNonPagedType", &PsSiloContextNonPagedType });
        constantTimeExportProvider.insert({ "PsSiloContextPagedType", &PsSiloContextPagedType });
        constantTimeExportProvider.insert({ "PsThreadType", &PsThreadType });
        constantTimeExportProvider.insert({ "PsUILanguageComitted", &PsUILanguageComitted });
        constantTimeExportProvider.insert({ "SeILSigningPolicyPtr", &SeILSigningPolicyPtr });
        constantTimeExportProvider.insert({ "SePublicDefaultDacl", &SePublicDefaultDacl });
        constantTimeExportProvider.insert({ "SeSystemDefaultDacl", &SeSystemDefaultDacl });
        constantTimeExportProvider.insert({ "SeSystemDefaultSd", &SeSystemDefaultSd });
        constantTimeExportProvider.insert({ "SeTokenObjectType", &SeTokenObjectType });
        constantTimeExportProvider.insert({ "TmEnlistmentObjectType", &TmEnlistmentObjectType });
        constantTimeExportProvider.insert({ "TmResourceManagerObjectType", &TmResourceManagerObjectType });
        constantTimeExportProvider.insert({ "TmTransactionManagerObjectType", &TmTransactionManagerObjectType });
        constantTimeExportProvider.insert({ "TmTransactionObjectType", &TmTransactionObjectType });
        constantTimeExportProvider.insert({ "psMUITest", &psMUITest });


    }
    */
}



