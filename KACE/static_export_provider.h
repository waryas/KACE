#pragma once

#include <unordered_map>

#include "ntoskrnl_struct.h"
#include <MemoryTracker/memorytracker.h>

#pragma section("hookaccess", read, write)
#define MONITOR extern "C" inline __declspec(dllexport, allocate("hookaccess"))

MONITOR uint32_t InitSafeBootMode = 0;
MONITOR unsigned char KdDebuggerNotPresent = true;

MONITOR const char SeExport[]
    = "\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x06"
      "\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x0a"
      "\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x0c"
      "\x00\x00\x00\x00\x00\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x12"
      "\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x00\x00\x00\x00\x00\x16"
      "\x00\x00\x00\x00\x00\x00\x00\x17\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\xc0\xcf\xc5\xda\x81\xc2\xff\xff\xc0"
      "\xef\x64\xdd\x0f\xb2\xff\xff\xa0\x5f\x65\xdd\x0f\xb2\xff\xff\xc0\x6f\x65\xdd\x0f\xb2\xff\xff\xf0\xf4\x63\xdd\x0f\xb2\xff\xff\xc0"
      "\xbf\xc1\xda\x81\xc2\xff\xff\x30\x2d\xc2\xda\x81\xc2\xff\xff\xa0\xbf\x64\xdd\x0f\xb2\xff\xff\xc0\xad\x65\xdd\x0f\xb2\xff\xff\xc0"
      "\x3f\x69\xdd\x0f\xb2\xff\xff\x50\xfc\x66\xdd\x0f\xb2\xff\xff\x60\x3a\xc0\xda\x81\xc2\xff\xff\xf0\xc1\xca\xda\x81\xc2\xff\xff\x50"
      "\xc3\xca\xda\x81\xc2\xff\xff\x30\xc2\xca\xda\x81\xc2\xff\xff\x50\xc4\xca\xda\x81\xc2\xff\xff\x30\xc4\xca\xda\x81\xc2\xff\xff\xb0"
      "\xc3\xca\xda\x81\xc2\xff\xff\xf0\xc0\xca\xda\x81\xc2\xff\xff\xd0\x6e\xc0\xda\x81\xc2\xff\xff\xc0\xdf\xc1\xda\x81\xc2\xff\xff\x80"
      "\x0b\xc4\xda\x81\xc2\xff\xff\x19\x00\x00\x00\x00\x00\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x00\x1b\x00\x00\x00\x00\x00\x00\x00\xc0"
      "\x5f\xc1\xda\x81\xc2\xff\xff\x00\x3a\xc0\xda\x81\xc2\xff\xff\x1c\x00\x00\x00\x00\x00\x00\x00\x1d\x00\x00\x00\x00\x00\x00\x00\x1e"
      "\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x21\x00\x00\x00\x00\x00\x00\x00\x22"
      "\x00\x00\x00\x00\x00\x00\x00\x23\x00\x00\x00\x00\x00\x00\x00\x30\x3a\xc0\xda\x81\xc2\xff\xff\x90\x3f\x67\xdd\x0f\xb2\xff\xff\xc0"
      "\x3f\x67\xdd\x0f\xb2\xff\xff\x40\x7e\x65\xdd\x0f\xb2\xff\xff\x70\x7e\x65\xdd\x0f\xb2\xff\xff\x90\xb0\x6a\xdd\x0f\xb2\xff\xff\xa0"
      "\xcf\x66\xdd\x0f\xb2\xff\xff\x50\xb4\x6a\xdd\x0f\xb2\xff\xff\x10\x12\x66\xdd\x0f\xb2\xff\xff\xd0\xb0\x6a\xdd\x0f\xb2\xff\xff\x90"
      "\x13\x66\xdd\x0f\xb2\xff\xff\x24\x00\x00\x00\x00\x00\x00\x00";

//These are not analyzed yet to be correct type

MONITOR uint64_t CcFastMdlReadWait = 0;
MONITOR uint64_t CmKeyObjectType = 0;
MONITOR uint64_t ExActivationObjectType = 0;
MONITOR uint64_t ExCompositionObjectType = 0;
MONITOR uint64_t ExCoreMessagingObjectType = 0;
MONITOR uint64_t ExDesktopObjectType = 0;
MONITOR uint64_t ExEventObjectType = 0;
MONITOR uint64_t ExRawInputManagerObjectType = 0;
MONITOR uint64_t ExSemaphoreObjectType = 0;
MONITOR uint64_t ExTimerObjectType = 0;
MONITOR uint64_t ExWindowStationObjectType = 0;
MONITOR uint64_t FsRtlLegalAnsiCharacterArray = 0;
MONITOR uint64_t HalDispatchTable = 0;
MONITOR uint64_t HalPrivateDispatchTable = 0;
MONITOR uint64_t IoAdapterObjectType = 0;
MONITOR uint64_t IoCompletionObjectType = 0;
MONITOR uint64_t IoDeviceHandlerObjectSize = 0;
MONITOR uint64_t IoDeviceHandlerObjectType = 0;
MONITOR uint64_t IoDeviceObjectType = 0;
MONITOR uint64_t IoDriverObjectType = 0;
MONITOR uint64_t IoFileObjectType = 0;
MONITOR uint64_t IoReadOperationCount = 0;
MONITOR uint64_t IoReadTransferCount = 0;
MONITOR uint64_t IoStatisticsLock = 0;
MONITOR uint64_t IoWriteOperationCount = 0;
MONITOR uint64_t IoWriteTransferCount = 0;
MONITOR uint64_t KdComPortInUse = 0;
MONITOR uint64_t KdDebuggerEnabled = 0;
MONITOR uint64_t KdEnteredDebugger = 0;
MONITOR uint64_t KdEventLoggingEnabled = 0;
MONITOR uint64_t KdHvComPortInUse = 0;
MONITOR uint64_t KeDynamicPartitioningSupported = 0;
MONITOR uint64_t KeLastBranchMSR = 0;
MONITOR uint64_t KeLoaderBlock = 0;
MONITOR uint64_t KeNumberProcessors = 0;
MONITOR uint64_t KiBugCheckData = 0;
MONITOR uint64_t LpcPortObjectType = 0;
MONITOR uint64_t Mm64BitPhysicalAddress = 0;
MONITOR uint64_t MmBadPointer = 0;
MONITOR uint64_t MmHighestUserAddress = 0xFFE;
MONITOR uint64_t MmSectionObjectType = 0;
MONITOR uint64_t MmSystemRangeStart = 0x1000;
MONITOR uint64_t MmUserProbeAddress = 0xFFF;
MONITOR uint64_t NlsAnsiCodePage = 0;
MONITOR uint64_t NlsMbCodePageTag = 0;
MONITOR uint64_t NlsMbOemCodePageTag = 0;
MONITOR uint64_t NlsOemCodePage = 0;
MONITOR uint64_t NtBuildGUID = 0;
MONITOR uint64_t NtBuildLab = 0;
MONITOR uint64_t NtBuildNumber = 19044;
MONITOR uint64_t NtGlobalFlag = 0;
MONITOR uint64_t POGOBuffer = 0;
MONITOR uint64_t PsInitialSystemProcess = 70000000;
MONITOR uint64_t PsJobType = 0;
MONITOR PLDR_DATA_TABLE_ENTRY PsLoadedModuleList = 0;
MONITOR uint64_t PsLoadedModuleResource = 0x600000;
MONITOR uint64_t PsPartitionType = 0;
MONITOR _OBJECT_TYPE* PsProcessType = 0x0; //crashes here atm, need ot fix. it's a _OBJECT_TYPE*
MONITOR uint64_t PsSiloContextNonPagedType = 0;
MONITOR uint64_t PsSiloContextPagedType = 0;
MONITOR _OBJECT_TYPE* PsThreadType = 0x0;
MONITOR uint64_t PsUILanguageComitted = 0;
MONITOR uint64_t SeILSigningPolicyPtr = 0;
MONITOR uint64_t SePublicDefaultDacl = 0;
MONITOR uint64_t SeSystemDefaultDacl = 0;
MONITOR uint64_t SeSystemDefaultSd = 0;
MONITOR uint64_t SeTokenObjectType = 0;
MONITOR uint64_t TmEnlistmentObjectType = 0;
MONITOR uint64_t TmResourceManagerObjectType = 0;
MONITOR uint64_t TmTransactionManagerObjectType = 0;
MONITOR uint64_t TmTransactionObjectType = 0;
MONITOR uint64_t psMUITest = 0;

namespace ntoskrnl_export {
    void Initialize();
    void InitializeObjectType();
    void InitializePsLoadedModuleList();
    void InitializeExport();
} // namespace ntoskrnl_export
