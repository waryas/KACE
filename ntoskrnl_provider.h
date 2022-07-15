#pragma once

#include "ntoskrnl_struct.h"

_ETHREAD FakeKernelThread = { 0 };
_EPROCESS FakeSystemProcess = { 0 };

VOID* hM_AllocPoolTag(uint32_t pooltype, size_t size, ULONG tag) { //TODO tracking of alloc

    auto ptr = malloc(size);
    // memset(ptr, 0, size);
    return ptr;
}

VOID h_DeAllocPoolTag(uintptr_t ptr, ULONG tag) {

    free((PVOID)ptr);
    return;
}

VOID h_DeAllocPool(uintptr_t ptr) {
    free((PVOID)ptr);
    return;
}

//We're lucky usermode gs:0x188 is unused

_ETHREAD* h_KeGetCurrentThread() { return (_ETHREAD*)__readgsqword(0x188); }

#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

NTSTATUS h_NtQuerySystemInformation(uint32_t SystemInformationClass, uintptr_t SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {

    auto x = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    printf("Class %08x status : %08x\n", SystemInformationClass, x);
    if (x == 0) {
        printf("Class %08x success\n", SystemInformationClass);
        if (SystemInformationClass == 0xb) { //SystemModuleInformation
            auto ptr = (char*)SystemInformation;
            //*(uint64_t*)(ptr + 0x18) = GetModuleBase("ntoskrnl.exe");
            ;
            RTL_PROCESS_MODULES* loadedmodules = (RTL_PROCESS_MODULES*)(SystemInformation);
            // __NtRoutine("randededom", castTest->NumberOfModules);
            for (int i = 0; i < loadedmodules->NumberOfModules; i++) {
                char* modulename = PathFindFileNameA((LPCSTR)loadedmodules->Modules[i].FullPathName);
                auto modulebase = GetModuleBase(modulename);
                if (modulebase) {
                    printf("Patching %s base from %llx to %llx\n", modulename, loadedmodules->Modules[i].ImageBase, modulebase);
                    loadedmodules->Modules[i].ImageBase = modulebase;
                } else { //We're gonna pass the real module to the driver
                }
            }
            printf("base of system is : %llx\n", *(uint64_t*)(ptr + 0x18));

        } else if (SystemInformationClass == 0x5a) {
            SYSTEM_BOOT_ENVIRONMENT_INFORMATION* pBootInfo = (SYSTEM_BOOT_ENVIRONMENT_INFORMATION*)SystemInformation;
            printf("%llx\n", pBootInfo);
        }
    }
    return x;
}

uint64_t h_RtlRandomEx(unsigned long* seed) {
    printf("Seed is %08x\n", *seed);
    auto ret = __NtRoutine("RtlRandomEx", seed);
    *seed = ret; //Keep behavior kinda same as Kernel equivalent in case of check
    return ret;
}

NTSTATUS h_IoCreateDevice(_DRIVER_OBJECT* DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DEVICE_TYPE DeviceType,
    ULONG DeviceCharacteristics, BOOLEAN Exclusive, _DEVICE_OBJECT** DeviceObject) {
    *DeviceObject = (_DEVICE_OBJECT*)malloc(sizeof(_DEVICE_OBJECT));
    auto realDevice = *DeviceObject;

    memset(*DeviceObject, 0, sizeof(_DEVICE_OBJECT));

    realDevice->DeviceType = DeviceType;
    realDevice->Type = 3;
    realDevice->Size = sizeof(*realDevice);
    realDevice->ReferenceCount = 1;
    realDevice->DriverObject = DriverObject;
    realDevice->NextDevice = 0;

    return 0;
}

NTSTATUS h_IoCreateFileEx(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, void* IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength,
    void* CreateFileType, PVOID InternalParameters, ULONG Options, void* DriverContext) {
    printf("Creating file : %ls\n", ObjectAttributes->ObjectName->Buffer);
    auto ret = __NtRoutine("NtCreateFile", FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        Disposition, CreateOptions, EaBuffer, EaLength);
    printf("Return : %x\n", ret);
    return ret;
}

enum _EVENT_TYPE {
    NotificationEvent = 0,
    SynchronizationEvent = 1
};

void h_KeInitializeEvent(_KEVENT* Event, _EVENT_TYPE Type, BOOLEAN State) {

    /* Initialize the Dispatcher Header */
    Event->Header.SignalState = State;
    Event->Header.WaitListHead.Blink = &Event->Header.WaitListHead;
    Event->Header.WaitListHead.Flink = &Event->Header.WaitListHead;
    Event->Header.Type = Type;
    *(WORD*)((char*)&Event->Header.Lock + 1) = 0x600; //saw this on ida, someone explain me
}

NTSTATUS h_RtlGetVersion(RTL_OSVERSIONINFOW* lpVersionInformation) {
    auto ret = __NtRoutine("RtlGetVersion", lpVersionInformation);
    printf("%d.%d\n", lpVersionInformation->dwMajorVersion, lpVersionInformation->dwMinorVersion);
    return ret;
}

EXCEPTION_DISPOSITION __cdecl _c_exception( //EAC does CFG redirection with SEH .. the fuck?
    struct _EXCEPTION_RECORD* ExceptionRecord, void* EstablisherFrame, struct _CONTEXT* ContextRecord, struct _DISPATCHER_CONTEXT* DispatcherContext) {
    return (EXCEPTION_DISPOSITION)__NtRoutine("__C_specific_handler", ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
}

NTSTATUS h_RtlMultiByteToUnicodeN(PWCH UnicodeString, ULONG MaxBytesInUnicodeString, PULONG BytesInUnicodeString, const CHAR* MultiByteString,
    ULONG BytesInMultiByteString) {
    printf("Trying to convert : %s\n", MultiByteString);
    return __NtRoutine("RtlMultiByteToUnicodeN", UnicodeString, MaxBytesInUnicodeString, BytesInUnicodeString, MultiByteString, BytesInMultiByteString);
}

bool h_KeAreAllApcsDisabled() { //Track thread IRQL ideally
    return false;
}

bool h_KeAreApcsDisabled() { return false; }

NTSTATUS h_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, PVOID IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    printf("Creating file : %ls\n", ObjectAttributes->ObjectName->Buffer);
    auto ret = __NtRoutine("NtCreateFile", FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        CreateDisposition, CreateOptions, EaBuffer, EaLength);
    printf("Return : %x\n", ret);
    return ret;
}

NTSTATUS h_NtReadFile(

    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PVOID IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
    PULONG Key

) {
    auto ret = __NtRoutine("NtReadFile", FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    return ret;
}

NTSTATUS h_NtQueryInformationFile(HANDLE FileHandle, PVOID IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass) {
    printf("QueryInformationFile with class %d\n", FileInformationClass);
    auto ret = __NtRoutine("NtQueryInformationFile", FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    return ret;
}

NTSTATUS h_ZwQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation,
    ULONG Length, PULONG ResultLength) {
    auto ret = __NtRoutine("NtQueryValueKey", KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    return ret;
}

NTSTATUS h_ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes) {
    auto ret = __NtRoutine("NtOpenKey", KeyHandle, DesiredAccess, ObjectAttributes);
    printf("Try to open %ls : %x\n", ObjectAttributes->ObjectName->Buffer, ret);
    return ret;
}

NTSTATUS h_ZwFlushKey(PHANDLE KeyHandle) {
    auto ret = __NtRoutine("NtFlushKey", KeyHandle);
    return ret;
}
NTSTATUS h_ZwClose(PHANDLE Handle) {
    auto ret = __NtRoutine("NtClose", Handle);
    return ret;
}

NTSTATUS h_RtlWriteRegistryValue(ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName, ULONG ValueType, PVOID ValueData, ULONG ValueLength) {
    printf("Writing to %ls - %ls : %x\n", Path, ValueName, *(uint64_t*)ValueData);
    auto ret = __NtRoutine("RtlWriteRegistryValue", RelativeTo, Path, ValueName, ValueType, ValueData, ValueLength);
    return ret;
}

NTSTATUS h_RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    auto ret = __NtRoutine("RtlInitUnicodeString", DestinationString, SourceString);
    return ret;
}

NTSTATUS h_ZwQueryFullAttributesFile(OBJECT_ATTRIBUTES* ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation) {

    auto ret = __NtRoutine("NtQueryFullAttributesFile", ObjectAttributes, FileInformation);
    printf("Querying information for %ls : %x\n", ObjectAttributes->ObjectName->Buffer, ret);
    return ret;
}

PVOID h_PsGetProcessWow64Process(_EPROCESS* Process) {
    printf("Requesting WoW64 for process : %llx (id : %d)\n", Process, Process->UniqueProcessId);
    return Process->WoW64Process;
}

NTSTATUS h_IoWMIOpenBlock( //TODO
    LPCGUID Guid, ULONG DesiredAccess, PVOID* DataBlockObject) {
    printf("WMI GUID : %llx-%llx-%llx-%llx with access : %08x\n", Guid->Data1, Guid->Data2, Guid->Data3, Guid->Data4, DesiredAccess);
    return STATUS_SUCCESS;
}

NTSTATUS h_IoWMIQueryAllData( //TODO
    PVOID DataBlockObject, PULONG InOutBufferSize, PVOID OutBuffer) {

    return STATUS_SUCCESS;
}
uint64_t h_ObfDereferenceObject(PVOID obj) { //TODO

    return 0;
}
NTSTATUS h_PsLookupThreadByThreadId(HANDLE ThreadId, PVOID* Thread) {
    printf("Thread ID : %llx is being investigated.\n", ThreadId);
    auto ct = h_KeGetCurrentThread();

    if (ThreadId == (HANDLE)4) {
        *Thread = (PVOID)&FakeKernelThread;
    } else {
        *Thread = 0;
        return STATUS_INVALID_PARAMETER;
    }
    return 0;
};

VOID h_ExAcquireFastMutex(PFAST_MUTEX FastMutex) {
    auto fm = &FastMutex[0];
    fm->OldIrql = 0; //PASSIVE_LEVEL
    fm->Owner = (_KTHREAD*)h_KeGetCurrentThread();
    //fm = &FastMutex[0];
    //fm->OldIrql = 0; //PASSIVE_LEVEL
    // fm->Owner = (_KTHREAD*)&FakeKernelThread;
    fm->Count--;
    return;
}

VOID h_ExReleaseFastMutex(PFAST_MUTEX FastMutex) {
    FastMutex->OldIrql = 0; //PASSIVE_LEVEL
    FastMutex->Owner = 0;
    FastMutex->Count++;
    return;
}
LONG_PTR h_ObfReferenceObject(PVOID Object) {
    //  printf("Trying to get reference for %llx\n", Object);
    if (!Object)
        return -1;
    if (Object == (PVOID)&FakeSystemProcess) {
        //printf("Increasing ref by 1\n");
        return (LONG_PTR)&FakeSystemProcess;
    } else {
        printf("Failed\n");
        printf("%llx\n", Object);
    }

    return 0;
}

LONGLONG h_PsGetProcessCreateTimeQuadPart(_EPROCESS* process) {
    printf("Trying to get creation time for %llx\n", process);
    return process->CreateTime.QuadPart;
}

LONG h_RtlCompareString(const STRING* String1, const STRING* String2, BOOLEAN CaseInSensitive) {
    printf("Comparing %s to %s\n", String1->Buffer, String2->Buffer);
    auto ret = __NtRoutine("RtlCompareString", String1, String2, CaseInSensitive);
    return ret;
};

NTSTATUS h_PsLookupProcessByProcessId(HANDLE ProcessId, _EPROCESS** Process) {

    printf("Process %llx EPROCESS being retrieved\n", ProcessId);

    if (ProcessId == (HANDLE)4) {
        *Process = &FakeSystemProcess;
    } else {
        *Process = 0;
        return 0xC000000B; //INVALID_CID
    }
    return 0;
}

HANDLE h_PsGetProcessId(_EPROCESS* Process) {

    if (!Process)
        return 0;

    return Process->UniqueProcessId;
}

_EPROCESS* h_PsGetCurrentProcess() { return (_EPROCESS*)h_KeGetCurrentThread()->Tcb.ApcState.Process; }

_EPROCESS* h_PsGetCurrentThreadProcess() { return (_EPROCESS*)h_KeGetCurrentThread()->Tcb.Process; }

HANDLE h_PsGetCurrentThreadId() { return h_KeGetCurrentThread()->Cid.UniqueThread; }

HANDLE h_PsGetCurrentThreadProcessId() { return h_KeGetCurrentThread()->Cid.UniqueProcess; }

NTSTATUS h_NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
    ULONG ProcessInformationLength, PULONG ReturnLength) {

    if (ProcessHandle == (HANDLE)-1) { //self-check

        auto ret
            = __NtRoutine("NtQueryInformationProcess", ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
        printf("ProcessInformation for handle %llx - class %0x - ret : %x\n", ProcessHandle, ProcessInformationClass, ret);
        *(DWORD*)ProcessInformation = 1; //We are critical
        return ret;
    } else {
        auto ret
            = __NtRoutine("NtQueryInformationProcess", ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
        printf("ProcessInformation for handle %llx - class %0x - ret : %x\n", ProcessHandle, ProcessInformationClass, ret);
        return ret;
    }
}
bool h_PsIsProtectedProcess(_EPROCESS* process) {
    if (process->UniqueProcessId == (PVOID)4) {
        return true;
    }
    return (process->Protection.Level & 7) != 0;
}

PACCESS_TOKEN h_PsReferencePrimaryToken(_EPROCESS* Process) {
    //Process->Token.RefCnt++;
    _EX_FAST_REF* a1 = &Process->Token;
    auto Value = a1->Value;
    signed __int64 v3;
    signed __int64 v4; // rdi
    unsigned int v5; // r8d
    unsigned __int64 v6; // rdi

    if ((a1->Value & 0xF) != 0) {
        do {
            v3 = _InterlockedCompareExchange64((volatile long long*)a1, Value - 1, Value);
            if (Value == v3)
                break;
            Value = v3;
        } while ((v3 & 0xF) != 0);
    }
    v4 = Value;
    v5 = Value & 0xF;
    v6 = v4 & 0xFFFFFFFFFFFFFFF0ui64;
    if (v5 > 1)
        a1 = (_EX_FAST_REF*)v6;

    printf("Returning Token : %llx\n", a1);
    return a1;
}

NTSTATUS h_SeQueryInformationToken(PACCESS_TOKEN Token, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID* TokenInformation) {
    //TODO NOT IMPLEMENTED
    printf("Token : %llx - Class : %08x\n", Token, TokenInformationClass);
    if (TokenInformationClass == 0x19) { //IsAppContainer
        *(DWORD*)TokenInformation = 1; //We are not a appcontainer.
    }
    return 0;
}

void h_IoDeleteController(PVOID ControllerObject) {
    _EX_FAST_REF* ref = (_EX_FAST_REF*)ControllerObject;
    //TODO This needs to dereference the object  -- Check ntoskrnl.exe code
    printf("Deleting controller : %llx\n", ControllerObject);
    return;
};

NTSTATUS h_RtlDuplicateUnicodeString(int add_nul, const UNICODE_STRING* source, UNICODE_STRING* destination) {

    auto ret = __NtRoutine("RtlDuplicateUnicodeString", add_nul, source, destination);
    printf("RtlDuplicateUnicodeString : %llx\n", ret);
    return ret;
}

typedef struct _TIME_FIELDS {
    SHORT Year;
    SHORT Month;
    SHORT Day;
    SHORT Hour;
    SHORT Minute;
    SHORT Second;
    SHORT Milliseconds;
    SHORT Weekday;
} TIME_FIELDS, *PTIME_FIELDS;

void h_ExSystemTimeToLocalTime(PLARGE_INTEGER SystemTime, PLARGE_INTEGER LocalTime) {

    //LocalTime->QuadPart = SystemTime->QuadPart - 10;
}

int h_vswprintf_s(wchar_t* buffer, size_t numberOfElements, const wchar_t* format, va_list argptr) {
    return vswprintf_s(buffer, numberOfElements, format, argptr);
}

int h_swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...) {
    //TOFIX
    return swprintf_s(buffer, sizeOfBuffer, format, L"A", L"2", L"3", L"4", L"5");
}

int h__vsnwprintf(wchar_t* buffer, size_t count, const wchar_t* format, va_list argptr) { return _vsnwprintf(buffer, count, format, argptr); }

errno_t h_wcscpy_s(wchar_t* dest, rsize_t dest_size, const wchar_t* src) { return wcscpy_s(dest, dest_size, src); }

void h_RtlTimeToTimeFields(__int64 Time, __int64 TimeFields) { __NtRoutine("RtlTimeToTimeFields", Time, TimeFields); }

BOOLEAN h_KeSetTimer(_KTIMER* Timer, LARGE_INTEGER DueTime, _KDPC* Dpc) { return 0; }

ULONG_PTR h_KeIpiGenericCall(PVOID BroadcastFunction, ULONG_PTR Context) {

    printf("BroadcastFunction: %p\n", BroadcastFunction);
    printf("Content: %p\n", Context);
    //return ((__int64(__fastcall *)(ULONG_PTR))BroadcastFunction)(Context);

    return 0;
}

_SLIST_ENTRY* h_ExpInterlockedPopEntrySList(PSLIST_HEADER SListHead) { return 0; }

NTSTATUS h_ExCreateCallback(void* CallbackObject, void* ObjectAttributes, bool Create, bool AllowMultipleCallbacks) { return STATUS_SUCCESS; }

NTSTATUS h_KeDelayExecutionThread(char WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval) { return STATUS_SUCCESS; }

ULONG h_DbgPrompt(PCCH Prompt, PCH Response, ULONG Length) { return 0; }

NTSTATUS h_IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName) {

    int TemporaryObject; // ebx
    OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+20h] [rbp-30h] BYREF
    HANDLE LinkHandle; // [rsp+60h] [rbp+10h] BYREF

    memset(&ObjectAttributes.Attributes + 1, 0, 20);
    LinkHandle = 0;
    ObjectAttributes.RootDirectory = 0;
    ObjectAttributes.ObjectName = SymbolicLinkName;
    *(uintptr_t*)&ObjectAttributes.Length = 48;
    ObjectAttributes.Attributes = 576;
    TemporaryObject = __NtRoutine("ZwOpenSymbolicLinkObject", &LinkHandle, 0x10000u, &ObjectAttributes);
    if (TemporaryObject >= 0) {
        TemporaryObject = __NtRoutine("ZwMakeTemporaryObject", LinkHandle);
        if (TemporaryObject >= 0)
            h_ZwClose(&LinkHandle);
    }

    return TemporaryObject;
}

LONG NTAPI h_KeSetEvent(IN _KEVENT* Event, IN LONG Increment, IN BOOLEAN Wait) {
    LONG PreviousState;
    _KTHREAD* Thread;

    /*
	 * Check if this is an signaled notification event without an upcoming wait.
	 * In this case, we can immediately return TRUE, without locking.
	 */
    if ((Event->Header.Type == 0) && (Event->Header.SignalState == 1) && !(Wait)) {
        /* Return the signal state (TRUE/Signalled) */
        return TRUE;
    }

    /* Save the Previous State */
    PreviousState = Event->Header.SignalState;

    /* Return the previous State */
    return PreviousState;
}

NTSTATUS h_PsRemoveLoadImageNotifyRoutine(void* NotifyRoutine) { return STATUS_SUCCESS; }

NTSTATUS h_PsSetCreateProcessNotifyRoutineEx(void* NotifyRoutine, BOOLEAN Remove) { return STATUS_SUCCESS; }

UCHAR h_KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK SpinLock) { return 0; }

void h_KeReleaseSpinLock(PKSPIN_LOCK SpinLock, UCHAR NewIrql) { }

void h_ExWaitForRundownProtectionRelease(_EX_RUNDOWN_REF* RunRef) { }

BOOLEAN h_KeCancelTimer(_KTIMER* Timer) { return true; }

uint64_t zero = 0;

PVOID h_MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName) {

    char cStr[512] = { 0 };
    wchar_t* wStr = SystemRoutineName->Buffer;
    PVOID funcptr = 0;
    wcstombs(cStr, SystemRoutineName->Buffer, 256);
    printf("%s - ", cStr);

    for (int i = 0; i < MAX_STATIC_EXPORT; i++) {
        if (!staticExportProvider[i].name)
            break;
        if (strstr(staticExportProvider[i].name, cStr)) {
            funcptr = staticExportProvider[i].ptr;
            break;
        }
    }

    if (funcptr) { //Was it static exported variable
        printf("Prototyped Variable\n");
        return funcptr;
    }

    for (int i = 0; i < 512; i++) {
        if (!myProvider[i].name)
            break;
        if (strstr(myProvider[i].name, cStr)) {
            funcptr = myProvider[i].hook;
            break;
        }
    }
    if (funcptr == nullptr) {
        funcptr = GetProcAddress(ntdll, cStr);
        if (funcptr == nullptr) {
            printf("Need prototype\n");
            exit(0);
        } else {
            printf("NTDLL.dll Function\n");
        }
    } else {
        printf("Prototyped Function\n");
    }

    return funcptr;
}

FunctionPrototype myProvider[512] = {

    { "MmGetSystemRoutineAddress", 1, h_MmGetSystemRoutineAddress },
    { "IoDeleteSymbolicLink", 1, h_IoDeleteSymbolicLink },
    { "PsRemoveLoadImageNotifyRoutine", 1, h_PsRemoveLoadImageNotifyRoutine },
    { "PsSetCreateProcessNotifyRoutineEx", 2, h_PsSetCreateProcessNotifyRoutineEx },
    { "PsSetCreateProcessNotifyRoutine", 2, h_PsSetCreateProcessNotifyRoutineEx },
    { "KeAcquireSpinLockRaiseToDpc", 1, h_KeAcquireSpinLockRaiseToDpc },
    { "PsRemoveCreateThreadNotifyRoutine", 1, h_PsRemoveLoadImageNotifyRoutine },
    { "KeReleaseSpinLock", 2, h_KeReleaseSpinLock },
    { "ExpInterlockedPopEntrySList", 1, h_ExpInterlockedPopEntrySList },
    { "KeDelayExecutionThread", 3, h_KeDelayExecutionThread },
    { "ExWaitForRundownProtectionRelease", 1, h_ExWaitForRundownProtectionRelease },
    { "KeCancelTimer", 1, h_KeCancelTimer },
    { "KeSetEvent", 3, h_KeSetEvent },
    { "KeSetTimer", 3, h_KeSetTimer },
    { "ExCreateCallback", 4, h_ExCreateCallback },
    { "IoCreateFileEx", 1, h_IoCreateFileEx },
    { "RtlDuplicateUnicodeString", 1, h_RtlDuplicateUnicodeString },
    { "IoDeleteController", 1, h_IoDeleteController },
    { "SeQueryInformationToken", 1, h_SeQueryInformationToken },
    { "PsReferencePrimaryToken", 1, h_PsReferencePrimaryToken },
    { "PsIsProtectedProcess", 1, h_PsIsProtectedProcess },
    { "NtQueryInformationProcess", 1, h_NtQueryInformationProcess },
    { "PsGetCurrentThreadProcessId", 1, h_PsGetCurrentThreadProcessId },
    { "IoGetCurrentThreadProcessId", 1, h_PsGetCurrentThreadProcessId },
    { "PsGetCurrentThreadId", 1, h_PsGetCurrentThreadId },
    { "IoGetCurrentThreadId", 1, h_PsGetCurrentThreadId },
    { "PsGetCurrentProcess", 1, h_PsGetCurrentProcess },
    { "IoGetCurrentProcess", 1, h_PsGetCurrentProcess },
    { "PsGetProcessId", 1, h_PsGetProcessId },
    { "PsGetProcessWow64Process", 1, h_PsGetProcessWow64Process },
    { "PsLookupProcessByProcessId", 1, h_PsLookupProcessByProcessId },
    { "RtlCompareString", 1, h_RtlCompareString },
    { "PsGetProcessCreateTimeQuadPart", 1, h_PsGetProcessCreateTimeQuadPart },
    { "ObfReferenceObject", 1, h_ObfReferenceObject },
    { "ExAcquireFastMutex", 1, h_ExAcquireFastMutex },
    { "ExReleaseFastMutex", 1, h_ExReleaseFastMutex },
    { "ZwQueryFullAttributesFile", 2, h_ZwQueryFullAttributesFile },
    { "RtlWriteRegistryValue", 6, h_RtlWriteRegistryValue /*0x0 for passthrough*/,
        { { "RelativeInfo", TINT32 }, { "Path", TWSTRING }, { "ValueName", TWSTRING }, { "ValueType", TINT32 }, { "ValueData", TBUFFER },
            { "ValueLength", TINT32 } } },
    { "RtlInitUnicodeString", 2, h_RtlInitUnicodeString, { { "DestinationString", TUNICODESTRING }, { "SourceString", TUNICODESTRING } } },
    { "ZwOpenKey", 3, h_ZwOpenKey, { { "KeyHandle", TBUFFER }, { "DesiredAccess", TINT64 }, { "ObjectAttributes", TBUFFER } } },
    { "ZwFlushKey", 1, h_ZwFlushKey, { { "KeyHandle", TBUFFER } } },
    { "ZwClose", 1, h_ZwClose, { { "KeyHandle", TBUFFER } } },
    { "NtClose", 1, h_ZwClose, { { "KeyHandle", TBUFFER } } },
    { "ZwQuerySystemInformation", 4, h_NtQuerySystemInformation },
    { "NtQuerySystemInformation", 4, h_NtQuerySystemInformation },
    { "ExAllocatePoolWithTag", 3, hM_AllocPoolTag },
    { "ExFreePoolWithTag", 2, h_DeAllocPoolTag },
    { "ExFreePool", 1, h_DeAllocPool },
    { "RtlRandomEx", 1, h_RtlRandomEx },
    { "IoCreateDevice", 7, h_IoCreateDevice },
    { "KeInitializeEvent", 3, h_KeInitializeEvent },
    { "RtlGetVersion", 1, h_RtlGetVersion },
    { "DbgPrint", 1, printf },
    { "__C_specific_handler", 1, _c_exception },
    { "RtlMultiByteToUnicodeN", 1, h_RtlMultiByteToUnicodeN },
    { "KeAreAllApcsDisabled", 1, h_KeAreAllApcsDisabled },
    { "KeAreApcsDisabled", 1, h_KeAreApcsDisabled },
    { "ZwCreateFile", 1, h_NtCreateFile },
    { "ZwQueryInformationFile", 1, h_NtQueryInformationFile },
    { "ZwReadFile", 1, h_NtReadFile },
    { "ZwQueryValueKey", 1, h_ZwQueryValueKey },
    { "IoWMIOpenBlock", 1, h_IoWMIOpenBlock },
    { "IoWMIQueryAllData", 1, h_IoWMIQueryAllData },
    { "ObfDereferenceObject", 1, h_ObfDereferenceObject },
    { "PsLookupThreadByThreadId", 1, h_PsLookupThreadByThreadId },
    { "RtlDuplicateUnicodeString", 3, h_RtlDuplicateUnicodeString },
    { "ExSystemTimeToLocalTime", 2, h_ExSystemTimeToLocalTime },

    //{"wcscat_s", 3 , h_ExSystemTimeToLocalTime },
    { "RtlTimeToTimeFields", 2, h_RtlTimeToTimeFields },

};