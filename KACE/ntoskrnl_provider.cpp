#include <MemoryTracker/memorytracker.h>
#include <PEMapper/pefile.h>

#include "ntoskrnl_provider.h"
#include "provider.h"
#include "static_export_provider.h"

#include "handle_manager.h"
#include "nt_define.h"
#include <Logger/Logger.h>

#include "environment.h"

using fnFreeCall = uint64_t(__fastcall*)(...);

template <typename... Params>
static NTSTATUS __NtRoutine(const char* Name, Params&&... params) {
    auto fn = (fnFreeCall)GetProcAddress(GetModuleHandleA("ntdll.dll"), Name);
    return fn(std::forward<Params>(params)...);
}

#define NtQuerySystemInformation(...) __NtRoutine("NtQuerySystemInformation", __VA_ARGS__)

struct ThreadInfo {
    LPTHREAD_START_ROUTINE routineStart;
    PVOID routineContext;
    HANDLE mutex;
    _ETHREAD* ethread;
};

void TrampolineThread(ThreadInfo* info) {
    auto newETHREAD = (_ETHREAD*)MemoryTracker::AllocateVariable(sizeof(_ETHREAD));
    __writegsqword(0x188, (DWORD64)newETHREAD); //Fake KTHREAD
    __writegsqword(0x18, (DWORD64)&FakeKPCR); //Fake _KPCR
    __writegsqword(0x20, (DWORD64)&FakeCPU); //Fake _KPRCB

    newETHREAD->Tcb.Process = (_KPROCESS*)&FakeSystemProcess; //PsGetThreadProcess
    newETHREAD->Tcb.ApcState.Process = (_KPROCESS*)&FakeSystemProcess; //PsGetCurrentProcess

    newETHREAD->Cid.UniqueProcess = (void*)4; //PsGetThreadProcessId
    newETHREAD->Cid.UniqueThread = (PVOID)GetCurrentThreadId(); //PsGetThreadId

    newETHREAD->Tcb.PreviousMode = 0; //PsGetThreadPreviousMode
    newETHREAD->Tcb.State = 1; //
    newETHREAD->Tcb.InitialStack = (void*)0x1000;
    newETHREAD->Tcb.StackBase = (void*)0x1500;
    newETHREAD->Tcb.StackLimit = (void*)0x2000;
    newETHREAD->Tcb.ThreadLock = 11;
    newETHREAD->Tcb.LockEntries = (_KLOCK_ENTRY*)22;
    char ThreadName[256] = { 0 };
    sprintf(ThreadName, "ETHREAD%04x", GetCurrentThreadId());
    MemoryTracker::TrackVariable((uintptr_t)newETHREAD, sizeof(*newETHREAD), ThreadName);
    __writeeflags(0x10286);
    Logger::Log("Thread Initialized, starting...\n");
    info->ethread = newETHREAD;
    SetEvent(info->mutex);
    auto ret = info->routineStart(info->routineContext);
    Logger::Log("End of thread with return : %llx\n", ret);
    
}
void* hM_AllocPoolTag(uint32_t pooltype, size_t size, ULONG tag) { //Ok
    auto ptr = _aligned_malloc(size, 0x1000);
    return ptr;
}

void* hM_AllocPool(uint32_t pooltype, size_t size) { //Ok
    auto ptr = _aligned_malloc(size, 0x1000);
    return ptr;
}

void h_DeAllocPoolTag(uintptr_t ptr, ULONG tag) { //Ok
    _aligned_free((PVOID)ptr);
    return;
}

void h_DeAllocPool(uintptr_t ptr) { //Ok
    _aligned_free((PVOID)ptr);
    return;
}

_ETHREAD* h_KeGetCurrentThread() {  //Ok
    return (_ETHREAD*)__readgsqword(0x188); 
}

NTSTATUS h_NtQuerySystemInformation(uint32_t SystemInformationClass, uintptr_t SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) { //Other classes

    auto x = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    Logger::Log("\tClass %08x status : %08x\n", SystemInformationClass, x);

    if (x == 0) {
        Logger::Log("\tClass %08x success\n", SystemInformationClass);
        if (SystemInformationClass == 0xb) { //SystemModuleInformation
            auto ptr = (char*)SystemInformation;
            //*(uint64_t*)(ptr + 0x18) = GetModuleBase("ntoskrnl.exe");
            ;
            RTL_PROCESS_MODULES* loadedmodules = (RTL_PROCESS_MODULES*)(SystemInformation);
            // __NtRoutine("randededom", castTest->NumberOfModules);
            for (int i = 0; i < loadedmodules->NumberOfModules; i++) {
                char* modulename = (char*)loadedmodules->Modules[i].FullPathName;
                while (strstr(modulename, "\\"))
                    modulename++;

                auto mapped_module = PEFile::FindModule(modulename);

                if (mapped_module) {
                    Logger::Log("\tPatching %s base from %llx to %llx\n", modulename, (PVOID)loadedmodules->Modules[i].ImageBase,
                        (PVOID)mapped_module->GetMappedImageBase());
                    loadedmodules->Modules[i].ImageBase = mapped_module->GetMappedImageBase();
                } else { //We're gonna pass the real module to the driver
                    //loadedmodules->Modules[i].ImageBase = 0;
                    //loadedmodules->Modules[i].LoadCount = 0;
                }
            }
            //MemoryTracker::TrackVariable((uintptr_t)ptr, SystemInformationLength, (char*)"NtQuerySystemInformation"); BAD IDEA

            Logger::Log("\tBase is : %llx\n", *(uint64_t*)(ptr + 0x18));

        } else if (SystemInformationClass == 0x4D) { //SystemModuleInformation
            auto ptr = (char*)SystemInformation;
            //*(uint64_t*)(ptr + 0x18) = GetModuleBase("ntoskrnl.exe");
            _SYSTEM_MODULE_EX* pMods = (_SYSTEM_MODULE_EX*)(SystemInformation);
            ulong SizeRead = 0;
            ulong NumModules = 0;

            while ((SizeRead + sizeof(_SYSTEM_MODULE_EX)) <= *ReturnLength) {

                char* modulename = (char*)pMods->FullDllName;
                while (strstr(modulename, "\\"))
                    modulename++;

                auto mapped_module = PEFile::FindModule(modulename);
                if (mapped_module) {
                    Logger::Log("\tPatching %s base from %llx to %llx\n", modulename, pMods->ImageBase, mapped_module->GetMappedImageBase());
                    pMods->ImageBase = (PVOID)mapped_module->GetMappedImageBase();

                } else { //We're gonna pass the real module to the driver
                    //pMods->ImageBase = (PVOID)500000;
                    //pMods->LoadCount = 0;
                }

                NumModules++;
                pMods++;
                SizeRead += sizeof(_SYSTEM_MODULE_EX);
            }

            Logger::Log("\tBase is : %llx\n", *(uint64_t*)(ptr + 0x18));

        } else if (SystemInformationClass == 0x5a) {
            SYSTEM_BOOT_ENVIRONMENT_INFORMATION* pBootInfo = (SYSTEM_BOOT_ENVIRONMENT_INFORMATION*)SystemInformation;
            Logger::Log("\tBoot info buffer : %llx\n", (void*)pBootInfo);
        }
    }

    return x;
}

uint64_t h_RtlRandomEx(unsigned long* seed) { //Ok
    Logger::Log("\tSeed is %llx\n", *seed);
    auto ret = __NtRoutine("RtlRandomEx", seed);
    *seed = ret; //Keep behavior kinda same as Kernel equivalent in case of check
    return ret;
}

NTSTATUS h_IoCreateDevice(_DRIVER_OBJECT* DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DWORD DeviceType,
    ULONG DeviceCharacteristics, BOOLEAN Exclusive, _DEVICE_OBJECT** DeviceObject) { //Ok
    *DeviceObject = (_DEVICE_OBJECT*)MemoryTracker::AllocateVariable(sizeof(_DEVICE_OBJECT));
    auto realDevice = *DeviceObject;

    memset(realDevice, 0, sizeof(_DEVICE_OBJECT));

    realDevice->DeviceType = DeviceType;
    realDevice->Type = 3;
    realDevice->Size = sizeof(*realDevice);
    realDevice->ReferenceCount = 1;
    realDevice->DriverObject = DriverObject;
    realDevice->NextDevice = 0;
    Logger::Log("\tCreated device : %ls\n", DeviceName->Buffer);

    MemoryTracker::TrackVariable((uintptr_t)realDevice, sizeof(_DEVICE_OBJECT), "MainModule.CreatedDeviceObject");


    return 0;
}

NTSTATUS h_IoCreateFileEx(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, void* IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength,
    void* CreateFileType, PVOID InternalParameters, ULONG Options, void* DriverContext) { //Todo Sandboxing


    Logger::Log("\tCreating file : %ls\n", ObjectAttributes->ObjectName->Buffer);
    if (DesiredAccess == 0xC0000000)
        DesiredAccess = 0xC0100080;
    auto ret = __NtRoutine("NtCreateFile", FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        Disposition, CreateOptions, EaBuffer, EaLength);
    Logger::Log("\tReturn : %08x\n", ret);

    return 0;
}

void h_KeInitializeEvent(_KEVENT* Event, _EVENT_TYPE Type, BOOLEAN State) { //Ok

    /* Initialize the Dispatcher Header */
    Event->Header.SignalState = State;
    InitializeListHead(&Event->Header.WaitListHead);
    Event->Header.Type = Type;
    *(WORD*)((char*)&Event->Header.Lock + 1) = 0x600; //saw this on ida, someone explain me

    auto hEvent = CreateEvent(NULL, NULL, State, NULL);
    auto hMutex = CreateMutex(NULL, false, NULL);
    HandleManager::AddMap((uintptr_t)Event, (uintptr_t)hEvent);
    MutexManager::mutex_manager.insert(std::pair((uintptr_t)Event, (uintptr_t)hMutex));

    Logger::Log("\tEvent object : %llx\n", Event);
}

NTSTATUS h_RtlGetVersion(RTL_OSVERSIONINFOW* lpVersionInformation) { //Ok
    auto ret = __NtRoutine("RtlGetVersion", lpVersionInformation);
    Logger::Log("\t%d.%d.%d\n", lpVersionInformation->dwMajorVersion, lpVersionInformation->dwMinorVersion, lpVersionInformation->dwBuildNumber);
    return ret;
}

EXCEPTION_DISPOSITION _c_exception(_EXCEPTION_RECORD* ExceptionRecord, void* EstablisherFrame, _CONTEXT* ContextRecord,
    _DISPATCHER_CONTEXT* DispatcherContext) {
    return (EXCEPTION_DISPOSITION)__NtRoutine("__C_specific_handler", ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
}

NTSTATUS h_RtlMultiByteToUnicodeN(PWCH UnicodeString, ULONG MaxBytesInUnicodeString, PULONG BytesInUnicodeString, const CHAR* MultiByteString,
    ULONG BytesInMultiByteString) {
    Logger::Log("\tTrying to convert : %s\n", MultiByteString);
    return __NtRoutine("RtlMultiByteToUnicodeN", UnicodeString, MaxBytesInUnicodeString, BytesInUnicodeString, MultiByteString, BytesInMultiByteString);
}

bool h_KeAreAllApcsDisabled() { //Todo
    return false;
}

bool h_KeAreApcsDisabled() {  //Todo
    return false; 
}

NTSTATUS h_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, PVOID IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) { //oK, sandboxing needed
    Logger::Log("\tCreating file : %ls\n", ObjectAttributes->ObjectName->Buffer);
    auto ret = __NtRoutine("NtCreateFile", FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        CreateDisposition, CreateOptions, EaBuffer, EaLength);
    Logger::Log("\tReturn : %08x\n", ret);
    return ret;
}

NTSTATUS h_NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PVOID IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key) { //Ok, more logging
    auto ret = __NtRoutine("NtReadFile", FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    return ret;
}

NTSTATUS h_NtQueryInformationFile(HANDLE FileHandle, PVOID IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass) { //ok, more logging
    Logger::Log("\tQueryInformationFile with class %08x\n", FileInformationClass);
    auto ret = __NtRoutine("NtQueryInformationFile", FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    return ret;
}

NTSTATUS h_ZwQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation,
    ULONG Length, PULONG ResultLength) { //ok, more logging
    auto ret = __NtRoutine("NtQueryValueKey", KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    return ret;
}

NTSTATUS h_ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes) {
    auto ret = __NtRoutine("NtOpenKey", KeyHandle, DesiredAccess, ObjectAttributes); //ok
    Logger::Log("\tTry to open %ls : %08x\n", ObjectAttributes->ObjectName->Buffer, ret);
    return ret;
}

NTSTATUS h_ZwFlushKey(PHANDLE KeyHandle) { //ok
    auto ret = __NtRoutine("NtFlushKey", KeyHandle);
    return ret;
}

NTSTATUS h_ZwClose(HANDLE Handle) { //ok ?
    Logger::Log("\tClosing Kernel Handle : %llx\n", Handle);
    if (!Handle)
        return STATUS_NOT_FOUND;
    __try {
        auto ret = __NtRoutine("NtClose", Handle);
        return STATUS_SUCCESS;
    }
    __except (1) {
        return STATUS_NOT_FOUND;
    }
    return STATUS_SUCCESS;
    
}

NTSTATUS h_RtlWriteRegistryValue(ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName, ULONG ValueType, PVOID ValueData, ULONG ValueLength) { //Ok
    Logger::Log("\tWriting to %ls - %ls  %llx\n", Path, ValueName, *(const PVOID*)ValueData);
    auto ret = __NtRoutine("RtlWriteRegistryValue", RelativeTo, Path, ValueName, ValueType, ValueData, ValueLength);
    return ret;
}

NTSTATUS h_RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) { //Ok
    auto ret = __NtRoutine("RtlInitUnicodeString", DestinationString, SourceString);
    return ret;
}

NTSTATUS h_ZwQueryFullAttributesFile(OBJECT_ATTRIBUTES* ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation) { //Ok

    auto ret = __NtRoutine("NtQueryFullAttributesFile", ObjectAttributes, FileInformation);
    Logger::Log("\tQuerying information for %ls : %08x\n", ObjectAttributes->ObjectName->Buffer, ret);
    return ret;
}

PVOID h_PsGetProcessWow64Process(_EPROCESS* Process) { //Ok
    Logger::Log("\tRequesting WoW64 for process : %llx (id : %llx)\n", (const PVOID)Process, Process->UniqueProcessId);
    return Process->WoW64Process;
}

NTSTATUS h_IoWMIOpenBlock(LPCGUID Guid, ULONG DesiredAccess, PVOID* DataBlockObject) { //TODO
    Logger::Log("\tWMI GUID : %llx-%llx-%llx-%llx with access : %llx\n", Guid->Data1, Guid->Data2, Guid->Data3, Guid->Data4, DesiredAccess);
    return STATUS_SUCCESS;
}

NTSTATUS h_IoWMIQueryAllData(PVOID DataBlockObject, PULONG InOutBufferSize, PVOID OutBuffer) { //TODO
    return STATUS_SUCCESS; 
} 

uint64_t h_ObfDereferenceObject(PVOID obj) { //TODO

    return 0;
}

NTSTATUS h_PsLookupThreadByThreadId(HANDLE ThreadId, PVOID* Thread) { //Ok for now
   
    auto ct = h_KeGetCurrentThread();

    if (ThreadId == ct->Cid.UniqueThread) {
        *Thread = (PVOID)ct;
        return STATUS_SUCCESS;
    } else {
        for (auto thread = Environment::ThreadManager::environment_threads.begin(); thread != Environment::ThreadManager::environment_threads.end(); thread++) {
            auto ethread = thread->second;
            if (ethread->Cid.UniqueThread == ThreadId) {
                *Thread = (PVOID)ethread;
                return STATUS_SUCCESS;
            }
        }
        *Thread = 0;
        return STATUS_INVALID_PARAMETER;
    }
    
}

HANDLE h_PsGetThreadId(_ETHREAD* Thread) { //Ok
    if (Thread)
        return Thread->Cid.UniqueThread;
    else
        return 0;
}

_PEB* h_PsGetProcessPeb(_EPROCESS* process) { //Ok for now
    return process->Peb; 
}

HANDLE h_PsGetProcessInheritedFromUniqueProcessId(_EPROCESS* Process) {  //Ok for now
    return Process->InheritedFromUniqueProcessId; 
}

NTSTATUS h_IoQueryFileDosDeviceName(PVOID fileObject, PVOID* name_info) { //Todo
    typedef struct _OBJECT_NAME_INFORMATION {
        UNICODE_STRING Name;
    } aids;
    static aids n;
    name_info = (PVOID*)&n;
    Logger::Log("%s breakpoint, needs some work.\n", __FUNCTION__);
    DebugBreak();
    return STATUS_SUCCESS;
}

NTSTATUS h_ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes, PVOID PassedAccessState, ACCESS_MASK DesiredAccess, uint64_t ObjectType, 
    uint64_t AccessMode, PHANDLE Handle) { //Todo
    Logger::Log("%s breakpoint, needs some work.\n", __FUNCTION__);
    DebugBreak();
    return STATUS_SUCCESS;
}

NTSTATUS h_ObQueryNameString(PVOID Object, PVOID ObjectNameInfo, ULONG Length, PULONG ReturnLength) { //Todo
    Logger::Log("%s breakpoint, needs some work.\n", __FUNCTION__);
    DebugBreak();
    return STATUS_SUCCESS;
}

void h_ExAcquireFastMutex(PFAST_MUTEX FastMutex) { //Ok
    auto fm = FastMutex;

    if (!MutexManager::mutex_manager.contains((uintptr_t)&fm->Gate))
        DebugBreak();

    auto hMutex = MutexManager::mutex_manager[(uintptr_t)&fm->Gate];

    auto ret = WaitForSingleObject((HANDLE)hMutex, INFINITE);

    if (ret) {
        DebugBreak();
    }

    fm->OldIrql = 0; //PASSIVE_LEVEL
    fm->Owner = (_KTHREAD*)h_KeGetCurrentThread();
    fm->Count--;


    return;
}

void h_ExReleaseFastMutex(PFAST_MUTEX FastMutex) { //Ok

    auto fm = FastMutex;

    if (!MutexManager::mutex_manager.contains((uintptr_t)&fm->Gate))
        DebugBreak();

    auto hMutex = MutexManager::mutex_manager[(uintptr_t)&fm->Gate];
    auto ret = ReleaseMutex((HANDLE)hMutex);

    if (!ret)
        DebugBreak();

    FastMutex->OldIrql = 0; //PASSIVE_LEVEL
    FastMutex->Owner = 0;
    FastMutex->Count++;
    return;
}

LONG_PTR h_ObfReferenceObject(PVOID Object) { //Ok
    //  Logger::Log("Trying to get reference for %llx", Object);
    if (!Object)
        return -1;
    return (LONG_PTR)Object;
}

LONGLONG h_PsGetProcessCreateTimeQuadPart(_EPROCESS* process) { //Ok
    Logger::Log("\t\tTrying to get creation time for %llx\n", (const void*)process);
    return process->CreateTime.QuadPart;
}

LONG h_RtlCompareString(const STRING* String1, const STRING* String2, BOOLEAN CaseInSensitive) { //Ok
    Logger::Log("\tComparing %s to %s\n", String1->Buffer, String2->Buffer);
    auto ret = __NtRoutine("RtlCompareString", String1, String2, CaseInSensitive);
    return ret;
}

NTSTATUS h_PsLookupProcessByProcessId(HANDLE ProcessId, _EPROCESS** Process) {

    Logger::Log("\tProcess %08x EPROCESS being retrieved\n", ProcessId);

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

_EPROCESS* h_PsGetCurrentProcess() {
    auto val = (_EPROCESS*)h_KeGetCurrentThread()->Tcb.ApcState.Process;
    Logger::Log("\tReturning : %llx\n", val);
    return val;
}

_EPROCESS* h_PsGetCurrentThreadProcess() { return (_EPROCESS*)h_KeGetCurrentThread()->Tcb.Process; }

HANDLE h_PsGetCurrentThreadId() { return h_KeGetCurrentThread()->Cid.UniqueThread; }

HANDLE h_PsGetCurrentThreadProcessId() { 
    //Logger::Log("About to do stuff\n");
    auto meh = h_KeGetCurrentThread()->Cid.UniqueProcess; 
    //Logger::Log("Done\n");
    return meh;
}

NTSTATUS h_NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
    ULONG ProcessInformationLength, PULONG ReturnLength) {

    if (ProcessHandle == (HANDLE)-1) { //self-check

        auto ret
            = __NtRoutine("NtQueryInformationProcess", ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
        Logger::Log("\tProcessInformation for handle %llx - class %llx - ret : %llx\n", ProcessHandle, ProcessInformationClass, ret);
        *(DWORD*)ProcessInformation = 1; //We are critical
        return ret;
    } else {
        auto ret
            = __NtRoutine("NtQueryInformationProcess", ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
        Logger::Log("\tProcessInformation for handle %llx - class %llx - ret : %llx\n", ProcessHandle, ProcessInformationClass, ret);
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

    Logger::Log("\tReturning Token : %llx\n", (const void*)a1);
    return a1;
}

TOKEN_PRIVILEGES kernelToken[31] = { 0 };

NTSTATUS h_SeQueryInformationToken(PACCESS_TOKEN Token, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID* TokenInformation) {
    //TODO NOT IMPLEMENTED
    Logger::Log("\tToken : %llx - Class : %llx\n", (const void*)Token, (int)TokenInformationClass);
    if (TokenInformationClass == 0x19) { //IsAppContainer
        *(DWORD*)TokenInformation = 0; //We are not a appcontainer.
    } else if (TokenInformationClass == 0x3) {
        return 0xC0000002;
    }
    return 0xC0000022;
}

void h_IoDeleteController(PVOID ControllerObject) {
    _EX_FAST_REF* ref = (_EX_FAST_REF*)ControllerObject;
    //TODO This needs to dereference the object  -- Check ntoskrnl.exe code
    Logger::Log("\tDeleting controller : %llx\n", static_cast<const void*>(ControllerObject));
    return;
}

NTSTATUS h_RtlDuplicateUnicodeString(int add_nul, const UNICODE_STRING* source, UNICODE_STRING* destination) {

    auto ret = __NtRoutine("RtlDuplicateUnicodeString", add_nul, source, destination);
    Logger::Log("\tRtlDuplicateUnicodeString : %ls = %llx\n", source->Buffer, ret);
    return ret;
}

void h_ExSystemTimeToLocalTime(PLARGE_INTEGER SystemTime, PLARGE_INTEGER LocalTime) { memcpy(LocalTime, SystemTime, sizeof(LARGE_INTEGER)); }

int h_vswprintf_s(wchar_t* buffer, size_t numberOfElements, const wchar_t* format, va_list argptr) {
    const wchar_t* s = format;
    int count = 0;
    uint64_t variables[16] = { 0 };
    memset(variables, 0, sizeof(variables));
    for (count = 0; s[count]; s[count] == '%' ? count++ : *s++)
        ;

    for (int i = 0; i < count; i++) {
        variables[i] = va_arg(argptr, uint64_t);
        if (variables[i] >= 0xFFFFF78000000000 && variables[i] <= 0xFFFFF78000001000) {
            variables[i] -= 0xFFFFF77F80020000;
        }
    }

    auto ret = vswprintf_s(buffer, numberOfElements, format, (va_list)variables);
    Logger::Log("\tResult : %ls\n", buffer);
    return ret;
}

int h_swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...) {
    va_list ap;
    va_start(ap, format);
    const wchar_t* s = format;
    int count = 0;
    uint64_t variables[16] = { 0 };
    memset(variables, 0, sizeof(variables));
    for (count = 0; s[count]; s[count] == '%' ? count++ : *s++)
        ;

    for (int i = 0; i < count; i++) {
        variables[i] = va_arg(ap, uint64_t);
        if (variables[i] >= 0xFFFFF78000000000 && variables[i] <= 0xFFFFF78000001000) {
            variables[i] -= 0xFFFFF77F80020000;
        }
    }
    va_end(ap);

    auto ret = vswprintf_s(buffer, sizeOfBuffer, format, (va_list)variables);

    Logger::Log("\tResult : %ls\n", buffer);
    return ret;
}

errno_t h_wcscpy_s(wchar_t* dest, rsize_t dest_size, const wchar_t* src) { return wcscpy_s(dest, dest_size, src); }

errno_t h_wcscat_s(wchar_t* strDestination, size_t numberOfElements, const wchar_t* strSource) {
    if ((uint64_t)strSource >= 0xFFFFF78000000000 && (uint64_t)strSource <= 0xFFFFF78000001000) {
        strSource = (wchar_t*)((uint64_t)strSource - 0xFFFFF77F80020000);
    }
    return wcscat_s(strDestination, numberOfElements, strSource);
}

void h_RtlTimeToTimeFields(long long Time, long long TimeFields) { __NtRoutine("RtlTimeToTimeFields", Time, TimeFields); }

BOOLEAN h_KeSetTimer(_KTIMER* Timer, LARGE_INTEGER DueTime, _KDPC* Dpc) {
    Logger::Log("\tTimer object : %llx\n", Timer);
    Logger::Log("\tDPC object : %llx\n", Dpc);

    if (Dpc)
        DebugBreak();

    memcpy(&Timer->DueTime, &DueTime, sizeof(DueTime));

    if (TimerManager::timer_manager.contains(Timer))
        TimerManager::timer_manager[Timer] = GetTickCount64();
    else
        TimerManager::timer_manager.insert(std::pair(Timer, GetTickCount64()));

    Timer->Header.SignalState = 0;

    return true;
}

void h_KeInitializeTimer(_KTIMER* Timer) { 
    
    InitializeListHead(&Timer->Header.WaitListHead); 
    Logger::Log("Timer object : %llx - Header : %llx - Timer Entry : %llx\n", Timer, &Timer->Header, &Timer->TimerListEntry);

    Timer->Header.SignalState = 0;
}

ULONG_PTR h_KeIpiGenericCall(PVOID BroadcastFunction, ULONG_PTR Context) {
    Logger::Log("\tBroadcastFunction: %llx\n", static_cast<const void*>(BroadcastFunction));
    Logger::Log("\tContent: %llx\n", reinterpret_cast<const void*>(Context));
    auto ret = static_cast<long long (*)(ULONG_PTR)>(BroadcastFunction)(Context);
    Logger::Log("\tIPI Returned : %d\n", ret);
    return ret;

    //return 0;
}

_SLIST_ENTRY* h_ExpInterlockedPopEntrySList(PSLIST_HEADER SListHead) { return 0; }

typedef struct _CALLBACK_OBJECT {
    ULONG Signature;
    KSPIN_LOCK Lock;
    LIST_ENTRY RegisteredCallbacks;
    BOOLEAN AllowMultipleCallbacks;
    UCHAR reserved[3];
} CALLBACK_OBJECT;

CALLBACK_OBJECT test = { 0 };

NTSTATUS h_ExCreateCallback(void* CallbackObject, void* ObjectAttributes, bool Create, bool AllowMultipleCallbacks) {
    OBJECT_ATTRIBUTES* oa = (OBJECT_ATTRIBUTES*)ObjectAttributes;
    _CALLBACK_OBJECT** co = (_CALLBACK_OBJECT**)CallbackObject;
    Logger::Log("\tCallback object : %llx\n", CallbackObject);
    Logger::Log("\t*Callback object : %llx\n", *co);
    Logger::Log("\tCallback name : %ls\n", oa->ObjectName->Buffer);
    *co = (_CALLBACK_OBJECT*)0x10e4e9c820;
    return 0;
}

NTSTATUS h_KeDelayExecutionThread(char WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval) {
    Sleep(Interval->QuadPart * -1 / 10000);
    return STATUS_SUCCESS;
}

ULONG h_DbgPrompt(PCCH Prompt, PCH Response, ULONG Length) {
    RaiseException(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, 0);
    return 0x0;
}

NTSTATUS h_KdChangeOption(ULONG Option, ULONG InBufferBytes, PVOID InBuffer, ULONG OutBufferBytes, PVOID OutBuffer, PULONG OutBufferNeeded) {
    return 0xC0000354; // STATUS_DEBUGGER_INACTIVE
}

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

LONG h_KeSetEvent(_KEVENT* Event, LONG Increment, BOOLEAN Wait) {
    LONG PreviousState;
    _KTHREAD* Thread;

    PreviousState = Event->Header.SignalState;
    Event->Header.SignalState = 1;

    auto hEvent = HandleManager::GetHandle((uintptr_t)Event);
    SetEvent((HANDLE)hEvent);

    if (!MutexManager::mutex_manager.contains((uintptr_t)Event))
        DebugBreak();

    auto hMutex = MutexManager::mutex_manager[(uintptr_t)Event];

    ReleaseMutex((HANDLE)hMutex);
    return PreviousState;
}

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#ifndef STATUS_INVALID_PARAMETER
    // It is now defined in Windows 2008 SDK.
    #define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#define STATUS_CONFLICTING_ADDRESSES ((NTSTATUS)0xC0000018L)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS)0xC000007AL)
#define STATUS_INVALID_IMAGE_FORMAT ((NTSTATUS)0xC000007BL)
#define STATUS_NO_TOKEN ((NTSTATUS)0xC000007CL)

#define CURRENT_PROCESS ((HANDLE)-1)
#define CURRENT_THREAD ((HANDLE)-2)
#define NtCurrentProcess CURRENT_PROCESS

NTSTATUS h_PsRemoveLoadImageNotifyRoutine(void* NotifyRoutine) { return STATUS_PROCEDURE_NOT_FOUND; }

NTSTATUS h_PsSetCreateProcessNotifyRoutineEx(void* NotifyRoutine, BOOLEAN Remove) {
    if (Remove) {
        return STATUS_INVALID_PARAMETER;
    } else {
        return STATUS_SUCCESS;
    }
}

UCHAR h_KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK SpinLock) { 
    DebugBreak();
    return (UCHAR)0x00; 
}

void h_KeReleaseSpinLock(PKSPIN_LOCK SpinLock, UCHAR NewIrql) { 
    DebugBreak();
}

void h_ExWaitForRundownProtectionRelease(_EX_RUNDOWN_REF* RunRef) {
    DebugBreak();

}

BOOLEAN h_KeCancelTimer(_KTIMER* Timer) { 
    DebugBreak();
    return true; 

}

PVOID h_MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName) {

    char cStr[512] = { 0 };
    wchar_t* wStr = SystemRoutineName->Buffer;
    PVOID funcptr = 0;
    wcstombs(cStr, SystemRoutineName->Buffer, 256);
    Logger::Log("\tRetrieving %s ptr\n", cStr);

    if (Provider::function_providers.contains(cStr))
        return Provider::function_providers[cStr];

    if (Provider::data_providers.contains(cStr))
        return Provider::data_providers[cStr];

    if (Provider::passthrough_provider_cache.contains(cStr))
        return Provider::passthrough_provider_cache[cStr];

    funcptr = GetProcAddress(LoadLibraryA("ntdll.dll"), cStr);

    if (!funcptr)
        funcptr = Provider::unimplemented_stub;

    Provider::passthrough_provider_cache.insert(std::pair(cStr, funcptr));

    return funcptr;
}

HANDLE h_PsGetThreadProcessId(_ETHREAD* Thread) {
    if (Thread) {
        Thread->Cid.UniqueProcess;
    }
    return 0;
}

HANDLE h_PsGetThreadProcess(_ETHREAD* Thread) {
    if (Thread) {
        //todo impl
        Logger::Log("\th_PsGetThreadProcess un impl!\n");
        return 0;
    }
    return 0;
}

void h_ProbeForRead(void* address, size_t len, ULONG align) { Logger::Log("\tProbeForRead -> {%llx}(len: %d) align: %d\n", address, len, align); }
void h_ProbeForWrite(void* address, size_t len, ULONG align) { Logger::Log("\tProbeForWrite -> {%llx}(len: %d) align: %d\n", address, len, align); }

int h__vsnwprintf(wchar_t* buffer, size_t count, const wchar_t* format, va_list argptr) {

    return __NtRoutine("_vsnwprintf", buffer, count, format, argptr);
}

//todo fix mutex bs
void h_KeInitializeMutex(PVOID Mutex, ULONG level) { 
    DebugBreak();

}

LONG h_KeReleaseMutex(PVOID Mutex, BOOLEAN Wait) { 
    DebugBreak();
    return 0; }


NTSTATUS h_KeWaitForSingleObject(PVOID Object, void* WaitReason, void* WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {

    auto hEvent = HandleManager::GetHandle((uintptr_t)Object);
    if (!hEvent)
        DebugBreak();
    WaitForSingleObject((HANDLE)hEvent, INFINITE);
    return STATUS_SUCCESS;
};


NTSTATUS h_KeWaitForMutexObject(PVOID Object, void* WaitReason, void* WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {

    if (!MutexManager::mutex_manager.contains((uintptr_t)Object))
        DebugBreak();

    auto hMutex = MutexManager::mutex_manager[(uintptr_t)Object];
    Logger::Log("Object : %llx - WaitReason : %llx - WaitMode : %llx - Alertable : %d, Timeout : %llx\n", Object, WaitReason, WaitMode, Alertable, Timeout);
    WaitForSingleObject((HANDLE)hMutex, INFINITE);
    return STATUS_SUCCESS;
};

ULONG h_KeQueryTimeIncrement() { 
    return 156250; //machine with no hv
}


NTSTATUS h_PsCreateSystemThread(PHANDLE ThreadHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, HANDLE ProcessHandle, void* ClientId,
    void* StartRoutine, PVOID StartContext) {
    ThreadInfo* ti = (ThreadInfo*)malloc(sizeof(ThreadInfo));
    if (!ti)
        return STATUS_NO_MEMORY;

    ti->routineContext = StartContext;
    ti->routineStart = (LPTHREAD_START_ROUTINE)StartRoutine;
    ti->mutex = CreateEvent(NULL, false, false, NULL);

    if (!ti->mutex)
        return STATUS_NO_MEMORY;

    auto ret = CreateThread(nullptr, 8192, (LPTHREAD_START_ROUTINE)TrampolineThread, ti, 0, 0);
    WaitForSingleObject(ti->mutex, INFINITE);
    *ThreadHandle = ret;
    Environment::ThreadManager::environment_threads.insert(std::pair((uintptr_t)ret, ti->ethread));

    return STATUS_SUCCESS;
}

//todo impl
NTSTATUS h_PsTerminateSystemThread(NTSTATUS exitstatus) {
    Logger::Log("\tthread boom\n");

    ExitThread(exitstatus);
}

//todo impl
void h_IofCompleteRequest(void* pirp, CHAR boost) {


}

//todo impl
NTSTATUS h_IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName) { 
    Logger::Log("\tSymbolic Link Name : %ls\n", SymbolicLinkName->Buffer);
    Logger::Log("\tDeviceName : %ls\n", DeviceName->Buffer);

    return STATUS_SUCCESS; 

}

BOOL h_IoIsSystemThread(_ETHREAD* thread) { 
    auto ret = (thread->Tcb.MiscFlags & 0x400) != 0;

    return ret;

}

void h_IoDeleteDevice(_DEVICE_OBJECT* obj) {
    
}

//todo definitely will blowup
void* h_IoGetTopLevelIrp() {
    Logger::Log("\tIoGetTopLevelIrp blows up sorry\n");
    static int irp = 0;
    return &irp;
}

NTSTATUS h_ObReferenceObjectByHandle(HANDLE handle, ACCESS_MASK DesiredAccess, _OBJECT_TYPE* ObjectType, uint64_t AccessMode, PVOID* Object,
    void* HandleInformation) {

    if (HandleInformation) {
        
    }

    if (ObjectType == PsThreadType) {
        *(PHANDLE)(Object) = &FakeKernelThread;

        if (Environment::ThreadManager::environment_threads.contains((uintptr_t)handle)) {
            *(_ETHREAD**)(Object) = Environment::ThreadManager::environment_threads[(uintptr_t)handle];
        }
        else {
            DebugBreak();
        }
    }
    else if (ObjectType == PsProcessType) {
        *(PHANDLE)(Object) = handle;
    }
    else if (!ObjectType) //Ugh
    {
        *(PHANDLE)(Object) = handle;
    }
    else {
        *(PHANDLE)(Object) = handle;
    }


    return 0;
}

//todo more logic required
NTSTATUS h_ObRegisterCallbacks(PVOID CallbackRegistration, PVOID* RegistrationHandle) {
    *RegistrationHandle = (PVOID)0xDEADBEEFCAFE;
    return STATUS_SUCCESS;
}

void h_ObUnRegisterCallbacks(PVOID RegistrationHandle) { 

}

void* h_ObGetFilterVersion(void* arg) { return 0; }

BOOLEAN h_MmIsAddressValid(PVOID VirtualAddress) {
    if ((uintptr_t)VirtualAddress <= 0x10000)
        return false;
    return true;
}

NTSTATUS h_PsSetCreateThreadNotifyRoutine(PVOID NotifyRoutine) { return STATUS_SUCCESS; }

NTSTATUS h_PsSetLoadImageNotifyRoutine(PVOID NotifyRoutine) { return STATUS_SUCCESS; }

BOOLEAN h_ExAcquireResourceExclusiveLite(_ERESOURCE* Resource, BOOLEAN Wait) {
    //Resource->OwnerEntry.OwnerThread = (uint64_t)h_KeGetCurrentThread();

    return true;
}

NTSTATUS h_KdSystemDebugControl(int Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength,
    /*KPROCESSOR_MODE*/ int PreviousMode) {
    // expected behaviour when no debugger is attached
    return 0xC0000022;
}

NTSTATUS h_ZwOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes) {

    auto ret = __NtRoutine("ZwOpenSection", SectionHandle, DesiredAccess, ObjectAttributes);
    Logger::Log("\tSection name : %ls, access : %llx, ret : %08x\n", ObjectAttributes->ObjectName->Buffer, DesiredAccess, ret);

    return ret;
}


struct RamRange {
    uint64_t base;
    uint64_t size;
};

RamRange myRam[9] = { { 0x1000, 0x57000 }, { 0x59000, 0x46000 }, { 0x100000, 0xb81b9000 }, { 0xb82f1000, 0x3b0000 }, { 0xb86a3000, 0xcc58000 },
    { 0xc6b99000, 0xfd000 }, { 0xc7ba2000, 0x5e000 }, { 0x100000000, 0x337000000 }, { 0, 0 } };

uint64_t AllocatedContiguous = 0;

RamRange* h_MmGetPhysicalMemoryRanges() { return myRam; }

PVOID h_MmAllocateContiguousMemorySpecifyCache(SIZE_T NumberOfBytes, uintptr_t LowestAcceptableAddress, uintptr_t HighestAcceptableAddress,
    uintptr_t BoundaryAddressMultiple, uint32_t CacheType) {
    Logger::Log("\tLowest : %llx - Highest : %llx - Boundary : %llx - Cache Type : %d - Size : %08x\n", LowestAcceptableAddress, HighestAcceptableAddress,
        BoundaryAddressMultiple, CacheType, NumberOfBytes);
    AllocatedContiguous = (uint64_t)hM_AllocPool(CacheType, NumberOfBytes);
    return (PVOID)AllocatedContiguous;
}


unsigned long long h_MmGetPhysicalAddress(uint64_t BaseAddress) { //To test shit

    Logger::Log("\tGetting Physical address for %llx\n", BaseAddress);
    uint64_t ret = BaseAddress/0x1000;

    if (BaseAddress == AllocatedContiguous) {
        Logger::Log("\tGetting physical for last Contiguous Allocated Memory.\n");
        ret = 0xb0000000;
    }
    if (BaseAddress == 0xf0f87c3e1000) {
        ret = 0x1ad000;
    } else if (BaseAddress == 0xfb7dbedf6000) {
        ret = 0x200000;
    } else if (BaseAddress == 0xfbfdfeff7000) {
        ret = 0x200000;
    } else if (BaseAddress == 0xfc7e3f1f8000) {
        ret = 0x200000;
    } else if (BaseAddress == 0xfcfe7f3f9000) {
        ret = 0x200000;
    }

    Logger::Log("\tReturn : %llx\n", ret);
    return ret;
}

#define ADDRESS_AND_SIZE_TO_SPAN_PAGES(_Va, _Size) ((ULONG)((((ULONG_PTR)(_Va) & (PAGE_SIZE - 1)) + (_Size) + (PAGE_SIZE - 1)) >> PAGE_SHIFT))

typedef ULONG PFN_COUNT;
typedef ULONG PFN_NUMBER, *PPFN_NUMBER;
typedef LONG SPFN_NUMBER, *PSPFN_NUMBER;

#define MDL_ALLOCATED_FIXED_SIZE 0x0008

#define BYTE_OFFSET(Va) ((ULONG)((ULONG_PTR)(Va) & (PAGE_SIZE - 1)))

#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

void MmInitializeMdl(PMDL MemoryDescriptorList, PVOID BaseVa, SIZE_T Length) {

    MemoryDescriptorList->Next = (PMDL)NULL;
    MemoryDescriptorList->Size = (USHORT)(sizeof(MDL) + (sizeof(PFN_NUMBER) * ADDRESS_AND_SIZE_TO_SPAN_PAGES(BaseVa, Length)));
    MemoryDescriptorList->MdlFlags = 0;
    MemoryDescriptorList->StartVa = (PVOID)PAGE_ALIGN(BaseVa);
    MemoryDescriptorList->ByteOffset = BYTE_OFFSET(BaseVa);
    MemoryDescriptorList->ByteCount = (ULONG)Length;
}

PMDL NTAPI h_IoAllocateMdl(IN PVOID VirtualAddress, IN ULONG Length, IN BOOLEAN SecondaryBuffer, IN BOOLEAN ChargeQuota, IN _IRP* Irp) {
    PMDL Mdl = NULL, p;
    ULONG Flags = 0;
    ULONG Size;

    if (Length & 0x80000000)
        return NULL;
    Size = ADDRESS_AND_SIZE_TO_SPAN_PAGES(VirtualAddress, Length);
    if (Size > 23) {
        /* This is bigger then our fixed-size MDLs. Calculate real size */
        Size *= sizeof(PFN_NUMBER);
        Size += sizeof(MDL);
        if (Size > 0xFFFF)
            return NULL;
    } else {
        /* Use an internal fixed MDL size */
        Size = (23 * sizeof(PFN_NUMBER)) + sizeof(MDL);
        Flags |= MDL_ALLOCATED_FIXED_SIZE;
    }

    /* Check if we don't have an mdl yet */
    if (!Mdl) {
        /* Allocate one from pool */
        Mdl = (PMDL)hM_AllocPoolTag(0, Size, 'MdlT');
        if (!Mdl)
            return NULL;
    }

    /* Initialize it */

    MmInitializeMdl(Mdl, VirtualAddress, Length);
    Mdl->MdlFlags |= Flags;

    /* Check if an IRP was given too */
    if (Irp) {
        /* Check if it came with a secondary buffer */
        if (SecondaryBuffer) {
            /* Insert the MDL at the end */
            p = Irp->MdlAddress;
            while (p->Next)
                p = p->Next;
            p->Next = Mdl;
        } else {
            /* Otherwise, insert it directly */
            Irp->MdlAddress = Mdl;
        }
    }

    /* Return the allocated mdl */
    return Mdl;
}

PVOID h_ExRegisterCallback(PVOID CallbackObject, PVOID CallbackFunction, PVOID CallbackContext) { 
    return CallbackObject; 
}

void h_KeInitializeGuardedMutex(_KGUARDED_MUTEX* Mutex) {
    Mutex->Owner = 0i64;
    Mutex->Count = 1;
    Mutex->Contention = 0;
    Logger::Log("\tMutex gate : %llx\n", &Mutex->Gate);
    Mutex->Gate.Header.Type = 1;
    Mutex->Gate.Header.Size = 6;
    Mutex->Gate.Header.Signalling = 0;
    Mutex->Gate.Header.SignalState = 0;
    Mutex->Gate.Header.WaitListHead.Flink = &Mutex->Gate.Header.WaitListHead;
    Mutex->Gate.Header.WaitListHead.Blink = &Mutex->Gate.Header.WaitListHead;
    auto hMutex = CreateMutex(NULL, false, NULL);
    MutexManager::mutex_manager.insert(std::pair((uintptr_t)&Mutex->Gate, (uintptr_t)hMutex));

    
}

NTSTATUS
h_KeWaitForMultipleObjects(ULONG Count, PVOID Object[], uint32_t WaitType, _KWAIT_REASON WaitReason, uint32_t WaitMode, BOOLEAN Alertable,
    PLARGE_INTEGER Timeout, _KWAIT_BLOCK* WaitBlockArray) {
    uintptr_t* handleList = (uintptr_t*)malloc(sizeof(uintptr_t*) * Count);
    for (int i = 0; i < Count; i++) {
        handleList[i] = (uintptr_t)HandleManager::GetHandle((uintptr_t)Object[i]);
    }
    bool waitAll = false;
    if (WaitType == 0)
        waitAll = true;
    else if (WaitType == 1)
        waitAll = false;
    else {
        DebugBreak();
    }
    DWORD WaitMS = 0;
    if (Timeout && Timeout->QuadPart < 0) {
        WaitMS = Timeout->QuadPart * -1 / 10000;
        DebugBreak();
    } else if (!Timeout) {
        WaitMS = INFINITE;

    } else {
        DebugBreak();
    }
    auto ret = WaitForMultipleObjects(Count, (const HANDLE*)handleList, waitAll, WaitMS);

    return STATUS_SUCCESS;
}

void h_KeClearEvent(_KEVENT* Event) { //This should set the Event to non-signaled

    auto hEvent = HandleManager::GetHandle((uintptr_t)Event);

    if (!hEvent)
        DebugBreak;
    
    if (!MutexManager::mutex_manager.contains((uintptr_t)Event))
        DebugBreak();

    auto hMutex = MutexManager::mutex_manager[(uintptr_t)Event];

    ReleaseMutex((HANDLE)hMutex);
    ResetEvent((HANDLE)hEvent);
    Event->Header.SignalState = 0;
    return;
}

BOOLEAN h_KeReadStateTimer(_KTIMER* timer) { 
    if (TimerManager::timer_manager.contains(timer)) {
        auto timeSet = TimerManager::timer_manager[timer];
        if ((timer->DueTime.QuadPart * -1 / 10000) + timeSet < GetTickCount64()) {
            timer->Header.SignalState = 1;
            return true;
        }
        else {
            return false;
        }
    }
    else {
        DebugBreak();
    }
    return false; 
}


NTSTATUS h_ExGetFirmwareEnvironmentVariable(
    PUNICODE_STRING VariableName,
    LPGUID          VendorGuid,
    PVOID           Value,
    PULONG          ValueLength,
    PULONG          Attributes
) {
    Logger::Log("\tReading UEFI Var : %ls - GUID : %llx-%llx-%llx-%llx\n", VariableName->Buffer, VendorGuid->Data1, VendorGuid->Data2, VendorGuid->Data3, VendorGuid->Data4);
    if (*ValueLength)
        Logger::Log("\tRequested length : %llx\n", *ValueLength);

    return STATUS_SUCCESS;
}

NTSTATUS h_ZwDeviceIoControlFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID  ApcRoutine,
     PVOID            ApcContext,
     PVOID IoStatusBlock,
    ULONG            IoControlCode,
    PVOID            InputBuffer,
   ULONG            InputBufferLength,
    PVOID            OutputBuffer,
   ULONG            OutputBufferLength
) {
    auto ret = __NtRoutine("NtDeviceIoControlFile", FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    Logger::Log("\tHandle : %llx\n", FileHandle);
    Logger::Log("\tEvent : %llx\n", Event);
    Logger::Log("\tAPC Routine : %llx\n", ApcRoutine);
    Logger::Log("\tIOCTL : %llx\n", IoControlCode);
    Logger::Log("\tLen : %d Buffer : \n\t", InputBufferLength);

    //for (int i = 0; i < InputBufferLength; i++) {
    //    Logger::Log("%01x\n", ((unsigned char*)InputBuffer)[i]);
    //}
    Logger::Log("\tRet : %llx\n", ret);

    return ret;
}

NTSTATUS h_IoGetDeviceInterfaces(
    const GUID* InterfaceClassGuid,
    _DEVICE_OBJECT* PhysicalDeviceObject,
    ULONG          Flags,
    wchar_t** SymbolicLinkList
) {
    wchar_t GUID[256] = { 0 };
    StringFromGUID2(*InterfaceClassGuid, GUID, 64);
    Logger::Log("\tInterface Class Guid : %ls\n", GUID);
    if (PhysicalDeviceObject) {
        if (PhysicalDeviceObject->DriverObject) {
            
            Logger::Log("Device driver name : %ls\t", PhysicalDeviceObject->DriverObject->DriverName.Buffer);
        }
    }
    *SymbolicLinkList = (wchar_t*)0;
    //wcscpy(*SymbolicLinkList, L"\\??\\PCI#VEN_8086&DEV_15B8&SUBSYS_86721043&REV_00#3&11583659&0&FE#{cac88484-7515-4c03-82e6-71a87abac361}");

    return STATUS_NOT_FOUND;
}

typedef struct _MM_COPY_ADDRESS {
    union {
        PVOID            VirtualAddress;
        PVOID PhysicalAddress;
    };
} MM_COPY_ADDRESS, * PMMCOPY_ADDRESS;

#define MM_COPY_MEMORY_PHYSICAL             0x1
#define MM_COPY_MEMORY_VIRTUAL              0x2
NTSTATUS h_MmCopyMemory(
    PVOID           TargetAddress,
    MM_COPY_ADDRESS SourceAddress,
    SIZE_T          NumberOfBytes,
    ULONG           Flags,
    PSIZE_T         NumberOfBytesTransferred
){
    if (Flags == MM_COPY_MEMORY_PHYSICAL) {
        *NumberOfBytesTransferred = NumberOfBytes;
    }
    else {
        Logger::Log("\tCopyying %d bytes from %llx to %llx\n", NumberOfBytes, SourceAddress, TargetAddress);
        *NumberOfBytesTransferred = NumberOfBytes;
    }
    return STATUS_SUCCESS;
}

PVOID k_MmMapIoSpaceEx(
   uint64_t PhysicalAddress,
   SIZE_T           NumberOfBytes,
   ULONG            Protect
) {
    if (PhysicalAddress == 0xfee00000)
        return 0;
    return (PVOID)(PhysicalAddress * 0x1000);
}

#define EX_SPIN_LOCK volatile LONG


__int64 __fastcall ExpWaitForSpinLockSharedAndAcquire(EX_SPIN_LOCK* a1)
{
    unsigned int v2; // esi
    unsigned __int32 v4; // edi
    bool v6; // zf
    signed __int32 v7; // eax

    v2 = 0;
    do
    {
        v4 = *a1;
        while (v4 < 0)
        {
            if ((v4 & 0x40000000) == 0)
            {
                v7 = _InterlockedCompareExchange(a1, v4 | 0x40000000, v4);
                v6 = v4 == v7;
                v4 = v7;
                if (!v6)
                    continue;
            }
            
            ++v2;
            _mm_pause();
            v4 = *a1;
        }
    } while (v4 != _InterlockedCompareExchange(a1, (v4 + 1) & 0xBFFFFFFF, v4));
    return v2;
}

__int64 __fastcall ExpWaitForSpinLockExclusiveAndAcquire(volatile LONG* a1)
{
    unsigned int v2; // ebx
    signed __int32 v4; // eax
    signed __int32 v6; // ett

    v2 = 0;
    do
    {
        v4 = *a1;
        while (v4 < 0)
        {
            if ((v4 & 0x40000000) == 0)
            {
                v6 = v4;
                v4 = _InterlockedCompareExchange(a1, v4 | 0x40000000, v4);
                if (v6 != v4)
                    continue;
            }
          
            ++v2;
            _mm_pause();
        
            v4 = *a1;
        }
    } while (_interlockedbittestandset(a1, 0x1Fu));
    return v2;
}


uint64_t  h_ExAcquireSpinLockExclusive(EX_SPIN_LOCK* SpinLock)
{

    __int64 v2; // rdx
    bool v3; // zf
    unsigned __int32 v4; // eax
    int v5; // [rsp+38h] [rbp+10h] BYREF

    v5 = 0;
    if (_interlockedbittestandset(SpinLock, 0x1Fu))
        v5 = ExpWaitForSpinLockExclusiveAndAcquire(SpinLock);
    v2 = *(unsigned int*)SpinLock;
    if ((*SpinLock & 0xBFFFFFFF) != 0x80000000)
    {
        do
        {
            if ((v2 & 0x40000000) == 0)
            {
                v4 = _InterlockedCompareExchange(SpinLock, v2 | 0x40000000, v2);
                v3 = (DWORD)v2 == v4;
                v2 = v4;
                if (!v3)
                    continue;
            }
            _mm_pause();
            v2 = *(unsigned int*)SpinLock;
        } while ((v2 & 0xBFFFFFFF) != 0x80000000);
    }
    return 0;
}

uint64_t  h_ExAcquireSpinLockShared(EX_SPIN_LOCK* SpinLock)
{

    _m_prefetchw((const void*)SpinLock);
    int v2 = *SpinLock & 0x7FFFFFFF;
    if (v2 != _InterlockedCompareExchange(SpinLock, v2 + 1, v2))
        ExpWaitForSpinLockSharedAndAcquire(SpinLock);
    return 0;
}

void  h_ExReleaseSpinLockShared(EX_SPIN_LOCK* SpinLock, uint32_t OldIrql)
{
    _InterlockedAnd(SpinLock, 0xBFFFFFFF);
    _InterlockedDecrement(SpinLock);
}

void  h_ExReleaseSpinLockExclusive(EX_SPIN_LOCK* SpinLock, uint32_t OldIrql)
{
    *SpinLock = 0;
}

void ntoskrnl_provider::Initialize() {
    Provider::AddFuncImpl("ExAcquireSpinLockShared", h_ExAcquireSpinLockShared);
    Provider::AddFuncImpl("ExReleaseSpinLockShared", h_ExReleaseSpinLockShared);
    Provider::AddFuncImpl("ExAcquireSpinLockExclusive", h_ExAcquireSpinLockExclusive);
    Provider::AddFuncImpl("ExReleaseSpinLockExclusive", h_ExReleaseSpinLockExclusive);
    Provider::AddFuncImpl("MmMapIoSpaceEx", k_MmMapIoSpaceEx);
    Provider::AddFuncImpl("MmCopyMemory", h_MmCopyMemory);
    Provider::AddFuncImpl("IoGetDeviceInterfaces", h_IoGetDeviceInterfaces);
    Provider::AddFuncImpl("ZwDeviceIoControlFile", h_ZwDeviceIoControlFile);
    Provider::AddFuncImpl("NtDeviceIoControlFile", h_ZwDeviceIoControlFile);
    Provider::AddFuncImpl("ExGetFirmwareEnvironmentVariable", h_ExGetFirmwareEnvironmentVariable);
    Provider::AddFuncImpl("KeReadStateTimer", h_KeReadStateTimer);
    Provider::AddFuncImpl("KeClearEvent", h_KeClearEvent);
    Provider::AddFuncImpl("KeWaitForMutexObject", h_KeWaitForMutexObject);
    Provider::AddFuncImpl("ExRegisterCallback", h_ExRegisterCallback);
    Provider::AddFuncImpl("KeWaitForMultipleObjects", h_KeWaitForMultipleObjects);
    Provider::AddFuncImpl("KeInitializeGuardedMutex", h_KeInitializeGuardedMutex);
    Provider::AddFuncImpl("IoAllocateMdl", h_IoAllocateMdl);
    Provider::AddFuncImpl("MmAllocateContiguousMemorySpecifyCache", h_MmAllocateContiguousMemorySpecifyCache);
    Provider::AddFuncImpl("MmGetPhysicalMemoryRanges", h_MmGetPhysicalMemoryRanges);
    Provider::AddFuncImpl("MmGetPhysicalAddress", h_MmGetPhysicalAddress);
    Provider::AddFuncImpl("_vsnwprintf", h__vsnwprintf);
    Provider::AddFuncImpl("ZwOpenSection", h_ZwOpenSection);
    Provider::AddFuncImpl("MmGetSystemRoutineAddress", h_MmGetSystemRoutineAddress);
    Provider::AddFuncImpl("IoDeleteSymbolicLink", h_IoDeleteSymbolicLink);
    Provider::AddFuncImpl("PsRemoveLoadImageNotifyRoutine", h_PsRemoveLoadImageNotifyRoutine);
    Provider::AddFuncImpl("PsSetCreateProcessNotifyRoutineEx", h_PsSetCreateProcessNotifyRoutineEx);
    Provider::AddFuncImpl("PsSetCreateProcessNotifyRoutine", h_PsSetCreateProcessNotifyRoutineEx);
    Provider::AddFuncImpl("KeAcquireSpinLockRaiseToDpc", h_KeAcquireSpinLockRaiseToDpc);
    Provider::AddFuncImpl("PsRemoveCreateThreadNotifyRoutine", h_PsRemoveLoadImageNotifyRoutine);
    Provider::AddFuncImpl("KeReleaseSpinLock", h_KeReleaseSpinLock);
    Provider::AddFuncImpl("ExpInterlockedPopEntrySList", h_ExpInterlockedPopEntrySList);
    Provider::AddFuncImpl("KeDelayExecutionThread", h_KeDelayExecutionThread);
    Provider::AddFuncImpl("ExWaitForRundownProtectionRelease", h_ExWaitForRundownProtectionRelease);
    Provider::AddFuncImpl("KeCancelTimer", h_KeCancelTimer);
    Provider::AddFuncImpl("KeSetEvent", h_KeSetEvent);
    Provider::AddFuncImpl("KeSetTimer", h_KeSetTimer);
    Provider::AddFuncImpl("ExCreateCallback", h_ExCreateCallback);
    Provider::AddFuncImpl("IoCreateFileEx", h_IoCreateFileEx);
    Provider::AddFuncImpl("RtlDuplicateUnicodeString", h_RtlDuplicateUnicodeString);
    Provider::AddFuncImpl("IoDeleteController", h_IoDeleteController);
    Provider::AddFuncImpl("SeQueryInformationToken", h_SeQueryInformationToken);
    Provider::AddFuncImpl("PsReferencePrimaryToken", h_PsReferencePrimaryToken);
    Provider::AddFuncImpl("PsIsProtectedProcess", h_PsIsProtectedProcess);
    Provider::AddFuncImpl("NtQueryInformationProcess", h_NtQueryInformationProcess);
    Provider::AddFuncImpl("PsGetCurrentThreadProcessId", h_PsGetCurrentThreadProcessId);
    Provider::AddFuncImpl("IoGetCurrentThreadProcessId", h_PsGetCurrentThreadProcessId);
    Provider::AddFuncImpl("PsGetCurrentThreadId", h_PsGetCurrentThreadId);
    Provider::AddFuncImpl("IoGetCurrentThreadId", h_PsGetCurrentThreadId);
    Provider::AddFuncImpl("PsGetCurrentProcess", h_PsGetCurrentProcess);
    Provider::AddFuncImpl("IoGetCurrentProcess", h_PsGetCurrentProcess);
    Provider::AddFuncImpl("PsGetProcessId", h_PsGetProcessId);
    Provider::AddFuncImpl("PsGetProcessWow64Process", h_PsGetProcessWow64Process);
    Provider::AddFuncImpl("PsLookupProcessByProcessId", h_PsLookupProcessByProcessId);
    Provider::AddFuncImpl("RtlCompareString", h_RtlCompareString);
    Provider::AddFuncImpl("PsGetProcessCreateTimeQuadPart", h_PsGetProcessCreateTimeQuadPart);
    Provider::AddFuncImpl("ObfReferenceObject", h_ObfReferenceObject);
    Provider::AddFuncImpl("ExAcquireFastMutex", h_ExAcquireFastMutex);
    Provider::AddFuncImpl("ExReleaseFastMutex", h_ExReleaseFastMutex);
    Provider::AddFuncImpl("ZwQueryFullAttributesFile", h_ZwQueryFullAttributesFile);
    Provider::AddFuncImpl("RtlWriteRegistryValue", h_RtlWriteRegistryValue);
    Provider::AddFuncImpl("RtlInitUnicodeString", h_RtlInitUnicodeString);
    Provider::AddFuncImpl("ZwOpenKey", h_ZwOpenKey);
    Provider::AddFuncImpl("ZwFlushKey", h_ZwFlushKey);
    Provider::AddFuncImpl("ZwClose", h_ZwClose);
    Provider::AddFuncImpl("NtClose", h_ZwClose);
    Provider::AddFuncImpl("ZwQuerySystemInformation", h_NtQuerySystemInformation);
    Provider::AddFuncImpl("NtQuerySystemInformation", h_NtQuerySystemInformation);
    Provider::AddFuncImpl("ExAllocatePoolWithTag", hM_AllocPoolTag);
    Provider::AddFuncImpl("ExAllocatePool", hM_AllocPool);
    Provider::AddFuncImpl("ExFreePoolWithTag", h_DeAllocPoolTag);
    Provider::AddFuncImpl("ExFreePool", h_DeAllocPool);
    Provider::AddFuncImpl("RtlRandomEx", h_RtlRandomEx);
    Provider::AddFuncImpl("IoCreateDevice", h_IoCreateDevice);
    Provider::AddFuncImpl("IoIsSystemThread", h_IoIsSystemThread);
    Provider::AddFuncImpl("KeInitializeEvent", h_KeInitializeEvent);
    Provider::AddFuncImpl("RtlGetVersion", h_RtlGetVersion);
    Provider::AddFuncImpl("DbgPrint", printf);
    Provider::AddFuncImpl("__C_specific_handler", _c_exception);
    Provider::AddFuncImpl("RtlMultiByteToUnicodeN", h_RtlMultiByteToUnicodeN);
    Provider::AddFuncImpl("KeAreAllApcsDisabled", h_KeAreAllApcsDisabled);
    Provider::AddFuncImpl("KeAreApcsDisabled", h_KeAreApcsDisabled);
    Provider::AddFuncImpl("ZwCreateFile", h_NtCreateFile);
    Provider::AddFuncImpl("ZwQueryInformationFile", h_NtQueryInformationFile);
    Provider::AddFuncImpl("ZwReadFile", h_NtReadFile);
    Provider::AddFuncImpl("ZwQueryValueKey", h_ZwQueryValueKey);
    Provider::AddFuncImpl("IoWMIOpenBlock", h_IoWMIOpenBlock);
    Provider::AddFuncImpl("IoWMIQueryAllData", h_IoWMIQueryAllData);
    Provider::AddFuncImpl("ObfDereferenceObject", h_ObfDereferenceObject);
    Provider::AddFuncImpl("PsLookupThreadByThreadId", h_PsLookupThreadByThreadId);
    Provider::AddFuncImpl("RtlDuplicateUnicodeString", h_RtlDuplicateUnicodeString);
    Provider::AddFuncImpl("ExSystemTimeToLocalTime", h_ExSystemTimeToLocalTime);
    Provider::AddFuncImpl("ProbeForRead", h_ProbeForRead);
    Provider::AddFuncImpl("ProbeForWrite", h_ProbeForWrite);
    Provider::AddFuncImpl("RtlTimeToTimeFields", h_RtlTimeToTimeFields);
    Provider::AddFuncImpl("KeInitializeMutex", h_KeInitializeMutex);
    Provider::AddFuncImpl("KeReleaseMutex", h_KeReleaseMutex);
    Provider::AddFuncImpl("KeWaitForSingleObject", h_KeWaitForSingleObject);
    Provider::AddFuncImpl("PsCreateSystemThread", h_PsCreateSystemThread);
    Provider::AddFuncImpl("PsTerminateSystemThread", h_PsTerminateSystemThread);
    Provider::AddFuncImpl("IofCompleteRequest", h_IofCompleteRequest);
    Provider::AddFuncImpl("IoCreateSymbolicLink", h_IoCreateSymbolicLink);
    Provider::AddFuncImpl("IoDeleteDevice", h_IoDeleteDevice);
    Provider::AddFuncImpl("IoGetTopLevelIrp", h_IoGetTopLevelIrp);
    Provider::AddFuncImpl("ObReferenceObjectByHandle", h_ObReferenceObjectByHandle);
    Provider::AddFuncImpl("ObRegisterCallbacks", h_ObRegisterCallbacks);
    Provider::AddFuncImpl("ObUnRegisterCallbacks", h_ObUnRegisterCallbacks);
    Provider::AddFuncImpl("ObGetFilterVersion", h_ObGetFilterVersion); // undoc func
    Provider::AddFuncImpl("MmIsAddressValid", h_MmIsAddressValid);
    Provider::AddFuncImpl("PsSetCreateThreadNotifyRoutine", h_PsSetCreateThreadNotifyRoutine);
    Provider::AddFuncImpl("PsSetLoadImageNotifyRoutine", h_PsSetLoadImageNotifyRoutine);
    Provider::AddFuncImpl("PsGetCurrentProcessId", h_PsGetCurrentThreadProcessId);
    Provider::AddFuncImpl("PsGetThreadId", h_PsGetThreadId);
    Provider::AddFuncImpl("PsGetThreadProcessId", h_PsGetThreadProcessId);
    Provider::AddFuncImpl("PsGetThreadProcess", h_PsGetThreadProcess);
    Provider::AddFuncImpl("IoQueryFileDosDeviceName", h_IoQueryFileDosDeviceName);
    Provider::AddFuncImpl("ObOpenObjectByPointer", h_ObOpenObjectByPointer);
    Provider::AddFuncImpl("ObQueryNameString", h_ObQueryNameString);
    Provider::AddFuncImpl("PsGetProcessInheritedFromUniqueProcessId", h_PsGetProcessInheritedFromUniqueProcessId);
    Provider::AddFuncImpl("PsGetProcessPeb", h_PsGetProcessPeb);
    Provider::AddFuncImpl("KeQueryTimeIncrement", h_KeQueryTimeIncrement);
    Provider::AddFuncImpl("ExAcquireResourceExclusiveLite", h_ExAcquireResourceExclusiveLite);
    Provider::AddFuncImpl("vswprintf_s", h_vswprintf_s);
    Provider::AddFuncImpl("swprintf_s", h_swprintf_s);
    Provider::AddFuncImpl("wcscpy_s", h_wcscpy_s);
    Provider::AddFuncImpl("wcscat_s", h_wcscat_s);
    Provider::AddFuncImpl("KeIpiGenericCall", h_KeIpiGenericCall);
    Provider::AddFuncImpl("KeInitializeTimer", h_KeInitializeTimer);
    Provider::AddFuncImpl("DbgPrompt", h_DbgPrompt);
    Provider::AddFuncImpl("KdChangeOption", h_KdChangeOption);
    Provider::AddFuncImpl("KdSystemDebugControl", h_KdSystemDebugControl);
    ntoskrnl_export::Initialize();
}