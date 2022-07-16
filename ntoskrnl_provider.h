#pragma once
#include <cstdint>
#include <cstdio>

#include "module_layout.h"
#include "ntoskrnl_struct.h"
#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

inline _ETHREAD FakeKernelThread = { 0 };
inline _EPROCESS FakeSystemProcess = { 0 };


//Ex*

VOID* hM_AllocPoolTag(uint32_t pooltype, size_t size, ULONG tag);
VOID* hM_AllocPool(uint32_t pooltype, size_t size);
VOID* hM_AllocPool(uint32_t pooltype, size_t size);
VOID h_DeAllocPoolTag(uintptr_t ptr, ULONG tag);
VOID h_DeAllocPool(uintptr_t ptr);
VOID h_ExAcquireFastMutex(PFAST_MUTEX FastMutex);
VOID h_ExReleaseFastMutex(PFAST_MUTEX FastMutex);
void h_ExSystemTimeToLocalTime(PLARGE_INTEGER SystemTime, PLARGE_INTEGER LocalTime);
void h_ProbeForRead(void* address, size_t len, ULONG align);
void h_ProbeForWrite(void* address, size_t len, ULONG align);
_SLIST_ENTRY* h_ExpInterlockedPopEntrySList(PSLIST_HEADER SListHead);
NTSTATUS h_ExCreateCallback(void* CallbackObject, void* ObjectAttributes, bool Create, bool AllowMultipleCallbacks);
void h_ExWaitForRundownProtectionRelease(_EX_RUNDOWN_REF* RunRef);


//Mm*

PVOID h_MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName);
BOOLEAN h_MmIsAddressValid(PVOID VirutalAddress);

//Ke*

_ETHREAD* h_KeGetCurrentThread();
void h_KeInitializeEvent(
	_KEVENT* Event,
	_EVENT_TYPE Type,
	BOOLEAN    State );
bool h_KeAreAllApcsDisabled();
bool h_KeAreApcsDisabled();
LONG
NTAPI
h_KeSetEvent(IN _KEVENT* Event,
	IN LONG Increment,
	IN BOOLEAN Wait);
BOOLEAN h_KeCancelTimer(_KTIMER* Timer);

void h_KeInitializeMutex(PVOID Mutex, ULONG level);
LONG h_KeReleaseMutex(
	PVOID Mutex,
	BOOLEAN  Wait
);
UCHAR h_KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK SpinLock);
void h_KeReleaseSpinLock(PKSPIN_LOCK SpinLock, UCHAR NewIrql);
BOOLEAN h_KeSetTimer(_KTIMER* Timer, LARGE_INTEGER DueTime, _KDPC* Dpc);
NTSTATUS h_KeDelayExecutionThread(char WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval);
NTSTATUS h_KeWaitForSingleObject(PVOID Object, void* WaitReason, void* WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
ULONG_PTR h_KeIpiGenericCall(
	PVOID BroadcastFunction,
	ULONG_PTR              Context
);

//Ki*

//Rtl*
uint64_t h_RtlRandomEx(unsigned long* seed);
NTSTATUS h_RtlGetVersion(
	RTL_OSVERSIONINFOW* lpVersionInformation
);
NTSTATUS h_RtlMultiByteToUnicodeN(
	PWCH       UnicodeString,
	ULONG      MaxBytesInUnicodeString,
	PULONG     BytesInUnicodeString,
	const CHAR* MultiByteString,
	ULONG      BytesInMultiByteString
);
NTSTATUS h_RtlWriteRegistryValue(ULONG  RelativeTo, PCWSTR Path, PCWSTR ValueName, ULONG  ValueType, PVOID  ValueData, ULONG  ValueLength);
NTSTATUS h_RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
LONG h_RtlCompareString(
	const STRING* String1,
	const STRING* String2,
	BOOLEAN      CaseInSensitive
);;

void h_RtlTimeToTimeFields(__int64 Time, __int64 TimeFields);


NTSTATUS h_RtlDuplicateUnicodeString(int add_nul, const UNICODE_STRING* source, UNICODE_STRING* destination);


//Ob*
void* h_ObGetFilterVersion(void* arg);

NTSTATUS h_ObOpenObjectByPointer(
	PVOID           Object,
	ULONG           HandleAttributes,
	PVOID   PassedAccessState,
	ACCESS_MASK     DesiredAccess,
	uint64_t    ObjectType,
	uint64_t AccessMode,
	PHANDLE         Handle
);
NTSTATUS h_ObQueryNameString(
	PVOID                    Object,
	PVOID ObjectNameInfo,
	ULONG                    Length,
	PULONG                   ReturnLength
);
NTSTATUS h_ObReferenceObjectByHandle(
	HANDLE handle,
	ACCESS_MASK                DesiredAccess,
	GUID* ObjectType,
	uint64_t            AccessMode,
	PVOID* Object,
	void* HandleInformation);

NTSTATUS h_ObRegisterCallbacks(PVOID CallbackRegistration, PVOID* RegistrationHandle);
void h_ObUnRegisterCallbacks(PVOID RegistrationHandle);
uint64_t h_ObfDereferenceObject(
	PVOID obj
);
LONG_PTR h_ObfReferenceObject(PVOID Object);

//Io

NTSTATUS h_IoCreateDevice(_DRIVER_OBJECT* DriverObject,
	ULONG           DeviceExtensionSize,
	PUNICODE_STRING DeviceName,
	DEVICE_TYPE     DeviceType,
	ULONG           DeviceCharacteristics,
	BOOLEAN         Exclusive,
	_DEVICE_OBJECT** DeviceObject);
NTSTATUS h_IoCreateFileEx(
	PHANDLE                   FileHandle,
	ACCESS_MASK               DesiredAccess,
	OBJECT_ATTRIBUTES* ObjectAttributes,
	void* IoStatusBlock,
	PLARGE_INTEGER            AllocationSize,
	ULONG                     FileAttributes,
	ULONG                     ShareAccess,
	ULONG                     Disposition,
	ULONG                     CreateOptions,
	PVOID                     EaBuffer,
	ULONG                     EaLength,
	void* CreateFileType,
	PVOID                     InternalParameters,
	ULONG                     Options,
	void* DriverContext);
NTSTATUS h_IoWMIOpenBlock( //TODO
	LPCGUID Guid,
	ULONG   DesiredAccess,
	PVOID* DataBlockObject);
NTSTATUS h_IoWMIQueryAllData( //TODO
	PVOID  DataBlockObject,
	PULONG InOutBufferSize,
	PVOID  OutBuffer);


NTSTATUS h_IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName);
void h_IoDeleteDevice(_DEVICE_OBJECT*);
void* h_IoGetTopLevelIrp();

NTSTATUS h_IoQueryFileDosDeviceName(PVOID fileObject, PVOID* name_info);
void h_IoDeleteController(PVOID ControllerObject);;
void h_IofCompleteRequest(void* pirp, CHAR boost);
NTSTATUS h_IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName);


//Ps*

HANDLE h_PsGetProcessId(_EPROCESS* Process);
HANDLE h_PsGetThreadId(_ETHREAD* Thread);
HANDLE h_PsGetThreadProcessId(_ETHREAD* Thread);
HANDLE h_PsGetThreadProcess(_ETHREAD* Thread);
PVOID h_PsGetProcessWow64Process(_EPROCESS* Process);
NTSTATUS h_PsLookupThreadByThreadId(HANDLE ThreadId, PVOID* Thread);
LONGLONG h_PsGetProcessCreateTimeQuadPart(_EPROCESS* process);
_PEB* h_PsGetProcessPeb(_EPROCESS* process);
HANDLE h_PsGetProcessInheritedFromUniqueProcessId(_EPROCESS* Process);
_EPROCESS* h_PsGetCurrentProcess();
_EPROCESS* h_PsGetCurrentThreadProcess();
HANDLE h_PsGetCurrentThreadId();
HANDLE h_PsGetCurrentThreadProcessId();
NTSTATUS h_PsLookupProcessByProcessId(HANDLE    ProcessId, _EPROCESS** Process);
bool h_PsIsProtectedProcess(_EPROCESS* process);
PACCESS_TOKEN h_PsReferencePrimaryToken(_EPROCESS* Process);
NTSTATUS h_PsRemoveLoadImageNotifyRoutine(void* NotifyRoutine);
NTSTATUS h_PsSetCreateProcessNotifyRoutineEx(void* NotifyRoutine, BOOLEAN Remove);
NTSTATUS h_PsSetCreateThreadNotifyRoutine(PVOID NotifyRoutine);
NTSTATUS h_PsSetLoadImageNotifyRoutine(PVOID NotifyRoutine);
HANDLE h_PsGetCurrentProcessId();
NTSTATUS h_PsCreateSystemThread(PHANDLE ThreadHandle, ULONG DesiredAccess, void* ObjectAttributes, HANDLE ProcessHandle, void* ClientId,
	void* StartRoutine, PVOID StartContext);
NTSTATUS h_PsTerminateSystemThread(NTSTATUS exitstatus);

//Se*

NTSTATUS h_SeQueryInformationToken(
	PACCESS_TOKEN           Token,
	TOKEN_INFORMATION_CLASS TokenInformationClass,
	PVOID* TokenInformation
);


//Nt*-Zw*
NTSTATUS h_NtQuerySystemInformation(uint32_t SystemInformationClass, uintptr_t SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS h_NtCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	OBJECT_ATTRIBUTES* ObjectAttributes,
	PVOID   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
);
NTSTATUS h_NtReadFile(
	HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PVOID IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
	PULONG Key);
NTSTATUS h_NtQueryInformationFile(
	HANDLE                 FileHandle,
	PVOID       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
);
NTSTATUS h_ZwQueryValueKey(
	HANDLE                      KeyHandle,
	PUNICODE_STRING             ValueName,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	PVOID                       KeyValueInformation,
	ULONG                       Length,
	PULONG                      ResultLength
);
NTSTATUS h_ZwOpenKey(PHANDLE KeyHandle,
	ACCESS_MASK        DesiredAccess,
	OBJECT_ATTRIBUTES* ObjectAttributes);
NTSTATUS h_ZwFlushKey(PHANDLE   KeyHandle);
NTSTATUS h_ZwClose(PHANDLE  Handle);
NTSTATUS h_ZwQueryFullAttributesFile(
	OBJECT_ATTRIBUTES* ObjectAttributes,
	PFILE_NETWORK_OPEN_INFORMATION FileInformation
);
NTSTATUS h_NtQueryInformationProcess(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);


//CRT stuff

int h_vswprintf_s(wchar_t* buffer, size_t numberOfElements, const wchar_t* format, va_list argptr);
int h_swprintf_s(
	wchar_t* buffer,
	size_t sizeOfBuffer,
	const wchar_t* format,
	...
);
int h__vsnwprintf(
	wchar_t* buffer,
	size_t count,
	const wchar_t* format,
	va_list argptr
);
errno_t h_wcscpy_s(
	wchar_t* dest,
	rsize_t dest_size,
	const wchar_t* src
);


//SEH Handler

EXCEPTION_DISPOSITION __cdecl _c_exception( //EAC does CFG redirection with SEH .. the fuck?
											//The fuck indeed.
	struct _EXCEPTION_RECORD* ExceptionRecord,
	void* EstablisherFrame,
	struct _CONTEXT* ContextRecord,
	struct _DISPATCHER_CONTEXT* DispatcherContext
);

//Dbg

ULONG h_DbgPrompt(PCCH Prompt, PCH Response, ULONG Length);

inline std::unordered_map<std::string, ConstantFunctionPrototype> myConstantProvider = {
	{ "MmGetSystemRoutineAddress", { 1, h_MmGetSystemRoutineAddress }},
	{ "IoDeleteSymbolicLink", { 1, h_IoDeleteSymbolicLink } },
	{ "PsRemoveLoadImageNotifyRoutine", {1, h_PsRemoveLoadImageNotifyRoutine }},
	{ "PsSetCreateProcessNotifyRoutineEx", {2, h_PsSetCreateProcessNotifyRoutineEx }},
	{ "PsSetCreateProcessNotifyRoutine", {2, h_PsSetCreateProcessNotifyRoutineEx} },
	{ "KeAcquireSpinLockRaiseToDpc",{ 1, h_KeAcquireSpinLockRaiseToDpc }},
	{ "PsRemoveCreateThreadNotifyRoutine", {1, h_PsRemoveLoadImageNotifyRoutine} },
	{ "KeReleaseSpinLock",{ 2, h_KeReleaseSpinLock} },
	{ "ExpInterlockedPopEntrySList", {1, h_ExpInterlockedPopEntrySList} },
	{ "KeDelayExecutionThread", {3, h_KeDelayExecutionThread} },
	{ "ExWaitForRundownProtectionRelease", {1, h_ExWaitForRundownProtectionRelease} },
	{ "KeCancelTimer", {1, h_KeCancelTimer} },
	{ "KeSetEvent", {3, h_KeSetEvent} },
	{ "KeSetTimer",{ 3, h_KeSetTimer} },
	{ "ExCreateCallback", {4, h_ExCreateCallback }},
	{ "IoCreateFileEx",{ 1, h_IoCreateFileEx }},
	{ "RtlDuplicateUnicodeString", {1, h_RtlDuplicateUnicodeString }},
	{ "IoDeleteController", {1, h_IoDeleteController }},
	{ "SeQueryInformationToken", {1, h_SeQueryInformationToken }},
	{ "PsReferencePrimaryToken",{ 1, h_PsReferencePrimaryToken }},
	{ "PsIsProtectedProcess",{ 1, h_PsIsProtectedProcess }},
	{ "NtQueryInformationProcess", {1, h_NtQueryInformationProcess }},
	{ "PsGetCurrentThreadProcessId", {1, h_PsGetCurrentThreadProcessId }},
	{ "IoGetCurrentThreadProcessId", {1, h_PsGetCurrentThreadProcessId} },
	{ "PsGetCurrentThreadId", {1, h_PsGetCurrentThreadId} },
	{ "IoGetCurrentThreadId", {1, h_PsGetCurrentThreadId} },
	{ "PsGetCurrentProcess",{ 1, h_PsGetCurrentProcess }},
	{ "IoGetCurrentProcess",{ 1, h_PsGetCurrentProcess }},
	{ "PsGetProcessId", {1, h_PsGetProcessId} },
	{ "PsGetProcessWow64Process",{ 1, h_PsGetProcessWow64Process} },
	{ "PsLookupProcessByProcessId", {1, h_PsLookupProcessByProcessId} },
	{ "RtlCompareString", {1, h_RtlCompareString} },
	{ "PsGetProcessCreateTimeQuadPart", {1, h_PsGetProcessCreateTimeQuadPart} },
	{ "ObfReferenceObject", {1, h_ObfReferenceObject} },
	{ "ExAcquireFastMutex",{ 1, h_ExAcquireFastMutex }},
	{ "ExReleaseFastMutex", {1, h_ExReleaseFastMutex} },
	{ "ZwQueryFullAttributesFile", {2, h_ZwQueryFullAttributesFile} },
	{ "RtlWriteRegistryValue",{ 6, h_RtlWriteRegistryValue /*0x0 for passthrough*/,
		{ { "RelativeInfo", TINT32 }, { "Path", TWSTRING }, { "ValueName", TWSTRING }, { "ValueType", TINT32 }, { "ValueData", TBUFFER },
			{ "ValueLength", TINT32 } } }},
	{ "RtlInitUnicodeString", {2, h_RtlInitUnicodeString, { { "DestinationString", TUNICODESTRING }, { "SourceString", TUNICODESTRING } }} },
	{ "ZwOpenKey", {3, h_ZwOpenKey, { { "KeyHandle", TBUFFER }, { "DesiredAccess", TINT64 }, { "ObjectAttributes", TBUFFER }} } },
	{ "ZwFlushKey",{ 1, h_ZwFlushKey, { { "KeyHandle", TBUFFER } } }},
	{ "ZwClose", {1, h_ZwClose, { { "KeyHandle", TBUFFER } }} },
	{ "NtClose",{ 1, h_ZwClose, { { "KeyHandle", TBUFFER } } }},
	{ "ZwQuerySystemInformation",{ 4, h_NtQuerySystemInformation }},
	{ "NtQuerySystemInformation", {4, h_NtQuerySystemInformation }},
	{ "ExAllocatePoolWithTag", {3, hM_AllocPoolTag} },
	{ "ExAllocatePool", {2, hM_AllocPool} },
	{ "ExFreePoolWithTag", {2, h_DeAllocPoolTag} },
	{ "ExFreePool", {1, h_DeAllocPool} },
	{ "RtlRandomEx",{ 1, h_RtlRandomEx }},
	{ "IoCreateDevice", {7, h_IoCreateDevice} },
	{ "KeInitializeEvent",{ 3, h_KeInitializeEvent }},
	{ "RtlGetVersion", {1, h_RtlGetVersion} },
	{ "DbgPrint", {1, printf }},
	{ "__C_specific_handler",{ 1, _c_exception} },
	{ "RtlMultiByteToUnicodeN", {1, h_RtlMultiByteToUnicodeN }},
	{ "KeAreAllApcsDisabled", {1, h_KeAreAllApcsDisabled} },
	{ "KeAreApcsDisabled", {1, h_KeAreApcsDisabled }},
	{ "ZwCreateFile", {1, h_NtCreateFile} },
	{ "ZwQueryInformationFile",{ 1, h_NtQueryInformationFile} },
	{ "ZwReadFile", {1, h_NtReadFile} },
	{ "ZwQueryValueKey", {1, h_ZwQueryValueKey} },
	{ "IoWMIOpenBlock",{ 1, h_IoWMIOpenBlock} },
	{ "IoWMIQueryAllData", {1, h_IoWMIQueryAllData} },
	{ "ObfDereferenceObject", {1, h_ObfDereferenceObject }},
	{ "PsLookupThreadByThreadId", {1, h_PsLookupThreadByThreadId }},
	{ "RtlDuplicateUnicodeString", {3, h_RtlDuplicateUnicodeString }},
	{ "ExSystemTimeToLocalTime", {2, h_ExSystemTimeToLocalTime} },
	{ "ProbeForRead", { 3, h_ProbeForRead } },
	{ "ProbeForWrite", { 3, h_ProbeForWrite } },
	{ "RtlTimeToTimeFields", { 2, h_RtlTimeToTimeFields } },
	{ "KeInitializeMutex", { 2, h_KeInitializeMutex } },
	{ "KeReleaseMutex", { 2, h_KeReleaseMutex } },
	{ "KeWaitForSingleObject", { 5, h_KeWaitForSingleObject } },
	{ "PsCreateSystemThread", { 7, h_PsCreateSystemThread } },
	{ "PsTerminateSystemThread", { 1, h_PsTerminateSystemThread } },
	{ "IofCompleteRequest", { 2, h_IofCompleteRequest } },
	{ "IoCreateSymbolicLink", { 2, h_IoCreateSymbolicLink } },
	{ "IoDeleteDevice", { 1, h_IoDeleteDevice } },
	{ "IoGetTopLevelIrp", { 0, h_IoGetTopLevelIrp } },
	{ "ObReferenceObjectByHandle", { 6, h_ObReferenceObjectByHandle } },
	{ "ObRegisterCallbacks", { 3, h_ObRegisterCallbacks } },
	{ "ObUnRegisterCallbacks", { 1, h_ObUnRegisterCallbacks } },
	{ "ObGetFilterVersion", { 1, h_ObGetFilterVersion } }, // undoc func
	{ "MmIsAddressValid", { 1, h_MmIsAddressValid } },
	{ "PsSetCreateThreadNotifyRoutine", { 1, h_PsSetCreateThreadNotifyRoutine } },
	{ "PsSetLoadImageNotifyRoutine", { 1, h_PsSetLoadImageNotifyRoutine } },
	{ "PsGetCurrentProcessId", { 1, h_PsGetCurrentThreadProcessId } },
	{ "PsGetThreadId", { 1, h_PsGetThreadId } },
	{ "PsGetThreadProcessId", { 1, h_PsGetThreadProcessId } },
	{ "PsGetThreadProcess", { 1, h_PsGetThreadProcess } },
	{ "IoQueryFileDosDeviceName", { 1, h_IoQueryFileDosDeviceName } },
	{ "ObOpenObjectByPointer", { 1, h_ObOpenObjectByPointer } },
	{ "ObQueryNameString", { 1, h_ObQueryNameString } },
	{ "PsGetProcessInheritedFromUniqueProcessId", { 1, h_PsGetProcessInheritedFromUniqueProcessId } },
	{ "PsGetProcessPeb", { 1, h_PsGetProcessPeb } },
};