#include "libs/PEMapper/pefile.h"
#include "libs/MemoryTracker/memorytracker.h"

#include "provider.h"
#include "ntoskrnl_provider.h"

#include "spdlog/spdlog.h"


using fnFreeCall = uint64_t(__fastcall*)(...);

template <typename... Params>
static NTSTATUS __NtRoutine(const char* Name, Params&&... params) {
	auto fn = (fnFreeCall)GetProcAddress(GetModuleHandleA("ntdll.dll"), Name);
	return fn(std::forward<Params>(params)...);
}

#define NtQuerySystemInformation(...) __NtRoutine("NtQuerySystemInformation", __VA_ARGS__)


void* hM_AllocPoolTag(uint32_t pooltype, size_t size, ULONG tag) {
	return _aligned_malloc(size, 0x1000);;
}


void* hM_AllocPool(uint32_t pooltype, size_t size) {
	return _aligned_malloc(size, 0x1000);;
}

void h_DeAllocPoolTag(uintptr_t ptr, ULONG tag)
{
	_aligned_free((PVOID)ptr);
	return;
}

void h_DeAllocPool(uintptr_t ptr)
{
	_aligned_free((PVOID)ptr);
	return;
}

_ETHREAD* h_KeGetCurrentThread()
{
	return (_ETHREAD*)__readgsqword(0x188);
}

NTSTATUS h_NtQuerySystemInformation(uint32_t SystemInformationClass, uintptr_t SystemInformation,
	ULONG SystemInformationLength, PULONG ReturnLength)
{

	auto x = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	spdlog::info("Class {} status : {}", SystemInformationClass, x);
	if (x == 0) {
		spdlog::info("Class {} success", SystemInformationClass);
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

				auto modulebase = GetModuleBase(modulename);
				if (modulebase) {
					spdlog::info("Patching {} base from {:p} to {:p}", modulename, (PVOID)loadedmodules->Modules[i].ImageBase, (PVOID)modulebase);
					loadedmodules->Modules[i].ImageBase = modulebase;
				}
				else { //We're gonna pass the real module to the driver
					//loadedmodules->Modules[i].ImageBase = 0;
					//loadedmodules->Modules[i].LoadCount = 0;
				}
			}
			//MemoryTracker::TrackVariable((uintptr_t)ptr, SystemInformationLength, (char*)"NtQuerySystemInformation"); BAD IDEA

			spdlog::info("base of system is : {:p}", (PVOID) * reinterpret_cast<uint64_t*>(ptr + 0x18));

		}
		else if (SystemInformationClass == 0x4D) { //SystemModuleInformation
			auto ptr = (char*)SystemInformation;
			//*(uint64_t*)(ptr + 0x18) = GetModuleBase("ntoskrnl.exe");
			_SYSTEM_MODULE_EX* pMods = (_SYSTEM_MODULE_EX*)(SystemInformation);
			ulong SizeRead = 0;
			ulong NumModules = 0;

			while ((SizeRead + sizeof(_SYSTEM_MODULE_EX)) <= *ReturnLength)
			{


				char* modulename = (char*)pMods->FullDllName;
				while (strstr(modulename, "\\"))
					modulename++;

				auto modulebase = GetModuleBase(modulename);
				if (modulebase) {
					printf("Patching %s base from %llx to %llx\n", modulename, pMods->ImageBase, modulebase);
					pMods->ImageBase = (PVOID)modulebase;

				}
				else { //We're gonna pass the real module to the driver
					pMods->ImageBase = 0;


					pMods->LoadCount = 0;
				}

				NumModules++;
				pMods++;
				SizeRead += sizeof(_SYSTEM_MODULE_EX);
			}

			printf("base of system is : %llx\n", *(uint64_t*)(ptr + 0x18));

		}
		else if (SystemInformationClass == 0x5a) {
			SYSTEM_BOOT_ENVIRONMENT_INFORMATION* pBootInfo = (SYSTEM_BOOT_ENVIRONMENT_INFORMATION*)SystemInformation;
			spdlog::info("{}", (void*)pBootInfo);

		}

	}
	return x;
}

uint64_t h_RtlRandomEx(unsigned long* seed)
{
	spdlog::info("Seed is {}", *seed);
	auto ret = __NtRoutine("RtlRandomEx", seed);
	*seed = ret; //Keep behavior kinda same as Kernel equivalent in case of check
	return ret;
}

NTSTATUS h_IoCreateDevice(_DRIVER_OBJECT* DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName,
	DWORD DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, _DEVICE_OBJECT** DeviceObject)
{
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

NTSTATUS h_IoCreateFileEx(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes,
	void* IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition,
	ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength, void* CreateFileType, PVOID InternalParameters, ULONG Options,
	void* DriverContext)
{

	PUNICODE_STRING OLDBuffer;
	OLDBuffer = ObjectAttributes->ObjectName;
	UNICODE_STRING TempBuffer;
	TempBuffer.Buffer = (wchar_t*)malloc(512);
	memset(TempBuffer.Buffer, 0, 512);

	wcscat(TempBuffer.Buffer, L"\\??\\C:\\kace");
	wcscat(TempBuffer.Buffer, OLDBuffer->Buffer);
	TempBuffer.Buffer[12] = 'c';
	TempBuffer.Buffer[13] = 'a';
	TempBuffer.Buffer[16] = 'a';
	TempBuffer.Length = wcslen(TempBuffer.Buffer) * 2;
	TempBuffer.MaximumLength = wcslen(TempBuffer.Buffer) * 2;
	ObjectAttributes->ObjectName = &TempBuffer;
	ObjectAttributes->Attributes = 0x00000040;
	spdlog::info(L"Creating file : {}", ObjectAttributes->ObjectName->Buffer);
	if (DesiredAccess == 0xC0000000)
		DesiredAccess = 0xC0100080;
	auto ret = __NtRoutine("NtCreateFile", FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength);
	spdlog::info("Return : {}", ret);
	ObjectAttributes->ObjectName = OLDBuffer;
	free(TempBuffer.Buffer);

	return 0;
}

void h_KeInitializeEvent(_KEVENT* Event, _EVENT_TYPE Type, BOOLEAN State)
{

	/* Initialize the Dispatcher Header */
	Event->Header.SignalState = State;
	InitializeListHead(&Event->Header.WaitListHead);
	Event->Header.Type = Type;
	*(WORD*)((char*)&Event->Header.Lock + 1) = 0x600; //saw this on ida, someone explain me
	printf("Callback object : %llx", Event);
}

NTSTATUS h_RtlGetVersion(RTL_OSVERSIONINFOW* lpVersionInformation)
{
	auto ret = __NtRoutine("RtlGetVersion", lpVersionInformation);
	spdlog::info("{}.{}", lpVersionInformation->dwMajorVersion, lpVersionInformation->dwMinorVersion);
	return ret;
}

EXCEPTION_DISPOSITION _c_exception(_EXCEPTION_RECORD* ExceptionRecord, void* EstablisherFrame, _CONTEXT* ContextRecord,
	_DISPATCHER_CONTEXT* DispatcherContext)
{
	return (EXCEPTION_DISPOSITION)__NtRoutine("__C_specific_handler", ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
}

NTSTATUS h_RtlMultiByteToUnicodeN(PWCH UnicodeString, ULONG MaxBytesInUnicodeString, PULONG BytesInUnicodeString,
	const CHAR* MultiByteString, ULONG BytesInMultiByteString)
{
	spdlog::info("Trying to convert : {}", MultiByteString);
	return __NtRoutine("RtlMultiByteToUnicodeN", UnicodeString, MaxBytesInUnicodeString, BytesInUnicodeString, MultiByteString, BytesInMultiByteString);
}

bool h_KeAreAllApcsDisabled()
{ //Track thread IRQL ideally
	return false;
}

bool h_KeAreApcsDisabled()
{
	return false;
}

NTSTATUS h_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes,
	PVOID IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
	ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	spdlog::info(L"Creating file : {}", ObjectAttributes->ObjectName->Buffer);
	auto ret = __NtRoutine("NtCreateFile", FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	spdlog::info("Return : {}", ret);
	return ret;
}

NTSTATUS h_NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PVOID IoStatusBlock,
	PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	auto ret = __NtRoutine("NtReadFile", FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	return ret;
}

NTSTATUS h_NtQueryInformationFile(HANDLE FileHandle, PVOID IoStatusBlock, PVOID FileInformation, ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass)
{
	spdlog::info("QueryInformationFile with class {}", FileInformationClass);
	auto ret = __NtRoutine("NtQueryInformationFile", FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	return ret;
}

NTSTATUS h_ZwQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
	auto ret = __NtRoutine("NtQueryValueKey", KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
	return ret;
}

NTSTATUS h_ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes)
{
	auto ret = __NtRoutine("NtOpenKey", KeyHandle, DesiredAccess, ObjectAttributes);
	spdlog::info(L"Try to open {} : {}", ObjectAttributes->ObjectName->Buffer, ret);
	return ret;
}

NTSTATUS h_ZwFlushKey(PHANDLE KeyHandle)
{
	auto ret = __NtRoutine("NtFlushKey", KeyHandle);
	return ret;
}

NTSTATUS h_ZwClose(PHANDLE Handle)
{
	auto ret = __NtRoutine("NtClose", Handle);
	return ret;
}

NTSTATUS h_RtlWriteRegistryValue(ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName, ULONG ValueType, PVOID ValueData,
	ULONG ValueLength)
{
	spdlog::info(L"Writing to {} - {}  {:p}", Path, ValueName, *(const PVOID*)ValueData);
	auto ret = __NtRoutine("RtlWriteRegistryValue", RelativeTo, Path, ValueName, ValueType, ValueData, ValueLength);
	return ret;
}

NTSTATUS h_RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
	auto ret = __NtRoutine("RtlInitUnicodeString", DestinationString, SourceString);
	return ret;
}

NTSTATUS h_ZwQueryFullAttributesFile(OBJECT_ATTRIBUTES* ObjectAttributes,
	PFILE_NETWORK_OPEN_INFORMATION FileInformation)
{

	auto ret = __NtRoutine("NtQueryFullAttributesFile", ObjectAttributes, FileInformation);
	spdlog::info(L"Querying information for {} : {}", ObjectAttributes->ObjectName->Buffer, ret);
	return ret;
}

PVOID h_PsGetProcessWow64Process(_EPROCESS* Process)
{
	spdlog::info("Requesting WoW64 for process : {} (id : {})", (const PVOID)Process, Process->UniqueProcessId);
	return Process->WoW64Process;
}

NTSTATUS h_IoWMIOpenBlock(LPCGUID Guid, ULONG DesiredAccess, PVOID* DataBlockObject)
{
	//pdlog::info("WMI GUID : {}-{}-{}-{} with access : {}", Guid->Data1, Guid->Data2, Guid->Data3, Guid->Data4, DesiredAccess);
	return STATUS_SUCCESS;
}

NTSTATUS h_IoWMIQueryAllData(PVOID DataBlockObject, PULONG InOutBufferSize, PVOID OutBuffer)
{

	return STATUS_SUCCESS;
}

uint64_t h_ObfDereferenceObject(PVOID obj)
{ //TODO

	return 0;
}

NTSTATUS h_PsLookupThreadByThreadId(HANDLE ThreadId, PVOID* Thread)
{
	spdlog::info("Thread ID : {} is being investigated.", reinterpret_cast<long long>(ThreadId));
	auto ct = h_KeGetCurrentThread();

	if (ThreadId == (HANDLE)4) {
		*Thread = (PVOID)&FakeKernelThread;
	}
	else {
		*Thread = 0;
		return STATUS_INVALID_PARAMETER;
	}
	return 0;
}

HANDLE h_PsGetThreadId(_ETHREAD* Thread) {
	if (Thread)
		return Thread->Cid.UniqueThread;
	else
		return 0;
}

_PEB* h_PsGetProcessPeb(_EPROCESS* process) {
	return process->Peb;
}

HANDLE h_PsGetProcessInheritedFromUniqueProcessId(_EPROCESS* Process) {
	return Process->InheritedFromUniqueProcessId;
}


NTSTATUS h_IoQueryFileDosDeviceName(PVOID fileObject, PVOID* name_info) {
	typedef struct _OBJECT_NAME_INFORMATION {
		UNICODE_STRING Name;
	} aids;
	static aids n;
	name_info = (PVOID*)&n;

	return STATUS_SUCCESS;
}

NTSTATUS h_ObOpenObjectByPointer(
	PVOID           Object,
	ULONG           HandleAttributes,
	PVOID   PassedAccessState,
	ACCESS_MASK     DesiredAccess,
	uint64_t    ObjectType,
	uint64_t AccessMode,
	PHANDLE         Handle
) {
	return STATUS_SUCCESS;
}


NTSTATUS h_ObQueryNameString(PVOID Object, PVOID ObjectNameInfo, ULONG Length, PULONG ReturnLength) {
	spdlog::warn("Unimplemented function call detected");
	return STATUS_SUCCESS;
}


void h_ExAcquireFastMutex(PFAST_MUTEX FastMutex)
{
	auto fm = &FastMutex[0];
	fm->OldIrql = 0; //PASSIVE_LEVEL
	fm->Owner = (_KTHREAD*)h_KeGetCurrentThread();
	//fm = &FastMutex[0];
	//fm->OldIrql = 0; //PASSIVE_LEVEL
	// fm->Owner = (_KTHREAD*)&FakeKernelThread;
	fm->Count--;
	return;
}

void h_ExReleaseFastMutex(PFAST_MUTEX FastMutex)
{
	FastMutex->OldIrql = 0; //PASSIVE_LEVEL
	FastMutex->Owner = 0;
	FastMutex->Count++;
	return;
}

LONG_PTR h_ObfReferenceObject(PVOID Object)
{
	//  spdlog::info("Trying to get reference for %llx", Object);
	if (!Object)
		return -1;
	if (Object == (PVOID)&FakeSystemProcess) {
		spdlog::info("Increasing ref by 1");
		return (LONG_PTR)&FakeSystemProcess;
	}
	else {
		spdlog::info("Failed");
		spdlog::info("{:p}", Object);
	}

	return 0;
}

LONGLONG h_PsGetProcessCreateTimeQuadPart(_EPROCESS* process)
{
	spdlog::info("\t\tTrying to get creation time for {:p}", (const void*)process);
	return process->CreateTime.QuadPart;
}

LONG h_RtlCompareString(const STRING* String1, const STRING* String2, BOOLEAN CaseInSensitive)
{
	spdlog::info("\t\tComparing {} to {}", String1->Buffer, String2->Buffer);
	auto ret = __NtRoutine("RtlCompareString", String1, String2, CaseInSensitive);
	return ret;
}

NTSTATUS h_PsLookupProcessByProcessId(HANDLE ProcessId, _EPROCESS** Process)
{

	spdlog::info("\t\tProcess {} EPROCESS being retrieved", ProcessId);

	if (ProcessId == (HANDLE)4) {
		*Process = &FakeSystemProcess;
	}
	else {
		*Process = 0;
		return 0xC000000B; //INVALID_CID
	}
	return 0;
}

HANDLE h_PsGetProcessId(_EPROCESS* Process)
{

	if (!Process)
		return 0;

	return Process->UniqueProcessId;
}

_EPROCESS* h_PsGetCurrentProcess()
{
	return (_EPROCESS*)h_KeGetCurrentThread()->Tcb.ApcState.Process;
}

_EPROCESS* h_PsGetCurrentThreadProcess()
{
	return (_EPROCESS*)h_KeGetCurrentThread()->Tcb.Process;
}

HANDLE h_PsGetCurrentThreadId()
{
	return h_KeGetCurrentThread()->Cid.UniqueThread;
}

HANDLE h_PsGetCurrentThreadProcessId()
{
	return h_KeGetCurrentThread()->Cid.UniqueProcess;
}

NTSTATUS h_NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{

	if (ProcessHandle == (HANDLE)-1) { //self-check


		auto ret = __NtRoutine("NtQueryInformationProcess", ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		spdlog::info("ProcessInformation for handle {} - class {} - ret : {}", ProcessHandle, ProcessInformationClass, ret);
		*(DWORD*)ProcessInformation = 1; //We are critical
		return ret;
	}
	else {
		auto ret = __NtRoutine("NtQueryInformationProcess", ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		spdlog::info("ProcessInformation for handle {} - class {} - ret : {}", ProcessHandle, ProcessInformationClass, ret);
		return ret;
	}

}

bool h_PsIsProtectedProcess(_EPROCESS* process)
{
	if (process->UniqueProcessId == (PVOID)4) {
		return true;
	}
	return (process->Protection.Level & 7) != 0;
}

PACCESS_TOKEN h_PsReferencePrimaryToken(_EPROCESS* Process)
{
	//Process->Token.RefCnt++;
	_EX_FAST_REF* a1 = &Process->Token;
	auto Value = a1->Value;
	signed __int64 v3;
	signed __int64 v4; // rdi
	unsigned int v5; // r8d
	unsigned __int64 v6; // rdi

	if ((a1->Value & 0xF) != 0)
	{
		do
		{
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

	spdlog::info("Returning Token : {:p}", (const void*)a1);
	return a1;
}

TOKEN_PRIVILEGES kernelToken[31] = { 0 };

NTSTATUS h_SeQueryInformationToken(PACCESS_TOKEN Token, TOKEN_INFORMATION_CLASS TokenInformationClass,
	PVOID* TokenInformation)
{
	//TODO NOT IMPLEMENTED
	spdlog::info("Token : {:p} - Class : {}", (const void*)Token, (int)TokenInformationClass);
	if (TokenInformationClass == 0x19) { //IsAppContainer
		*(DWORD*)TokenInformation = 0; //We are not a appcontainer.
	}
	else if (TokenInformationClass == 0x3) {
		return 0xC0000002;
	}
	return 0xC0000022;
}

void h_IoDeleteController(PVOID ControllerObject)
{
	_EX_FAST_REF* ref = (_EX_FAST_REF*)ControllerObject;
	//TODO This needs to dereference the object  -- Check ntoskrnl.exe code
	spdlog::info("Deleting controller : {:p}", static_cast<const void*>(ControllerObject));
	return;
}

NTSTATUS h_RtlDuplicateUnicodeString(int add_nul, const UNICODE_STRING* source, UNICODE_STRING* destination)
{

	auto ret = __NtRoutine("RtlDuplicateUnicodeString", add_nul, source, destination);
	spdlog::info("RtlDuplicateUnicodeString : {}", ret);
	return ret;
}

void h_ExSystemTimeToLocalTime(PLARGE_INTEGER SystemTime, PLARGE_INTEGER LocalTime)
{
	memcpy(LocalTime, SystemTime, sizeof(LARGE_INTEGER));
}

int h_vswprintf_s(wchar_t* buffer, size_t numberOfElements, const wchar_t* format, va_list argptr)
{
	const wchar_t* s = format;
	int count = 0;
	uint64_t variables[16] = { 0 };
	memset(variables, 0, sizeof(variables));
	for (count = 0; s[count]; s[count] == '%' ? count++ : *s++);

	for (int i = 0; i < count; i++) {
		variables[i] = va_arg(argptr, uint64_t);
		if (variables[i] >= 0xFFFFF78000000000 && variables[i] <= 0xFFFFF78000001000) {
			variables[i] -= 0xFFFFF77F80020000;
		}
	}


	auto ret = vswprintf_s(buffer, numberOfElements, format, (va_list)variables);
	spdlog::info(buffer);
	return ret;
}


int h_swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...)
{
	va_list ap;
	va_start(ap, format);
	const wchar_t* s = format;
	int count = 0;
	uint64_t variables[16] = { 0 };
	memset(variables, 0, sizeof(variables));
	for (count = 0; s[count]; s[count] == '%' ? count++ : *s++);

	for (int i = 0; i < count; i++) {
		variables[i] = va_arg(ap, uint64_t);
		if (variables[i] >= 0xFFFFF78000000000 && variables[i] <= 0xFFFFF78000001000) {
			variables[i] -= 0xFFFFF77F80020000;
		}
	}
	va_end(ap);

	auto ret = vswprintf_s(buffer, sizeOfBuffer, format, (va_list)variables);


	spdlog::info(buffer);
	return ret;
}


errno_t h_wcscpy_s(wchar_t* dest, rsize_t dest_size, const wchar_t* src)
{
	return wcscpy_s(dest, dest_size, src);
}

errno_t h_wcscat_s(
	wchar_t* strDestination,
	size_t numberOfElements,
	const wchar_t* strSource
) {
	if ((uint64_t)strSource >= 0xFFFFF78000000000 && (uint64_t)strSource <= 0xFFFFF78000001000) {
		strSource = (wchar_t*)((uint64_t)strSource - 0xFFFFF77F80020000);
	}
	return wcscat_s(strDestination, numberOfElements, strSource);

}

void h_RtlTimeToTimeFields(long long Time, long long TimeFields)
{

	__NtRoutine("RtlTimeToTimeFields", Time, TimeFields);
}

BOOLEAN h_KeSetTimer(_KTIMER* Timer, LARGE_INTEGER DueTime, _KDPC* Dpc)
{
	printf("Timer object : %llx", Timer);
	printf("DPC object : %llx", Dpc);
	memcpy(&Timer->DueTime, &DueTime, sizeof(DueTime));
	return true;
}

void h_KeInitializeTimer(_KTIMER* Timer) {
	InitializeListHead(&Timer->TimerListEntry);
}
ULONG_PTR h_KeIpiGenericCall(PVOID BroadcastFunction, ULONG_PTR Context)
{
	spdlog::info("BroadcastFunction: {:p}", static_cast<const void*>(BroadcastFunction));
	spdlog::info("Content: {:p}", reinterpret_cast<const void*>(Context));
	auto ret = static_cast<long long(*)(ULONG_PTR)>(BroadcastFunction)(Context);
	spdlog::info("IPI Returned : {}", ret);
	return ret;

	//return 0;
}

_SLIST_ENTRY* h_ExpInterlockedPopEntrySList(PSLIST_HEADER SListHead)
{
	return 0;
}

typedef struct _CALLBACK_OBJECT
{
	ULONG Signature;
	KSPIN_LOCK Lock;
	LIST_ENTRY RegisteredCallbacks;
	BOOLEAN AllowMultipleCallbacks;
	UCHAR reserved[3];
} CALLBACK_OBJECT;

CALLBACK_OBJECT test = { 0 };

NTSTATUS h_ExCreateCallback(void* CallbackObject, void* ObjectAttributes, bool Create, bool AllowMultipleCallbacks)
{
	OBJECT_ATTRIBUTES* oa = (OBJECT_ATTRIBUTES*)ObjectAttributes;
	_CALLBACK_OBJECT** co = (_CALLBACK_OBJECT**)CallbackObject;
	printf("Callback object : %llx", CallbackObject);
	printf("*Callback object : %llx", *co);
	*co = (_CALLBACK_OBJECT*)0x10e4e9c820;
	return 0;
}

NTSTATUS h_KeDelayExecutionThread(char WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval)
{

	return STATUS_SUCCESS;
}

ULONG h_DbgPrompt(PCCH Prompt, PCH Response, ULONG Length)
{
	uint64_t a = (uint64_t)h_DbgPrompt >> 60 << 32 / h_KeDelayExecutionThread(0, 0, 0);
	printf("%d", a);
	strcpy(Response, "Your mom\n");
	return 0x3000;
}

NTSTATUS h_KdChangeOption(
	ULONG Option,
	ULONG     InBufferBytes,
	PVOID     InBuffer,
	ULONG     OutBufferBytes,
	PVOID     OutBuffer,
	PULONG    OutBufferNeeded
) {
	return 0xC0000354; // STATUS_DEBUGGER_INACTIVE
}

NTSTATUS h_IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName)
{

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
	if (TemporaryObject >= 0)
	{
		TemporaryObject = __NtRoutine("ZwMakeTemporaryObject", LinkHandle);
		if (TemporaryObject >= 0)
			h_ZwClose(&LinkHandle);
	}

	return TemporaryObject;
}

LONG h_KeSetEvent(_KEVENT* Event, LONG Increment, BOOLEAN Wait)
{
	LONG PreviousState;
	_KTHREAD* Thread;


	/*
	 * Check if this is an signaled notification event without an upcoming wait.
	 * In this case, we can immediately return TRUE, without locking.
	 */
	if ((Event->Header.Type == 0) &&
		(Event->Header.SignalState == 1) &&
		!(Wait))
	{
		/* Return the signal state (TRUE/Signalled) */
		return TRUE;
	}

	/* Save the Previous State */
	PreviousState = Event->Header.SignalState;

	/* Return the previous State */
	return PreviousState;
}

#define STATUS_SUCCESS                ((NTSTATUS)0x00000000L)
#define STATUS_BUFFER_OVERFLOW        ((NTSTATUS)0x80000005L)
#define STATUS_UNSUCCESSFUL           ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED        ((NTSTATUS)0xC0000002L)
#define STATUS_INFO_LENGTH_MISMATCH   ((NTSTATUS)0xC0000004L)
#ifndef STATUS_INVALID_PARAMETER
// It is now defined in Windows 2008 SDK.
#define STATUS_INVALID_PARAMETER      ((NTSTATUS)0xC000000DL)
#endif
#define STATUS_CONFLICTING_ADDRESSES  ((NTSTATUS)0xC0000018L)
#define STATUS_ACCESS_DENIED          ((NTSTATUS)0xC0000022L)
#define STATUS_BUFFER_TOO_SMALL       ((NTSTATUS)0xC0000023L)
#define STATUS_OBJECT_NAME_NOT_FOUND  ((NTSTATUS)0xC0000034L)
#define STATUS_PROCEDURE_NOT_FOUND    ((NTSTATUS)0xC000007AL)
#define STATUS_INVALID_IMAGE_FORMAT   ((NTSTATUS)0xC000007BL)
#define STATUS_NO_TOKEN               ((NTSTATUS)0xC000007CL)

#define CURRENT_PROCESS ((HANDLE) -1)
#define CURRENT_THREAD  ((HANDLE) -2)
#define NtCurrentProcess CURRENT_PROCESS

NTSTATUS h_PsRemoveLoadImageNotifyRoutine(void* NotifyRoutine)
{

	return STATUS_PROCEDURE_NOT_FOUND;
}

NTSTATUS h_PsSetCreateProcessNotifyRoutineEx(void* NotifyRoutine, BOOLEAN Remove)
{
	if (Remove) {
		return STATUS_INVALID_PARAMETER;
	}
	else {
		return STATUS_SUCCESS;
	}
}

UCHAR h_KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK SpinLock)
{

	return (UCHAR)0x00;
}

void h_KeReleaseSpinLock(PKSPIN_LOCK SpinLock, UCHAR NewIrql)
{


}

void h_ExWaitForRundownProtectionRelease(_EX_RUNDOWN_REF* RunRef)
{

}

BOOLEAN h_KeCancelTimer(_KTIMER* Timer)
{

	return true;
}

PVOID h_MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
{

	char cStr[512] = { 0 };
	wchar_t* wStr = SystemRoutineName->Buffer;
	PVOID funcptr = 0;
	wcstombs(cStr, SystemRoutineName->Buffer, 256);
	spdlog::info("{}", cStr);


	if (constantTimeExportProvider.contains(cStr)) {
		funcptr = constantTimeExportProvider[cStr];
	}

	if (funcptr) {//Was it static exported variable 
		spdlog::info(prototypedMsg);
		return funcptr;
	}

	if (myConstantProvider.contains(cStr))
		funcptr = myConstantProvider[cStr].hook;

	if (funcptr == nullptr) {
		funcptr = GetProcAddress(ntdll, cStr);
		if (funcptr == nullptr) {

#ifdef STUB_UNIMPLEMENTED
			spdlog::info("\033[38;5;9mUSING STUB\033[0m");
			funcptr = unimplemented_stub;
#else
			spdlog::info("\033[38;5;9mNOT_IMPLEMENTED\033[0m");
			funcptr = 0;
			exit(0);
#endif
		}
		else {
			spdlog::info(passthroughMsg);
		}
	}
	else {
		spdlog::info(prototypedMsg);
	}

	return funcptr;
}

HANDLE h_PsGetThreadProcessId(_ETHREAD* Thread) {
	if (Thread) {
		Thread->Cid.UniqueProcess;
	}return 0;
}

HANDLE h_PsGetThreadProcess(_ETHREAD* Thread) {
	if (Thread) {
		//todo impl
		spdlog::warn("h_PsGetThreadProcess un impl!");
		return 0;
	} return 0;
}

void h_ProbeForRead(void* address, size_t len, ULONG align) {
	spdlog::info("ProbeForRead -> {:p}(len: {}) align: {}", address, len, align);
}
void h_ProbeForWrite(void* address, size_t len, ULONG align) {
	spdlog::info("ProbeForWrite -> {:p}(len: {}) align: {}", address, len, align);
}




int h__vsnwprintf(wchar_t* buffer, size_t count, const wchar_t* format, va_list argptr)
{

	return _vsnwprintf(buffer, count, format, argptr);
}




//todo fix mutex bs
void h_KeInitializeMutex(PVOID Mutex, ULONG level)
{

}

LONG h_KeReleaseMutex(PVOID Mutex, BOOLEAN Wait) { return 0; }

//todo object might be invalid
NTSTATUS h_KeWaitForSingleObject(
	PVOID Object,
	void* WaitReason,
	void* WaitMode, BOOLEAN Alertable,
	PLARGE_INTEGER Timeout) {
	return STATUS_SUCCESS;
};

ULONG h_KeQueryTimeIncrement() {
	return 1000;
}

//todo impl might be broken
NTSTATUS h_PsCreateSystemThread(
	PHANDLE ThreadHandle, ULONG DesiredAccess,
	void* ObjectAttributes,
	HANDLE ProcessHandle, void* ClientId, void* StartRoutine,
	PVOID StartContext) {
	//CreateThread(nullptr, 4096, (LPTHREAD_START_ROUTINE)StartRoutine, StartContext, 0, 0);
	return 0;
}

//todo impl 
NTSTATUS h_PsTerminateSystemThread(
	NTSTATUS exitstatus) {
	printf("thread boom"); __debugbreak(); int* a = 0; *a = 1; return 0;
}

//todo impl
void h_IofCompleteRequest(void* pirp, CHAR boost) {

}

//todo impl
NTSTATUS h_IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName) {
	return STATUS_SUCCESS;
}




BOOL h_IoIsSystemThread(_ETHREAD* thread) {
	return true;
}



void h_IoDeleteDevice(_DEVICE_OBJECT* obj) {

}

//todo definitely will blowup
void* h_IoGetTopLevelIrp() {
	spdlog::warn("IoGetTopLevelIrp blows up sorry");
	static int irp = 0;
	return &irp;
}

NTSTATUS h_ObReferenceObjectByHandle(
	HANDLE handle,
	ACCESS_MASK DesiredAccess,
	GUID* ObjectType,
	uint64_t AccessMode,
	PVOID* Object,
	void* HandleInformation) {
	spdlog::warn("h_ObReferenceObjectByHandle blows up sorry");
	return -1;
}

//todo more logic required
NTSTATUS h_ObRegisterCallbacks(PVOID CallbackRegistration, PVOID* RegistrationHandle) {
	*RegistrationHandle = (PVOID)0xDEADBEEFCAFE;
	return STATUS_SUCCESS;
}

void h_ObUnRegisterCallbacks(PVOID RegistrationHandle) {

}

void* h_ObGetFilterVersion(void* arg) {
	return 0;
}

BOOLEAN h_MmIsAddressValid(PVOID VirtualAddress) {
	printf("Checking for %llx\n", VirtualAddress);
	if (VirtualAddress == 0)
		return false;
	return true; // rand() % 2 :troll:
}

NTSTATUS h_PsSetCreateThreadNotifyRoutine(PVOID NotifyRoutine) {
	return STATUS_SUCCESS;
}

NTSTATUS h_PsSetLoadImageNotifyRoutine(PVOID NotifyRoutine) { return STATUS_SUCCESS; }

BOOLEAN h_ExAcquireResourceExclusiveLite(
	_ERESOURCE* Resource,
	BOOLEAN    Wait
) {
	//Resource->OwnerEntry.OwnerThread = (uint64_t)h_KeGetCurrentThread();

	return true;
}

NTSTATUS h_KdSystemDebugControl(int Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength,
	/*KPROCESSOR_MODE*/ int PreviousMode)
{
	// expected behaviour when no debugger is attached
	return 0xC0000022;
}

void Initialize() {

	myConstantProvider.insert({ "MmGetSystemRoutineAddress", {1, h_MmGetSystemRoutineAddress} });
	myConstantProvider.insert({ "IoDeleteSymbolicLink", { 1, h_IoDeleteSymbolicLink } });
	myConstantProvider.insert({ "PsRemoveLoadImageNotifyRoutine", {1, h_PsRemoveLoadImageNotifyRoutine } });
	myConstantProvider.insert({ "PsSetCreateProcessNotifyRoutineEx", {2, h_PsSetCreateProcessNotifyRoutineEx } });
	myConstantProvider.insert({ "PsSetCreateProcessNotifyRoutine", {2, h_PsSetCreateProcessNotifyRoutineEx} });
	myConstantProvider.insert({ "KeAcquireSpinLockRaiseToDpc",{ 1, h_KeAcquireSpinLockRaiseToDpc } });
	myConstantProvider.insert({ "PsRemoveCreateThreadNotifyRoutine", {1, h_PsRemoveLoadImageNotifyRoutine} });
	myConstantProvider.insert({ "KeReleaseSpinLock",{ 2, h_KeReleaseSpinLock} });
	myConstantProvider.insert({ "ExpInterlockedPopEntrySList", {1, h_ExpInterlockedPopEntrySList} });
	myConstantProvider.insert({ "KeDelayExecutionThread", {3, h_KeDelayExecutionThread} });
	myConstantProvider.insert({ "ExWaitForRundownProtectionRelease", {1, h_ExWaitForRundownProtectionRelease} });
	myConstantProvider.insert({ "KeCancelTimer", {1, h_KeCancelTimer} });
	myConstantProvider.insert({ "KeSetEvent", {3, h_KeSetEvent} });
	myConstantProvider.insert({ "KeSetTimer",{ 3, h_KeSetTimer} });
	myConstantProvider.insert({ "ExCreateCallback", {4, h_ExCreateCallback } });
	myConstantProvider.insert({ "IoCreateFileEx",{ 1, h_IoCreateFileEx } });
	myConstantProvider.insert({ "RtlDuplicateUnicodeString", {1, h_RtlDuplicateUnicodeString } });
	myConstantProvider.insert({ "IoDeleteController", {1, h_IoDeleteController } });
	myConstantProvider.insert({ "SeQueryInformationToken", {1, h_SeQueryInformationToken } });
	myConstantProvider.insert({ "PsReferencePrimaryToken",{ 1, h_PsReferencePrimaryToken } });
	myConstantProvider.insert({ "PsIsProtectedProcess",{ 1, h_PsIsProtectedProcess } });
	myConstantProvider.insert({ "NtQueryInformationProcess", {1, h_NtQueryInformationProcess } });
	myConstantProvider.insert({ "PsGetCurrentThreadProcessId", {1, h_PsGetCurrentThreadProcessId } });
	myConstantProvider.insert({ "IoGetCurrentThreadProcessId", {1, h_PsGetCurrentThreadProcessId} });
	myConstantProvider.insert({ "PsGetCurrentThreadId", {1, h_PsGetCurrentThreadId} });
	myConstantProvider.insert({ "IoGetCurrentThreadId", {1, h_PsGetCurrentThreadId} });
	myConstantProvider.insert({ "PsGetCurrentProcess",{ 1, h_PsGetCurrentProcess } });
	myConstantProvider.insert({ "IoGetCurrentProcess",{ 1, h_PsGetCurrentProcess } });
	myConstantProvider.insert({ "PsGetProcessId", {1, h_PsGetProcessId} });
	myConstantProvider.insert({ "PsGetProcessWow64Process",{ 1, h_PsGetProcessWow64Process} });
	myConstantProvider.insert({ "PsLookupProcessByProcessId", {1, h_PsLookupProcessByProcessId} });
	myConstantProvider.insert({ "RtlCompareString", {1, h_RtlCompareString} });
	myConstantProvider.insert({ "PsGetProcessCreateTimeQuadPart", {1, h_PsGetProcessCreateTimeQuadPart} });
	myConstantProvider.insert({ "ObfReferenceObject", {1, h_ObfReferenceObject} });
	myConstantProvider.insert({ "ExAcquireFastMutex",{ 1, h_ExAcquireFastMutex } });
	myConstantProvider.insert({ "ExReleaseFastMutex", {1, h_ExReleaseFastMutex} });
	myConstantProvider.insert({ "ZwQueryFullAttributesFile", {2, h_ZwQueryFullAttributesFile} });
	myConstantProvider.insert({ "RtlWriteRegistryValue",{ 6, h_RtlWriteRegistryValue} });
	myConstantProvider.insert({ "RtlInitUnicodeString", {2, h_RtlInitUnicodeString} });
	myConstantProvider.insert({ "ZwOpenKey", {3, h_ZwOpenKey} });
	myConstantProvider.insert({ "ZwFlushKey",{ 1, h_ZwFlushKey} });
	myConstantProvider.insert({ "ZwClose", {1, h_ZwClose} });
	myConstantProvider.insert({ "NtClose",{ 1, h_ZwClose} });
	myConstantProvider.insert({ "ZwQuerySystemInformation",{ 4, h_NtQuerySystemInformation } });
	myConstantProvider.insert({ "NtQuerySystemInformation", {4, h_NtQuerySystemInformation } });
	myConstantProvider.insert({ "ExAllocatePoolWithTag", {3, hM_AllocPoolTag} });
	myConstantProvider.insert({ "ExAllocatePool", {2, hM_AllocPool} });
	myConstantProvider.insert({ "ExFreePoolWithTag", {2, h_DeAllocPoolTag} });
	myConstantProvider.insert({ "ExFreePool", {1, h_DeAllocPool} });
	myConstantProvider.insert({ "RtlRandomEx",{ 1, h_RtlRandomEx } });
	myConstantProvider.insert({ "IoCreateDevice", {7, h_IoCreateDevice} });
	myConstantProvider.insert({ "IoIsSystemThread", {1, h_IoIsSystemThread} });
	myConstantProvider.insert({ "KeInitializeEvent",{ 3, h_KeInitializeEvent } });
	myConstantProvider.insert({ "RtlGetVersion", {1, h_RtlGetVersion} });
	myConstantProvider.insert({ "DbgPrint", {1, printf } });
	myConstantProvider.insert({ "__C_specific_handler",{ 1, _c_exception} });
	myConstantProvider.insert({ "RtlMultiByteToUnicodeN", {1, h_RtlMultiByteToUnicodeN } });
	myConstantProvider.insert({ "KeAreAllApcsDisabled", {1, h_KeAreAllApcsDisabled} });
	myConstantProvider.insert({ "KeAreApcsDisabled", {1, h_KeAreApcsDisabled } });
	myConstantProvider.insert({ "ZwCreateFile", {1, h_NtCreateFile} });
	myConstantProvider.insert({ "ZwQueryInformationFile",{ 1, h_NtQueryInformationFile} });
	myConstantProvider.insert({ "ZwReadFile", {1, h_NtReadFile} });
	myConstantProvider.insert({ "ZwQueryValueKey", {1, h_ZwQueryValueKey} });
	myConstantProvider.insert({ "IoWMIOpenBlock",{ 1, h_IoWMIOpenBlock} });
	myConstantProvider.insert({ "IoWMIQueryAllData", {1, h_IoWMIQueryAllData} });
	myConstantProvider.insert({ "ObfDereferenceObject", {1, h_ObfDereferenceObject } });
	myConstantProvider.insert({ "PsLookupThreadByThreadId", {1, h_PsLookupThreadByThreadId } });
	myConstantProvider.insert({ "RtlDuplicateUnicodeString", {3, h_RtlDuplicateUnicodeString } });
	myConstantProvider.insert({ "ExSystemTimeToLocalTime", {2, h_ExSystemTimeToLocalTime} });
	myConstantProvider.insert({ "ProbeForRead", { 3, h_ProbeForRead } });
	myConstantProvider.insert({ "ProbeForWrite", { 3, h_ProbeForWrite } });
	myConstantProvider.insert({ "RtlTimeToTimeFields", { 2, h_RtlTimeToTimeFields } });
	myConstantProvider.insert({ "KeInitializeMutex", { 2, h_KeInitializeMutex } });
	myConstantProvider.insert({ "KeReleaseMutex", { 2, h_KeReleaseMutex } });
	myConstantProvider.insert({ "KeWaitForSingleObject", { 5, h_KeWaitForSingleObject } });
	myConstantProvider.insert({ "PsCreateSystemThread", { 7, h_PsCreateSystemThread } });
	myConstantProvider.insert({ "PsTerminateSystemThread", { 1, h_PsTerminateSystemThread } });
	myConstantProvider.insert({ "IofCompleteRequest", { 2, h_IofCompleteRequest } });
	myConstantProvider.insert({ "IoCreateSymbolicLink", { 2, h_IoCreateSymbolicLink } });
	myConstantProvider.insert({ "IoDeleteDevice", { 1, h_IoDeleteDevice } });
	myConstantProvider.insert({ "IoGetTopLevelIrp", { 0, h_IoGetTopLevelIrp } });
	myConstantProvider.insert({ "ObReferenceObjectByHandle", { 6, h_ObReferenceObjectByHandle } });
	myConstantProvider.insert({ "ObRegisterCallbacks", { 3, h_ObRegisterCallbacks } });
	myConstantProvider.insert({ "ObUnRegisterCallbacks", { 1, h_ObUnRegisterCallbacks } });
	myConstantProvider.insert({ "ObGetFilterVersion", { 1, h_ObGetFilterVersion } }); // undoc func
	myConstantProvider.insert({ "MmIsAddressValid", { 1, h_MmIsAddressValid } });
	myConstantProvider.insert({ "PsSetCreateThreadNotifyRoutine", { 1, h_PsSetCreateThreadNotifyRoutine } });
	myConstantProvider.insert({ "PsSetLoadImageNotifyRoutine", { 1, h_PsSetLoadImageNotifyRoutine } });
	myConstantProvider.insert({ "PsGetCurrentProcessId", { 1, h_PsGetCurrentThreadProcessId } });
	myConstantProvider.insert({ "PsGetThreadId", { 1, h_PsGetThreadId } });
	myConstantProvider.insert({ "PsGetThreadProcessId", { 1, h_PsGetThreadProcessId } });
	myConstantProvider.insert({ "PsGetThreadProcess", { 1, h_PsGetThreadProcess } });
	myConstantProvider.insert({ "IoQueryFileDosDeviceName", { 1, h_IoQueryFileDosDeviceName } });
	myConstantProvider.insert({ "ObOpenObjectByPointer", { 1, h_ObOpenObjectByPointer } });
	myConstantProvider.insert({ "ObQueryNameString", { 1, h_ObQueryNameString } });
	myConstantProvider.insert({ "PsGetProcessInheritedFromUniqueProcessId", { 1, h_PsGetProcessInheritedFromUniqueProcessId } });
	myConstantProvider.insert({ "PsGetProcessPeb", { 1, h_PsGetProcessPeb } });
	myConstantProvider.insert({ "KeQueryTimeIncrement", {1, h_KeQueryTimeIncrement} });
	myConstantProvider.insert({ "ExAcquireResourceExclusiveLite", {1, h_ExAcquireResourceExclusiveLite} });
	myConstantProvider.insert({ "vswprintf_s", {1, h_vswprintf_s} });
	myConstantProvider.insert({ "swprintf_s", {1, h_swprintf_s} });
	myConstantProvider.insert({ "wcscpy_s", {1, h_wcscpy_s} });
	myConstantProvider.insert({ "wcscat_s", {1, h_wcscat_s} });
	myConstantProvider.insert({ "KeIpiGenericCall", {1, h_KeIpiGenericCall} });
	myConstantProvider.insert({ "KeInitializeTimer", {1, h_KeInitializeTimer} });
	myConstantProvider.insert({ "DbgPrompt", {1, h_DbgPrompt} });
	myConstantProvider.insert({ "KdChangeOption", {1, h_KdChangeOption} });
	myConstantProvider.insert({ "KdSystemDebugControl", { 1, h_KdSystemDebugControl } });
}