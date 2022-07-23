#include <iostream>
#include <cassert>

#include <cstring>
#include <cstdlib>


#include "emulation.h"

#include "ntoskrnl_provider.h"

//#define MONITOR_ACCESS //This will monitor every read/write with a page_guard - SLOW - Better debugging

//This will monitor every read/write with a page_guard - SLOW - Better debugging

#include <PEMapper/pefile.h>
#include <MemoryTracker/memorytracker.h>
#include <Logger/Logger.h>

#include "provider.h"

#include <intrin.h>

#include "paging_emulation.h"


//#define MONITOR_ACCESS //This will monitor every read/write with a page_guard - SLOW - Better debugging

//#define MONITOR_DATA_ACCESS 1//This will monitor every read/write with a page_guard - SLOW - Better debugging

using proxyCall = uint64_t(__fastcall*)(...);
proxyCall DriverEntry = nullptr;



#define READ_VIOLATION 0
#define WRITE_VIOLATION 1
#define EXECUTE_VIOLATION 8
 
uint64_t fakeKUSER_SHARED_DATA = MemoryTracker::AllocateVariable(0x1000);



void setKUSD() {
	memcpy((PVOID)fakeKUSER_SHARED_DATA, (PVOID)0x7FFE0000, 0x1000);
}

uint64_t passthrough(...)
{
	return 0;
}

//POC STAGE, NEED TO MAKE THIS DYNAMIC - Most performance issue come from this, also for some reason i only got this to work in Visual studio, not outside of it.

uintptr_t lastPG = 0;


extern "C" void u_iret();

LONG ExceptionHandler(EXCEPTION_POINTERS* e)
{
	uintptr_t ep = (uintptr_t)e->ExceptionRecord->ExceptionAddress;

	auto offset = ep - GetMainModule()->base;

	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_FLT_DIVIDE_BY_ZERO)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}
	else if (e->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
	{
		bool wasEmulated = false;

		wasEmulated = VCPU::PrivilegedInstruction::Parse(e->ContextRecord);

		if (wasEmulated) {
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else {
			DebugBreak();
		}

	}
	else if (e->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
	{
		


		lastPG = PAGE_ALIGN_DOWN(e->ExceptionRecord->ExceptionInformation[1]);
		if (lastPG == PAGE_ALIGN_DOWN((uintptr_t)&InitSafeBootMode))
		{
			auto accessedChar = self_data->GetExport(e->ExceptionRecord->ExceptionInformation[1] - (uintptr_t)GetModuleHandle(nullptr));
			uintptr_t readAddr = e->ExceptionRecord->ExceptionInformation[1];
			if (!accessedChar) { //?
				while (!accessedChar) {
					readAddr--;
					accessedChar = self_data->GetExport(readAddr - (uintptr_t)GetModuleHandle(nullptr));
				}
				if (e->ExceptionRecord->ExceptionInformation[0] == 0) {
					Logger::Log("\033[38;5;46m[Reading]\033[0m %s:+%08x\n", accessedChar, e->ExceptionRecord->ExceptionInformation[1] - readAddr);
				}
				else {
					Logger::Log("\033[38;5;46m[Writing]\033[0m %s:+%08x\n", accessedChar, e->ExceptionRecord->ExceptionInformation[1] - readAddr);
				}
			}
			else {
				if (e->ExceptionRecord->ExceptionInformation[0] == 0) {
					Logger::Log("\033[38;5;46m[Reading]\033[0m %s\n", accessedChar);
				}
				else {
					Logger::Log("\033[38;5;46m[Writing]\033[0m %s\n", accessedChar);
				}
				
			}

		}
		else if (!FindModule(lastPG))
		{

			if (MemoryTracker::isTracked(lastPG)) {
				auto namevar = MemoryTracker::getName(lastPG);
				auto offset = e->ExceptionRecord->ExceptionInformation[1] - MemoryTracker::getStart(namevar);
				if (e->ExceptionRecord->ExceptionInformation[0] == 0) {
					Logger::Log("\033[38;5;46m[Reading]\033[0m %s+0x%08x - Type : %d\n", namevar.c_str(), offset, e->ExceptionRecord->ExceptionInformation[0]);
				}
				else {
					Logger::Log("\033[38;5;46m[Writing]\033[0m %s+0x%08x - Type : %d\n", namevar.c_str(), offset, e->ExceptionRecord->ExceptionInformation[0]);
				}

			}
			else {
				Logger::Log("WEIRD, CONTACT WARYAS\n");
				exit(0);
			}

		}
		else
		{

			SetVariableInModulesEAT(e->ExceptionRecord->ExceptionInformation[1]);

			auto read_module = FindModule(e->ExceptionRecord->ExceptionInformation[1]);
			if (read_module)
			{
				if (e->ExceptionRecord->ExceptionInformation[0] == 0) {
					Logger::Log("\033[38;5;46m[Reading]\033[0m %s+%08x\n", read_module->name,
						PVOID(e->ExceptionRecord->ExceptionInformation[1] - read_module->base));
				}
				else {
					Logger::Log("\033[38;5;46m[Writing]\033[0m %s+%08x\n", read_module->name,
						PVOID(e->ExceptionRecord->ExceptionInformation[1] - read_module->base));
				}
			}
			else
			{
				Logger::Log("Accessing unknown data\n");
			}

		}
		e->ContextRecord->EFlags |= 0x100ui32;
		lastPG = PAGE_ALIGN_DOWN(e->ExceptionRecord->ExceptionInformation[1]);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (e->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		DWORD oldProtect;

		VirtualProtect((LPVOID)lastPG, 0x1000, PAGE_READWRITE | PAGE_GUARD, &oldProtect);

		lastPG = 0;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (e->ExceptionRecord->ExceptionCode = EXCEPTION_ACCESS_VIOLATION)
	{
		auto bufferopcode = (uint8_t*)e->ContextRecord->Rip;
		auto addr_access = e->ExceptionRecord->ExceptionInformation[1];
		bool wasEmulated = false;
		switch (e->ExceptionRecord->ExceptionInformation[0])
		{
		case WRITE_VIOLATION:
			Logger::Log("Trying to write, not handled\n");
			exit(0);
			break;

		case READ_VIOLATION:

			wasEmulated = VCPU::MemoryRead::Parse(e->ExceptionRecord->ExceptionInformation[1], e->ContextRecord);

			if (wasEmulated) {
				return EXCEPTION_CONTINUE_EXECUTION;
			}

			if (e->ExceptionRecord->ExceptionInformation[1] == e->ExceptionRecord->ExceptionInformation[0] && e->ExceptionRecord->ExceptionInformation[0] == 0) {
				return EXCEPTION_CONTINUE_SEARCH;
			}

			if (bufferopcode[0] == 0xCD && bufferopcode[1] == 0x20) {
				Logger::Log("\033[38;5;46m[INFO]\033[0m Checking for Patchguard (int 20)\n");
				e->ContextRecord->Rip += 2;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else if (bufferopcode[0] == 0x48 && bufferopcode[1] == 0xCF) {
				e->ContextRecord->Rip = (uintptr_t)u_iret;
				Logger::Log("\033[38;5;46m[INFO]\033[0m IRET Timing Emulation\n");
				return EXCEPTION_CONTINUE_EXECUTION;
			}

			break;
		case EXECUTE_VIOLATION:
			uintptr_t redirectRip = 0;
			if (ep <= 0x1000000) //tried to execute a non-relocated IAT -- Dirty but does the trick for now
				redirectRip = FindFunctionInModulesFromIAT(ep);
			else //EAT execution
				redirectRip = FindFunctionInModulesFromEAT(ep);

			if (!redirectRip) {
#ifdef STUB_UNIMPLEMENTED
				redirectRip = (uintptr_t)unimplemented_stub;
#else
				Logger::Log("Exiting...");
				exit(0);
#endif
			}

			e->ContextRecord->Rip = redirectRip;
			return EXCEPTION_CONTINUE_EXECUTION;
			break;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

const wchar_t* driverName = L"\\Driver\\vgk";
const wchar_t* registryBuffer = L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\vgk";

DWORD FakeDriverEntry(LPVOID)
{
	FixMainModuleSEH(); //Needed for EAC, they use __try/__except(1) redirection
	
	AddVectoredExceptionHandler(true, ExceptionHandler);

	Logger::Log("Calling the driver entrypoint\n");

	drvObj.Size = sizeof(drvObj);
	drvObj.DriverName.Buffer = (WCHAR*)driverName;
	drvObj.DriverName.Length = lstrlenW(driverName);
	drvObj.DriverName.MaximumLength = 16;

	RegistryPath.Buffer = (WCHAR*)registryBuffer;
	RegistryPath.Length = lstrlenW(RegistryPath.Buffer) * 2;
	RegistryPath.MaximumLength = lstrlenW(RegistryPath.Buffer) * 2;
	//memset((void*)&drvObj, 0xFF, sizeof(drvObj));

	memset(&FakeKernelThread, 0, sizeof(FakeKernelThread));
	memset(&FakeSystemProcess, 0, sizeof(FakeSystemProcess));
	memset(&FakeKPCR, 0, sizeof(FakeKPCR));
	memset(&FakeCPU, 0, sizeof(FakeCPU));

	InitializeListHead(&FakeKernelThread.Tcb.Header.WaitListHead);
	InitializeListHead(&FakeSystemProcess.Pcb.Header.WaitListHead);

	__writegsqword(0x188, (DWORD64)&FakeKernelThread); //Fake KTHREAD
	__writegsqword(0x18, (DWORD64)&FakeKPCR); //Fake _KPCR
	__writegsqword(0x20, (DWORD64)&FakeCPU); //Fake _KPRCB

	FakeKernelThread.Tcb.Process = (_KPROCESS*)&FakeSystemProcess; //PsGetThreadProcess
	FakeKernelThread.Tcb.ApcState.Process = (_KPROCESS*)&FakeSystemProcess; //PsGetCurrentProcess

	FakeKernelThread.Cid.UniqueProcess = (void*)4; //PsGetThreadProcessId
	FakeKernelThread.Cid.UniqueThread = (void*)0x8; //PsGetThreadId

	FakeKernelThread.Tcb.PreviousMode = 0; //PsGetThreadPreviousMode
	FakeKernelThread.Tcb.State = 1; //
	FakeKernelThread.Tcb.InitialStack = (void*)0x1000;
	FakeKernelThread.Tcb.StackBase = (void*)0x1500;
	FakeKernelThread.Tcb.StackLimit = (void*)0x2000;
	FakeKernelThread.Tcb.ThreadLock = 11;
	FakeKernelThread.Tcb.LockEntries = (_KLOCK_ENTRY*)22;

	FakeSystemProcess.UniqueProcessId = (void*)4;
	FakeSystemProcess.Protection.Level = 7;
	FakeSystemProcess.WoW64Process = nullptr;
	FakeSystemProcess.CreateTime.QuadPart = GetTickCount64();

	FakeCPU.CurrentThread = (_KTHREAD*)&FakeKernelThread;
	FakeCPU.IdleThread = (_KTHREAD*)&FakeKernelThread;
	FakeCPU.CoresPerPhysicalProcessor = 2;
	FakeCPU.LogicalProcessorsPerCore = 2;
	FakeCPU.MajorVersion = 10;
	FakeCPU.MinorVersion = 0;
	FakeCPU.RspBase = __readgsqword(0x8);


	FakeKPCR.CurrentPrcb = &FakeCPU;
	FakeKPCR.NtTib.StackBase = (PVOID)__readgsqword(0x8);
	FakeKPCR.NtTib.StackLimit = (PVOID)__readgsqword(0x10);
	FakeKPCR.MajorVersion = 10;
	FakeKPCR.MinorVersion = 0;
	FakeKPCR.Used_Self = (void*)__readgsqword(0x30); //Usermode TEB is actually in kernel gs:0x30
	FakeKPCR.Self = &FakeKPCR;


	__writeeflags(0x10286);

	

	MemoryTracker::TrackVariable((uintptr_t)&FakeKPCR, sizeof(FakeKPCR), (char*)"KPCR");
	MemoryTracker::TrackVariable((uintptr_t)&FakeCPU, sizeof(FakeCPU), (char*)"CPU");

	MemoryTracker::TrackVariable((uintptr_t)&drvObj, sizeof(drvObj), (char*)"MainModule.DriverObject");
	MemoryTracker::TrackVariable((uintptr_t)&RegistryPath, sizeof(RegistryPath), (char*)"MainModule.RegistryPath");
	MemoryTracker::TrackVariable((uintptr_t)&FakeSystemProcess, sizeof(FakeSystemProcess), (char*)"PID4.EPROCESS");
	MemoryTracker::TrackVariable((uintptr_t)&FakeKernelThread, sizeof(FakeKernelThread), (char*)"PID4.ETHREAD");


	
	drvObj.DriverSection = (_KLDR_DATA_TABLE_ENTRY*)MemoryTracker::AllocateVariable(sizeof(_KLDR_DATA_TABLE_ENTRY) * 2);;
	MemoryTracker::TrackVariable((uintptr_t)drvObj.DriverSection, sizeof(_KLDR_DATA_TABLE_ENTRY) * 2, "MainModule.DriverObject.DriverSection");

	

	auto result = DriverEntry(&drvObj, &RegistryPath);
	Logger::Log("Done! = %llx", result);
	system("pause");
	return 0;
}


extern void Initialize();
extern void InitializeExport();

int main(int argc, char* argv[]) {


	MemoryTracker::Initiate();
	VCPU::Initialize();
	SetupCR3();
	//exit(0);
	PsInitialSystemProcess = (uint64_t)&FakeSystemProcess;

	
	Initialize();
	InitializeExport();

	

	//FreeConsole();
	//AllocConsole();
	DWORD dwMode;

	auto hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleMode(hOut, &dwMode);
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, dwMode);

	//logging setup

	// Uncomment to log to a file (file logging is blazingly fast (kekw))
	//auto logger = spdlog::basic_logger_mt("console and file logger", "kace_log.txt");
	//
	//spdlog::set_default_logger(logger);

	
	Logger::Log("Loading modules\n");

	

	LoadModule("c:\\EMU\\cng.sys", R"(c:\windows\system32\drivers\cng.sys)", "cng.sys", false);
	LoadModule("c:\\EMU\\ntoskrnl.exe", R"(c:\windows\system32\ntoskrnl.exe)", "ntoskrnl.exe", false);
	LoadModule("c:\\EMU\\fltmgr.sys", R"(c:\windows\system32\drivers\fltmgr.sys)", "FLTMGR.SYS", false);
	LoadModule("c:\\EMU\\CI.dll", R"(c:\windows\system32\CI.dll)", "Ci.dll", false);
	LoadModule("c:\\EMU\\HAL.dll", R"(c:\windows\system32\HAL.dll)", "HAL.dll", false);
	LoadModule("c:\\EMU\\kd.dll", R"(c:\windows\system32\kd.dll)", "kd.dll", false);
	LoadModule("c:\\EMU\\WdFilter.sys", R"(c:\windows\system32\drivers\WdFilter.sys)", "WdFilter.sys", false);
	LoadModule("c:\\EMU\\ntdll.dll", R"(c:\windows\system32\ntdll.dll)", "ntdll.dll", false);

	//DriverEntry = (proxyCall)LoadModule("c:\\EMU\\faceit.sys", "c:\\EMU\\faceit.sys", "faceit", true);
	//DriverEntry = reinterpret_cast<proxyCall>(LoadModule("c:\\EMU\\easyanticheat_03.sys", "c:\\EMU\\easyanticheat_03.sys", "EAC", true));
	DriverEntry = (proxyCall)LoadModule("c:\\EMU\\vgk.sys", "c:\\EMU\\vgk.sys", "VGK", true);

	
	HookSelf(argv[0]);
	const HANDLE ThreadHandle = CreateThread(nullptr, 4096, FakeDriverEntry, nullptr, 0, nullptr);

	if (!ThreadHandle)
		return 0;

	while (true)
	{
		Sleep(1000);

		DWORD ExitCode;
		if (GetExitCodeThread(ThreadHandle, &ExitCode))
		{
			if (ExitCode != STILL_ACTIVE)
			{
				break;
			}
		}
	}

	CloseHandle(ThreadHandle);

	return 0;
}
