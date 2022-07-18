#include <iostream>
#include <cassert>

#include <cstring>
#include <cstdlib>

#include "ntoskrnl_provider.h"

//#define MONITOR_ACCESS //This will monitor every read/write with a page_guard - SLOW - Better debugging

//#define MONITOR_DATA_ACCESS//This will monitor every read/write with a page_guard - SLOW - Better debugging

#include "pefile.h"
#include "provider.h"

#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/spdlog.h"

#include "memorytracker.hpp"

//#define MONITOR_ACCESS //This will monitor every read/write with a page_guard - SLOW - Better debugging

//#define MONITOR_DATA_ACCESS 1//This will monitor every read/write with a page_guard - SLOW - Better debugging

using proxyCall = uint64_t(__fastcall*)(...);
proxyCall DriverEntry = nullptr;

_DRIVER_OBJECT drvObj = { 0 };
UNICODE_STRING RegistryPath = { 0 };

#define READ_VIOLATION 0
#define WRITE_VIOLATION 1
#define EXECUTE_VIOLATION 8

uint64_t passthrough(...)
{
	return 0;
}

char tempBuffer[512] = { 0 };

void custom_printf(const char* buffer, ...) {
	va_list args;
	va_start(args, buffer);
	vsprintf(tempBuffer, buffer, args);
	spdlog::info(tempBuffer);
	va_end(args);
}

//POC STAGE, NEED TO MAKE THIS DYNAMIC - Most performance issue come from this, also for some reason i only got this to work in Visual studio, not outside of it.

uintptr_t lastPG = 0;

//From waryas machine, no hv, clean install
uint64_t cr0 = 0x8005003b;
uint64_t cr3 = 0x1ad002000000;
uint64_t cr4 = 0x370678;
uint64_t cr8 = 0;
LONG ExceptionHandler(EXCEPTION_POINTERS* e)
{
	uintptr_t ep = (uintptr_t)e->ExceptionRecord->ExceptionAddress;
	auto offset =  ep - GetMainModule()->base;


	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
	{
		auto ptr = *(uint32_t*)ep;
		auto ptrBuffer = (unsigned char*)ep;
		if (ptr == 0xc0200f44) //mov eax, cr8
		{
			// mov rax, cr8
			printf("Reading IRQL\n");
			e->ContextRecord->Rax = cr8;
			e->ContextRecord->Rip += 4;
			return EXCEPTION_CONTINUE_EXECUTION;
		} else if (ptr == 0x00200f44) // mov rax, cr8
		{
			// mov rax, cr8
			printf("Reading IRQL\n");
			e->ContextRecord->Rax = cr8;
			e->ContextRecord->Rip += 4;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x20 && ptrBuffer[2] == 0xD8) { //mov rax, cr3
			printf("Reading CR3\n");
			e->ContextRecord->Rax = cr3;
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x22 && ptrBuffer[2] == 0xD8) { //mov cr3, rax
			//e->ContextRecord->Rax = 0;
			printf("CHANGING CR3 to %llx\n", e->ContextRecord->Rax);
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x20 && ptrBuffer[2] == 0xC1) {
			printf("Reading CR0 into RCX\n");
			e->ContextRecord->Rcx = cr0;
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0xFA) { //CLEAR INTERRUPT
			e->ContextRecord->Rip += 1;
			printf("Clearing interrupt\n");
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0xFB) { //RESTORE INTERRUPT
			e->ContextRecord->Rip += 1;
			printf("Restoring interrupt\n");
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x23 && ptrBuffer[2] == 0xFE) { //mov dr7, rsi
			printf("Clearing DR7\n");
			e->ContextRecord->Dr7 = e->ContextRecord->Rsi;
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
			
	}
	else if (e->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE )
	{
		e->ContextRecord->EFlags |= 0x100ui32;
		DWORD oldProtect = 0;

		lastPG = PAGE_ALIGN_DOWN(e->ExceptionRecord->ExceptionInformation[1]);
		if (lastPG == PAGE_ALIGN_DOWN((uintptr_t)&InitSafeBootMode))
		{
			auto accessedChar = self_data->GetExport(e->ExceptionRecord->ExceptionInformation[1] - (uintptr_t)GetModuleHandle(nullptr));
			auto readAddr = e->ExceptionRecord->ExceptionInformation[1];
			if (!accessedChar) { //?
				while (!accessedChar) {
					readAddr--;
					accessedChar = self_data->GetExport(readAddr - (uintptr_t)GetModuleHandle(nullptr));
				}
				spdlog::info("\033[38;5;46m[Accessing]\033[0m {}:+{:p}", accessedChar,PVOID(e->ExceptionRecord->ExceptionInformation[1] - readAddr));
			}
			else {
               spdlog::info("\033[38;5;46m[Accessing]\033[0m {}", accessedChar);
			}

		} else if (!FindModule(lastPG))
		{
			
			if (MemoryTracker::isTracked(lastPG)) {
				auto namevar = MemoryTracker::getName(lastPG);
				auto offset = e->ExceptionRecord->ExceptionInformation[1] - MemoryTracker::getStart(namevar);
				printf("LOCAL ACCESS : %s+0x%08x - Type : %d\n", namevar.c_str(), offset, e->ExceptionRecord->ExceptionInformation[0]);

			}
			else {
				printf("WEIRD, CONTACT WARYAS");
				exit(0);
			}

		}
		else
		{

			SetVariableInModulesEAT(e->ExceptionRecord->ExceptionInformation[1]);

			auto read_module = FindModule(e->ExceptionRecord->ExceptionInformation[1]);
			if (read_module)
			{
			    spdlog::info("Reading {}+{:p}", read_module->name,
			    PVOID(e->ExceptionRecord->ExceptionInformation[1] - read_module->base));
			}
			else
			{
	            spdlog::info("Reading unknown data");
			}
			
		}
		lastPG = PAGE_ALIGN_DOWN(e->ExceptionRecord->ExceptionInformation[1]);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (e->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		DWORD oldProtect;
		if (!FindModule(lastPG))
		{
			VirtualProtect((LPVOID)lastPG, 0x1000, PAGE_READWRITE | PAGE_GUARD, &oldProtect);

		}
		else {
			VirtualProtect((LPVOID)lastPG, 0x1000, PAGE_READONLY | PAGE_GUARD, &oldProtect);
		}

		lastPG = 0;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (e->ExceptionRecord->ExceptionCode = EXCEPTION_ACCESS_VIOLATION)
	{
		auto bufferopcode = (uint8_t*)e->ContextRecord->Rip;
		auto addr_access = e->ExceptionRecord->ExceptionInformation[1];
		switch (e->ExceptionRecord->ExceptionInformation[0])
		{
		case WRITE_VIOLATION:
			printf("Tryign to write, not handled\n");
			exit(0);
			break;

		case READ_VIOLATION:
			if (bufferopcode[0] == 0xCD && bufferopcode[1] == 0x20) {
				printf("--CHECKING FOR PATCHGUARD--\n");
				e->ContextRecord->Rip += 2;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else if (bufferopcode[0] == 0xa1
				&& bufferopcode[1] == 0x6c
				&& bufferopcode[2] == 0x02
				&& bufferopcode[3] == 0x00
				&& bufferopcode[4] == 0x00
				&& bufferopcode[5] == 0x80
				&& bufferopcode[6] == 0xF7
				&& bufferopcode[7] == 0xff
				&& bufferopcode[8] == 0xff)
			{
				//A1 6C 02 00 00 80 F7 FF FF
				e->ContextRecord->Rax = *(uint32_t*)0x7FFE026c;
				e->ContextRecord->Rip += 9;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else if (bufferopcode[0] == 0x48
				&& bufferopcode[1] == 0xA1
				&& bufferopcode[2] == 0x20
				&& bufferopcode[3] == 0x03
				&& bufferopcode[4] == 0x00
				&& bufferopcode[5] == 0x00
				&& bufferopcode[6] == 0x80
				&& bufferopcode[7] == 0xf7
				&& bufferopcode[8] == 0xff
				&& bufferopcode[9] == 0xff)
			{
				
				e->ContextRecord->Rax = *(uint32_t*)0x7FFE026c;
				e->ContextRecord->Rip += 10;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else if (e->ExceptionRecord->ExceptionInformation[1] >= 0xFFFFF78000000000 && e->ExceptionRecord->
				ExceptionInformation[1] <= 0xFFFFF78000001000)
			{
				auto read_addr = e->ExceptionRecord->ExceptionInformation[1];
				auto offset_shared = read_addr - 0xFFFFF78000000000;

				if (e->ContextRecord->Rsi == read_addr)
				{
					e->ContextRecord->Rsi = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rdx == read_addr)
				{
					e->ContextRecord->Rdx = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rcx == read_addr)
				{
					e->ContextRecord->Rcx = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rax == read_addr)
				{
					e->ContextRecord->Rax = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rbx == read_addr)
				{
					e->ContextRecord->Rbx = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rdi == read_addr)
				{
					e->ContextRecord->Rdi = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rsp == read_addr)
				{
					e->ContextRecord->Rsp = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rbp == read_addr)
				{
					e->ContextRecord->Rbp = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R8 == read_addr)
				{
					e->ContextRecord->R8 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R9 == read_addr)
				{
					e->ContextRecord->R9 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R10 == read_addr)
				{
					e->ContextRecord->R10 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R11 == read_addr)
				{
					e->ContextRecord->R11 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R12 == read_addr)
				{
					e->ContextRecord->R12 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R13 == read_addr)
				{
					e->ContextRecord->R13 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R14 == read_addr)
				{
					e->ContextRecord->R14 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R15 == read_addr)
				{
					e->ContextRecord->R15 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rsi == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rsi = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rdx == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rdx = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rcx == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rcx = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rax == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rax = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rbx == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rbx = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rdi == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rdi = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rsp == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rsp = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R8 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R8 = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R9 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R9 = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R10 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R10 = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R11 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R11 = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R12 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R12 = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R13 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R13 = 0x7FFE0000;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R14 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R14 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R15 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R15 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rbp == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rbp = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
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
				spdlog::warn("Exiting...");
				exit(0);
#endif
			}

			e->ContextRecord->Rip = redirectRip;
			return EXCEPTION_CONTINUE_EXECUTION;
			break;
		}
		}
		printf("IM HERE\n");
	return 0;
	}

const wchar_t* driverName = L"\\Driver\\vgk";
const wchar_t* registryBuffer = L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\vgk";

DWORD FakeDriverEntry(LPVOID)
{
	FixMainModuleSEH(); //Needed for EAC, they use __try/__except(1) redirection

	AddVectoredExceptionHandler(true, ExceptionHandler);

	spdlog::info("Calling the driver entrypoint");

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

	FakeCPU.CurrentThread =  (_KTHREAD*)&FakeKernelThread;
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

	MemoryTracker::Initiate();

	MemoryTracker::TrackVariable((uintptr_t)&FakeKPCR, sizeof(FakeKPCR), (char*)"KPCR");
	MemoryTracker::TrackVariable((uintptr_t)&FakeCPU, sizeof(FakeCPU), (char*)"CPU");

	MemoryTracker::TrackVariable((uintptr_t)&FakeSystemProcess, sizeof(FakeSystemProcess), (char*)"PID4.EPROCESS");
	MemoryTracker::TrackVariable((uintptr_t)&FakeKernelThread, sizeof(FakeKernelThread), (char*)"PID4.ETHREAD");


	FakeKPCR.Self = (_KPCR*) & FakeKPCR.Self;

	auto result = DriverEntry(&drvObj, RegistryPath);
	spdlog::info("Done! = {}", result);
	system("pause");
	return 0;
}

int main(int argc, char* argv[]) {

	PsInitialSystemProcess = (uint64_t)&FakeSystemProcess;

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

    spdlog::set_pattern("[kace-%t] %v");
    spdlog::info("Loading modules");

	HookSelf(argv[0]);

	LoadModule("c:\\EMU\\cng.sys", R"(c:\windows\system32\drivers\cng.sys)", "cng.sys", false);
	LoadModule("c:\\EMU\\ntoskrnl.exe", R"(c:\windows\system32\ntoskrnl.exe)", "ntoskrnl.exe", false);
	LoadModule("c:\\EMU\\fltmgr.sys", R"(c:\windows\system32\drivers\fltmgr.sys)", "FLTMGR.SYS", false);
	LoadModule("c:\\EMU\\CI.dll", R"(c:\windows\system32\CI.dll)", "Ci.dll", false);
	LoadModule("c:\\EMU\\HAL.dll", R"(c:\windows\system32\HAL.dll)", "HAL.dll", false);
	LoadModule("c:\\EMU\\kd.dll", R"(c:\windows\system32\kd.dll)", "kd.dll", false);
	LoadModule("c:\\EMU\\ntdll.dll", R"(c:\windows\system32\ntdll.dll)", "ntdll.dll", false);

	//DriverEntry = (proxyCall)LoadModule("c:\\EMU\\faceit.sys", "c:\\EMU\\faceit.sys", "faceit", true);
	DriverEntry = reinterpret_cast<proxyCall>(LoadModule("c:\\EMU\\EasyAntiCheat_2.sys", "c:\\EMU\\EasyAntiCheat_2.sys", "EAC", true));
	//DriverEntry = (proxyCall)LoadModule("c:\\EMU\\vgk.sys", "c:\\EMU\\vgk.sys", "bedaisy", true);
	
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
