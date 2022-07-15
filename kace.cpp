#include <iostream>
#include <cassert>

#include <cstring>
#include <cstdlib>

#include "nt_define.h"

#include "LIEF/LIEF.hpp"

#include "static_export_provider.h"

//#define MONITOR_ACCESS //This will monitor every read/write with a page_guard - SLOW - Better debugging

#include "memory_layout.h"

#include "ntoskrnl_struct.h"
#include "ntoskrnl_provider.h"

using proxyCall = uint64_t(__fastcall*)(...);
proxyCall DriverEntry = nullptr;


_DRIVER_OBJECT drvObj = {0};
UNICODE_STRING RegistryPath = {0};


#define READ_VIOLATION 0
#define EXECUTE_VIOLATION 8

uint64_t passthrough(...)
{
	return 0;
}


//POC STAGE, NEED TO MAKE THIS DYNAMIC - Most performance issue come from this, also for some reason i only got this to work in Visual studio, not outside of it.

uintptr_t lastPG = 0;

LONG MyExceptionHandler(EXCEPTION_POINTERS* e)
{
	uintptr_t ep = (uintptr_t)e->ExceptionRecord->ExceptionAddress;
	auto offset = GetMainModule()->base - ep;

	//printf("%llx - %llx\n", ep - db, ep - kb);
	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
	{
		auto ptr = *(uint32_t*)ep;
		//printf("%08x\n", ptr);
		if (ptr == 0xc0200f44)
		{
			// mov rax, cr8
			e->ContextRecord->Rax = 0;
			e->ContextRecord->Rip += 4;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		//if (ptr[0] == 0x44 && ptr[1] == 0x0F && ptr[2] == 0x20 && ptr[3] == 0xc0) { // mov rax, cr8
		//	e->ContextRecord->Rax = 0; // IRQL = PASSIVE_LEVEL
		//	e->ContextRecord->Rip += 4;
		//	return EXCEPTION_CONTINUE_EXECUTION;
		//}
	}
	else if (e->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
	{
		e->ContextRecord->EFlags |= 0x100ui32;
		DWORD oldProtect = 0;

		lastPG = PAGE_ALIGN_DOWN(e->ExceptionRecord->ExceptionInformation[1]);
		if (lastPG == PAGE_ALIGN_DOWN((uintptr_t)&InitSafeBootMode))
		{
			auto hooked_section = self_data->exported_functions();
			for (auto entry = hooked_section.cbegin(); entry < hooked_section.cend(); ++entry)
			{
				if (entry->address() + (uintptr_t)GetModuleHandle(nullptr) == e->ExceptionRecord->ExceptionInformation[
					1])
				{
					printf("Driver is accessing %s\n", entry->name().c_str());
					break;
				}
			}
		}
		else
		{
			SetVariableInModulesEAT(e->ExceptionRecord->ExceptionInformation[1]);

			auto read_module = FindModule(e->ExceptionRecord->ExceptionInformation[1]);
			if (read_module)
			{
				printf("Reading %s+0x%llx\n", read_module->name,
				       e->ExceptionRecord->ExceptionInformation[1] - read_module->base);
			}
			else
			{
				printf("Reading unknown data\n");
			}
			lastPG = PAGE_ALIGN_DOWN(e->ExceptionRecord->ExceptionInformation[1]);
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (e->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		DWORD oldProtect;
		VirtualProtect((LPVOID)lastPG, 0x1000, PAGE_READONLY | PAGE_GUARD, &oldProtect);
		lastPG = 0;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (e->ExceptionRecord->ExceptionCode = EXCEPTION_ACCESS_VIOLATION)
	{
		auto bufferopcode = (uint8_t*)e->ContextRecord->Rip;
		auto addr_access = e->ExceptionRecord->ExceptionInformation[1];
		switch (e->ExceptionRecord->ExceptionInformation[0])
		{
		case READ_VIOLATION:

			if (e->ExceptionRecord->ExceptionInformation[1] >= 0xFFFFF78000000000 && e->ExceptionRecord->
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

			if (bufferopcode[0] == 0xa1
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

			break;
		case EXECUTE_VIOLATION:
			uintptr_t redirectRip = 0;
			printf("%llx\n", ep);
			if (ep <= 0x100000) //tried to execute a non-relocated IAT -- Dirty but does the trick for now
				redirectRip = FindFunctionInModulesFromIAT(ep);
			else //EAT execution
				redirectRip = FindFunctionInModulesFromEAT(ep);


			if (!redirectRip)
				exit(0);

			e->ContextRecord->Rip = redirectRip;
			return EXCEPTION_CONTINUE_EXECUTION;
			break;
		}
	}

	return 0;
}


UNICODE_STRING Derp = {0};

struct stuff
{
	uint64_t pad[4] = {0};
};

stuff padding = {{0, 0, 0, 0}};

const wchar_t* randomStr =
	L"LOLOLOL\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

int fakeDriverEntry()
{
	FixMainModuleSEH(); //Needed for EAC, they use __try/__except(1) redirection

	AddVectoredExceptionHandler(true, MyExceptionHandler);

	printf("Calling the driver entrypoint\n");


	drvObj.Size = sizeof(drvObj);
	drvObj.DriverName.Buffer = (WCHAR*)randomStr;
	drvObj.DriverName.Length = lstrlenW(randomStr);
	drvObj.DriverName.MaximumLength = 16;

	RegistryPath.Buffer = (WCHAR*)randomStr;
	RegistryPath.Length = lstrlenW(randomStr);
	RegistryPath.MaximumLength = 16;
	//memset((void*)&drvObj, 0xFF, sizeof(drvObj));

	memset(&FakeKernelThread, 0, sizeof(FakeKernelThread));

	memset(&FakeSystemProcess, 0, sizeof(FakeSystemProcess));

	InitializeListHead(&FakeKernelThread.Tcb.Header.WaitListHead);
	InitializeListHead(&FakeSystemProcess.Pcb.Header.WaitListHead);

	__writegsqword(0x188, (DWORD64)&FakeKernelThread); //Fake KTHREAD

	FakeKernelThread.Tcb.Process = (_KPROCESS*)&FakeSystemProcess; //PsGetThreadProcess
	FakeKernelThread.Tcb.ApcState.Process = (_KPROCESS*)&FakeSystemProcess; //PsGetCurrentProcess

	FakeKernelThread.Cid.UniqueProcess = (void*)4; //PsGetThreadProcessId
	FakeKernelThread.Cid.UniqueThread = (void*)0x1234; //PsGetThreadId

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

	auto result = DriverEntry(&drvObj, RegistryPath);
	printf("Done! = %llx\n", result);
	exit(0);
	return 0;
}


int main(int argc, char* argv[])
{
	HookSelf(argv[0]);
	LoadModule("c:\\EMU\\cng.sys", R"(c:\windows\system32\drivers\cng.sys)", "cng.sys", false);
	LoadModule("c:\\EMU\\ntoskrnl.exe", R"(c:\windows\system32\ntoskrnl.exe)", "ntoskrnl.exe", false);
	//DriverEntry = (proxyCall)LoadModule("c:\\EMU\\EasyAntiCheat_2.sys", "c:\\EMU\\EasyAntiCheat_2.sys", "EAC", true);
	LoadModule("c:\\EMU\\fltmgr.sys", R"(c:\windows\system32\drivers\fltmgr.sys)", "FLTMGR.SYS", false);
	LoadModule("c:\\EMU\\CI.dll", R"(c:\windows\system32\CI.dll)", "CI.dll", false);


	DriverEntry = (proxyCall)LoadModule("c:\\EMU\\faceit.sys", "c:\\EMU\\faceit.sys", "faceit", true);
	//DriverEntry = (proxyCall)LoadPE("C:\\Users\\Generic\\source\\repos\\KMDF Driver2\\x64\\Release\\KMDFDriver2.sys", true);

	//DriverEntry = (proxyCall)((uintptr_t)db + 0x11B0);

	CreateThread(nullptr, 4096, (LPTHREAD_START_ROUTINE)fakeDriverEntry, nullptr, 0, nullptr);

	while (true)
	{
		Sleep(1000);
	}

	return 0;
}
