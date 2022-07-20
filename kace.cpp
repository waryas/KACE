#include <iostream>
#include <cassert>

#include <cstring>
#include <cstdlib>

#include "ntoskrnl_provider.h"

//#define MONITOR_ACCESS //This will monitor every read/write with a page_guard - SLOW - Better debugging

//This will monitor every read/write with a page_guard - SLOW - Better debugging

#include "libs/PEMapper/pefile.h"
#include "libs/MemoryTracker/memorytracker.h"
#include "libs/Logger/Logger.h"

#include "provider.h"

#include <intrin.h>



//#define MONITOR_ACCESS //This will monitor every read/write with a page_guard - SLOW - Better debugging

//#define MONITOR_DATA_ACCESS 1//This will monitor every read/write with a page_guard - SLOW - Better debugging

using proxyCall = uint64_t(__fastcall*)(...);
proxyCall DriverEntry = nullptr;

_DRIVER_OBJECT drvObj = { 0 };
UNICODE_STRING RegistryPath = { 0 };

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


//From waryas machine, no hv, clean install
uint64_t cr0 = 0x80050033;
uint64_t cr3 = 0x0;
uint64_t cr4 = 0x370678;
uint64_t cr8 = 0;

void MSRRead(uint64_t ECX, EXCEPTION_POINTERS* e) {

	switch (ECX) {
	case 0x1D9:
		e->ContextRecord->Rax = 0;
		e->ContextRecord->Rdx = 0;
		e->ContextRecord->Rip += 2;
		break;
	default:
		//UNHANDLED
		break;
	}
}

uint64_t DBGCTL_lastEax = 0;
uint64_t DBGCTL_lastEdx = 0;



extern "C" void u_iret();

LONG ExceptionHandler(EXCEPTION_POINTERS* e)
{
	uintptr_t ep = (uintptr_t)e->ExceptionRecord->ExceptionAddress;
	auto offset = ep - GetMainModule()->base;


	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
	{
		auto ptr = *(uint32_t*)ep;
		auto ptrBuffer = (unsigned char*)ep;
		if (ptr == 0xc0200f44) //mov eax, cr8
		{
			// mov rax, cr8
			Logger::Log("\033[38;5;46m[Reading]\033[0m IRQL->EAX\n");
			e->ContextRecord->Rax = cr8;
			e->ContextRecord->Rip += 4;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptr == 0x00200f44) // mov rax, cr8
		{
			// mov rax, cr8
			Logger::Log("\033[38;5;46m[Reading]\033[0m IRQL->RAX\n");
			e->ContextRecord->Rax = cr8;
			e->ContextRecord->Rip += 4;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x32) { //rdmsr
			if (e->ContextRecord->Rcx == 0x1D9) {
				Logger::Log("\033[38;5;46m[Reading]\033[0m MSR DBGCTL -> %d, %d\n", DBGCTL_lastEax, DBGCTL_lastEdx);
				e->ContextRecord->Rax = DBGCTL_lastEax;
				e->ContextRecord->Rdx = DBGCTL_lastEax;
				e->ContextRecord->Rip += 2;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else {
				Logger::Log("\033[38;5;46m[Reading]\033[0m Unhandled MSR : %08x\n", e->ContextRecord->Rcx);
				if (e->ContextRecord->Rcx >= 10000) {
					Logger::Log("\033[38;5;46m[Reading]\033[0m Fake MSR -> Exception injection\n", e->ContextRecord->Rcx);
					//e->ContextRecord->Rip = (uint64_t)h_DbgPrompt;
					return EXCEPTION_CONTINUE_SEARCH;
				}
				//e->ContextRecord->Rip += 2;
			}

		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x30) {

			if (e->ContextRecord->Rcx == 0x1D9) {
				Logger::Log("\033[38;5;46m[Writing]\033[0m MSR DBGCTL -> %d, %d\n", e->ContextRecord->Rax, e->ContextRecord->Rdx);
				DBGCTL_lastEax = e->ContextRecord->Rax;
				DBGCTL_lastEdx = e->ContextRecord->Rdx;
				e->ContextRecord->Rip += 2;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else {
				Logger::Log("\033[38;5;46m[Writing]\033[0m Unhandled MSR : %08x\n", e->ContextRecord->Rcx);
			}
		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x20 && ptrBuffer[2] == 0xD8) { //mov rax, cr3
			Logger::Log("\033[38;5;46m[Reading]\033[0m CR3 -> Rax\n");
			e->ContextRecord->Rax = cr3;
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x20 && ptrBuffer[2] == 0xDA) { //mov rax, cr3
			Logger::Log("\033[38;5;46m[Reading]\033[0m CR3 -> Rdx\n");
			e->ContextRecord->Rdx = cr3;
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x22 && ptrBuffer[2] == 0xD8) { //mov cr3, rax
			//e->ContextRecord->Rax = 0;
			Logger::Log("\033[38;5;46m[Writing]\033[0m CR3 = %llx\n", e->ContextRecord->Rax);
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x20 && ptrBuffer[2] == 0xC1) {
			Logger::Log("\033[38;5;46m[Reading]\033[0m CR0 into RCX\n");
			e->ContextRecord->Rcx = cr0;
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x20 && ptrBuffer[2] == 0xC7) {
			Logger::Log("\033[38;5;46m[Reading]\033[0m CR0 into RDX\n");
			e->ContextRecord->Rdx = cr0;
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0xFA) { //CLEAR INTERRUPT
			e->ContextRecord->Rip += 1;
			Logger::Log("\033[38;5;46m[Info]\033[0m Clearing interrupt\n");
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0xFB) { //RESTORE INTERRUPT
			e->ContextRecord->Rip += 1;
			Logger::Log("\033[38;5;46m[Info]\033[0m Restoring interrupt\n");
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x23 && ptrBuffer[2] == 0xFE) { //mov dr7, rsi
			Logger::Log("\033[38;5;46m[Writing]\033[0m DR7 = %llx\n", e->ContextRecord->Rsi);
			e->ContextRecord->Dr7 = e->ContextRecord->Rsi;
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x23 && ptrBuffer[2] == 0xF8) { //mov dr7, rsi
			Logger::Log("\033[38;5;46m[Writing]\033[0m DR7 = %llx\n", e->ContextRecord->Rax);
			e->ContextRecord->Dr7 = e->ContextRecord->Rax;
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ptrBuffer[0] == 0x0F && ptrBuffer[1] == 0x23 && ptrBuffer[2] == 0xFB) { //mov dr7, rsi
		Logger::Log("\033[38;5;46m[Writing]\033[0m DR7 = %llx\n", e->ContextRecord->Rbx);
			e->ContextRecord->Dr7 = e->ContextRecord->Rbx;
			e->ContextRecord->Rip += 3;
			return EXCEPTION_CONTINUE_EXECUTION;
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
		switch (e->ExceptionRecord->ExceptionInformation[0])
		{
		case WRITE_VIOLATION:
			Logger::Log("Trying to write, not handled\n");
			exit(0);
			break;

		case READ_VIOLATION:
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

			else if (e->ExceptionRecord->ExceptionInformation[1] >= 0xFFFFF78000000000 && e->ExceptionRecord->
				ExceptionInformation[1] <= 0xFFFFF78000001000)
			{
				auto read_addr = e->ExceptionRecord->ExceptionInformation[1];
				auto offset_shared = read_addr - 0xFFFFF78000000000;
				Logger::Log("\033[38;5;46m[Accessing]\033[0m KUSER_SHARED_DATA + 0x%04x\n", offset_shared);

				setKUSD();

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
					e->ContextRecord->Rax = *(uint32_t*)(fakeKUSER_SHARED_DATA+0x26c);
					e->ContextRecord->Rip += 9;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (bufferopcode[0] == 0x48
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

					e->ContextRecord->Rax = *(uint32_t*)(fakeKUSER_SHARED_DATA + 0x26c);
					e->ContextRecord->Rip += 10;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rsi == read_addr)
				{
					e->ContextRecord->Rsi = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rdx == read_addr)
				{
					e->ContextRecord->Rdx = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rcx == read_addr)
				{
					e->ContextRecord->Rcx = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rax == read_addr)
				{
					e->ContextRecord->Rax = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rbx == read_addr)
				{
					e->ContextRecord->Rbx = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rdi == read_addr)
				{
					e->ContextRecord->Rdi = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rsp == read_addr)
				{
					e->ContextRecord->Rsp = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rbp == read_addr)
				{
					e->ContextRecord->Rbp = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R8 == read_addr)
				{
					e->ContextRecord->R8 = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R9 == read_addr)
				{
					e->ContextRecord->R9 = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R10 == read_addr)
				{
					e->ContextRecord->R10 = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R11 == read_addr)
				{
					e->ContextRecord->R11 = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R12 == read_addr)
				{
					e->ContextRecord->R12 = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R13 == read_addr)
				{
					e->ContextRecord->R13 = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R14 == read_addr)
				{
					e->ContextRecord->R14 = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R15 == read_addr)
				{
					e->ContextRecord->R15 = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rsi == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rsi = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rdx == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rdx = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rcx == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rcx = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rax == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rax = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rbx == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rbx = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rdi == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rdi = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rsp == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rsp = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R8 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R8 = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R9 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R9 = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R10 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R10 = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R11 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R11 = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R12 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R12 = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R13 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R13 = fakeKUSER_SHARED_DATA;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R14 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R14 = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R15 == 0xFFFFF78000000000)
				{
					e->ContextRecord->R15 = fakeKUSER_SHARED_DATA + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rbp == 0xFFFFF78000000000)
				{
					e->ContextRecord->Rbp = fakeKUSER_SHARED_DATA + offset_shared;
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

	MemoryTracker::TrackVariable((uintptr_t)&FakeSystemProcess, sizeof(FakeSystemProcess), (char*)"PID4.EPROCESS");
	MemoryTracker::TrackVariable((uintptr_t)&FakeKernelThread, sizeof(FakeKernelThread), (char*)"PID4.ETHREAD");


	auto result = DriverEntry(&drvObj, RegistryPath);
	Logger::Log("Done! = %llx", result);
	system("pause");
	return 0;
}


extern void Initialize();
extern void InitializeExport();

int main(int argc, char* argv[]) {

	MemoryTracker::Initiate();

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
	LoadModule("c:\\EMU\\ntdll.dll", R"(c:\windows\system32\ntdll.dll)", "ntdll.dll", false);

	//DriverEntry = (proxyCall)LoadModule("c:\\EMU\\faceit.sys", "c:\\EMU\\faceit.sys", "faceit", true);
	//DriverEntry = reinterpret_cast<proxyCall>(LoadModule("c:\\EMU\\EasyAntiCheat_2.sys", "c:\\EMU\\EasyAntiCheat_2.sys", "EAC", true));
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
