#include <iostream>
#include <assert.h>

#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "nt_define.h"

#include "LIEF/LIEF.hpp"

#include "nmd.h"

#include "memory_layout.h"

#include "ntoskrnl_struct.h"
#include "ntoskrnl_provider.h"

#pragma comment(lib,"E:\\src\\safe_capcom-master\\lib\\LIEF.lib")

typedef uint64_t(__fastcall* proxyCall)(...);
proxyCall DriverEntry = (proxyCall)0x0;



_DRIVER_OBJECT drvObj = { 0 };
UNICODE_STRING RegistryPath = { 0 };



#define READ_VIOLATION 0
#define EXECUTE_VIOLATION 8

uint64_t passthrough(...) {
	return 0;
}


//POC STAGE, NEED TO MAKE THIS DYNAMIC - Most performance issue come from this, also for some reason i only got this to work in Visual studio, not outside of it.

LONG MyExceptionHandler(EXCEPTION_POINTERS* e) {
	uintptr_t ep = (uintptr_t)e->ExceptionRecord->ExceptionAddress;
	auto offset = ep - db;
	DWORD64 base;
	//printf("%llx - %llx\n", ep - db, ep - kb);
	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION) {
		auto ptr = *(uint32_t*)ep;
		//printf("%08x\n", ptr);
		if (ptr == 0xc0200f44) { // mov rax, cr8
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
	else if (e->ExceptionRecord->ExceptionCode = EXCEPTION_ACCESS_VIOLATION) {
		uint8_t* bufferopcode = (uint8_t*)e->ContextRecord->Rip;
		auto addr_access = e->ExceptionRecord->ExceptionInformation[1];
		switch (e->ExceptionRecord->ExceptionInformation[0]) {
		case READ_VIOLATION:

			if (e->ExceptionRecord->ExceptionInformation[1] >= 0xFFFFF78000000000 && e->ExceptionRecord->ExceptionInformation[1] <= 0xFFFFF78000001000) {
				auto read_addr = e->ExceptionRecord->ExceptionInformation[1];
				auto offset_shared = read_addr - 0xFFFFF78000000000;
				
				if (e->ContextRecord->Rsi == read_addr) {
					e->ContextRecord->Rsi = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rdx == read_addr) {
					e->ContextRecord->Rdx = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rcx == read_addr) {
					e->ContextRecord->Rcx = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rax == read_addr) {
					e->ContextRecord->Rax = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rbx == read_addr) {
					e->ContextRecord->Rbx = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->Rsp == read_addr) {
					e->ContextRecord->Rsp = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R8 == read_addr) {
					e->ContextRecord->R8 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R9 == read_addr) {
					e->ContextRecord->R9 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R10 == read_addr) {
					e->ContextRecord->R10 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R11 == read_addr) {
					e->ContextRecord->R11 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R12 == read_addr) {
					e->ContextRecord->R12 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R13 == read_addr) {
					e->ContextRecord->R13 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R14 == read_addr) {
					e->ContextRecord->R14 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				if (e->ContextRecord->R15 == read_addr) {
					e->ContextRecord->R15 = 0x7FFE0000 + offset_shared;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				
			}
			if (e->ContextRecord->Rsi == (DWORD64)0xfffff78000000014) {
				if (bufferopcode[0] == 0x48 && bufferopcode[1] == 0x8B && bufferopcode[2] == 0x06) {
					e->ContextRecord->Rsi = 0x7FFE0014;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
			}
			else if (e->ContextRecord->Rdx == (DWORD64)0xfffff78000000014) {
				if (bufferopcode[0] == 0x4c && bufferopcode[1] == 0x8B && bufferopcode[2] == 0x12) {
					e->ContextRecord->Rdx = 0x7FFE0014;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
			}
			else if (offset == 0x5ff83a && e->ContextRecord->Rax == 0xFFFFF78000000014) {
				e->ContextRecord->Rdx = *(uint64_t*)0x7FFE0014;
				e->ContextRecord->Rip += 3;
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
				&& bufferopcode[8] == 0xff) { //A1 6C 02 00 00 80 F7 FF FF
				e->ContextRecord->Rax = *(uint32_t*)0x7FFE026c;
				e->ContextRecord->Rip += 9;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else {
				auto pe_imports = driver->imports();

				for (auto imports = pe_imports.cbegin(); imports < pe_imports.cend(); imports++) {
					for (auto entry = imports->entries().cbegin(); entry < imports->entries().cend(); entry++) {
						if (entry->iat_value() == addr_access) {

							printf("Binary is trying to read : %s\n", entry->name().c_str());
							if (strstr(entry->name().c_str(), "MmSystemRangeStart")) {
								e->ContextRecord->Rcx = 0x7FF000000000;
								e->ContextRecord->Rip += 3;
								return EXCEPTION_CONTINUE_EXECUTION;
							}
							else {
								return EXCEPTION_NONCONTINUABLE;
								printf("Function is not prototyped - Cannot continue\n");
							}

						}
					}
				}
			}
			break;
		case EXECUTE_VIOLATION:
			if (ep >= kb) { //ntoskrnl direct execution!
				offset = ep - kb;
				funcs = ntoskrnl->exported_functions();
				for (auto function = funcs.cbegin(); function < funcs.cend(); function++) {
					//printf("%llx - %llx", function->address(), offset);
					if (function->address() == offset) {
						printf("Trying to execute %s\n", function->name().c_str());
						for (int k = 0; k < NELEMS(myProvider); k++) {
							if (!_stricmp(myProvider[k].name, function->name().c_str())) {

								e->ContextRecord->Rip = (DWORD64)myProvider[k].hook;
								if (e->ContextRecord->Rip == 0) {
									e->ContextRecord->Rip = (DWORD64)&passthrough;
								}
								return EXCEPTION_CONTINUE_EXECUTION;

							}
						}
						printf("Function not prototyped\n");
						return EXCEPTION_NONCONTINUABLE;
					}
				}
			}
			else { //IAT Execution

				auto pe_imports = driver->imports();

				for (auto imports = pe_imports.cbegin(); imports < pe_imports.cend(); imports++) {
					for (auto entry = imports->entries().cbegin(); entry < imports->entries().cend(); entry++) {
						if (entry->iat_value() == e->ContextRecord->Rip) {
							printf("Binary is calling : %s\n", entry->name().c_str());
							for (int k = 0; k < NELEMS(myProvider); k++) {
								if (!_stricmp(entry->name().c_str(), myProvider[k].name)) {
									e->ContextRecord->Rip = (DWORD64)myProvider[k].hook;
									if (e->ContextRecord->Rip == 0) {
										e->ContextRecord->Rip = (DWORD64)&passthrough;
									}
									return EXCEPTION_CONTINUE_EXECUTION;
								}
							}
							printf("Function is not prototyped - Cannot continue\n");
							return EXCEPTION_NONCONTINUABLE;
						}
					}
				}
			}
			break;
		}


	}

	return 0;
}
typedef int(__fastcall* RtlInsertInvertedFunctionTable)(PVOID BaseAddress, ULONG uImageSize);

UNICODE_STRING Derp = { 0 };
struct stuff {
	uint64_t pad[4] = { 0 };
};
stuff padding = { {0,0,0,0} };

const wchar_t* randomStr = L"LOLOLOL\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
int fakeDriverEntry() {

	uintptr_t RVApdata = *(uint32_t*)(db + 0x180);
	uintptr_t pdataSize = *(uint32_t*)(db + 0x184);

	auto ntdllbase = LoadLibraryA("ntdll.dll");
	auto x = GetProcAddress(ntdllbase, "AlpcGetMessageFromCompletionList");
	RtlInsertInvertedFunctionTable rtlinsert = (RtlInsertInvertedFunctionTable)((DWORD64)x - 0x170);

	auto ret = rtlinsert((PVOID)db, driver->virtual_size());

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
	FakeSystemProcess.WoW64Process = 0;
	FakeSystemProcess.CreateTime.QuadPart = GetTickCount64();

	DriverEntry(&drvObj, &RegistryPath);
	printf("Done!\n");
	return 0;

}
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

#define	IMAGE_REL_BASED_ABSOLUTE	0 /* The base relocation is skipped.
						 This type can be used to pad a
						 block. */
#define IMAGE_REL_BASED_HIGHLOW		3 /* The base relocation applies all
						 32 bits of the difference to the
						 32-bit field at offset. */
#define IMAGE_REL_BASED_DIR64	       10 /* The base relocation applies the
						 difference to the 64-bit field at
						 offset. */

uint64_t ApplyRelocation(uint8_t* buffer, uint64_t origBase) {
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeaders;
	DWORD64						x;
	DWORD64						dwTmp;
	PIMAGE_BASE_RELOCATION		pBaseReloc;
	PIMAGE_RELOC				pReloc;
	auto iRelocOffset = (uintptr_t)buffer - origBase;
	pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)buffer + pDosHeader->e_lfanew);


	pBaseReloc = (PIMAGE_BASE_RELOCATION)
		((uintptr_t)buffer +
			pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (pBaseReloc->SizeOfBlock) {
		x = (uintptr_t)buffer + pBaseReloc->VirtualAddress;
		dwTmp = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
		pReloc = (PIMAGE_RELOC)(((DWORD64)pBaseReloc) + sizeof(IMAGE_BASE_RELOCATION));

		while (dwTmp--) {
			switch (pReloc->type) {
			case IMAGE_REL_BASED_DIR64:
				*((UINT_PTR*)(x + pReloc->offset)) += iRelocOffset;
				break;

			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				//*((DWORD*)(x + pReloc->offset)) += (DWORD)iRelocOffset;
				break;

			case 1:
				//*((WORD*)(x + pReloc->offset)) += HIWORD(iRelocOffset);
				break;

			case 2:
				//*((WORD*)(x + pReloc->offset)) += LOWORD(iRelocOffset);
				break;

			default:
				//printf("Unknown relocation type: 0x%08x", pReloc->type);
				break;
			}

			pReloc += 1;
		}

		pBaseReloc = (PIMAGE_BASE_RELOCATION)(((DWORD64)pBaseReloc) + pBaseReloc->SizeOfBlock);
	}



	return 1;
}

template <typename T> T makepointer(uint8_t* buffer, uint64_t offset) {
	return (T)((uint64_t)buffer + offset);
}

bool FixImport(uint8_t* buffer, uint64_t origBase) {

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pImageNtHeader = makepointer<PIMAGE_NT_HEADERS>(buffer, pDosHeader->e_lfanew);


	if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
		pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
		return true;

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = makepointer<PIMAGE_IMPORT_DESCRIPTOR>(buffer, pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


	for (; pImageImportDescriptor->Name; pImageImportDescriptor++) {

		PCHAR pDllName = makepointer<PCHAR>(buffer, pImageImportDescriptor->Name);

		HMODULE hMod = 0;

		if (strstr(pDllName, "ntoskrnl.exe")) {
			hMod = (HMODULE)kb;
		}
		else if (strstr(pDllName, "cng.sys")) {
			hMod = (HMODULE)cngb;
		}
		else if (strstr(pDllName, "FLTMGR.SYS")) {
			hMod = (HMODULE)fltb;
		}
		else {
			printf("Not supported import : %s\n", pDllName);
			exit(0);
		}




		// Original thunk
		PIMAGE_THUNK_DATA pOriginalThunk = NULL;
		if (pImageImportDescriptor->OriginalFirstThunk)
			pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(buffer, pImageImportDescriptor->OriginalFirstThunk);
		else
			pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(buffer, pImageImportDescriptor->FirstThunk);

		// IAT thunk
		PIMAGE_THUNK_DATA pIATThunk = makepointer<PIMAGE_THUNK_DATA>(buffer, pImageImportDescriptor->FirstThunk);

		for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++) {
			FARPROC lpFunction = NULL;
			if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
				//lpFunction = pfnGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
			}
			else {
				PIMAGE_IMPORT_BY_NAME pImageImportByName = makepointer<PIMAGE_IMPORT_BY_NAME>(buffer, pOriginalThunk->u1.AddressOfData);
				auto iName = (LPCSTR)&pImageImportByName->Name;
				if (!strcmp(iName, "SeExports")) {
					InitSeExport();
					pIATThunk->u1.Function = (uintptr_t)&SeExport;
				}
				else if (!strcmp(iName, "PsLookupThreadByThreadId")) {
					//pIATThunk->u1.Function = 0;
				}

				//lpFunction = pfnGetProcAddress(hMod, (LPCSTR) & (pImageImportByName->Name));
			}

			//pIATThunk->u1.Function = (ULONGLONG)lpFunction;
			//printf("OAT : AddressOfData : %llx - ForwarderString : %llx - Function : %llx - Ordinal : %llx\n", pOriginalThunk->u1.AddressOfData, pOriginalThunk->u1.ForwarderString, pOriginalThunk->u1.Function, pOriginalThunk->u1.Ordinal);

			//pIATThunk->u1.AddressOfData += (uint64_t)dm;
			//printf("IAT : ddressOfData : %llx - ForwarderString : %llx - Function : %llx - Ordinal : %llx\n", pIATThunk->u1.AddressOfData, pIATThunk->u1.ForwarderString, pIATThunk->u1.Function, pIATThunk->u1.Ordinal);
		}
	}
	//exit(0);
	return true;

}
uint64_t LoadPE(const char* file, bool isMainModule) {

	auto pe_binary = LIEF::PE::Parser::parse(file);
	FILE* f = fopen(file, "rb+");
	auto image_size = fsize(f);
	auto pe_sections = pe_binary->sections();



	image_to_execute = (uint8_t*)malloc(image_size);
	fread(image_to_execute, 1, image_size, f);
	fclose(f);



	if (isMainModule)
		driver = LIEF::PE::Parser::parse(file);
	else {
		if (strstr(file, "ntoskrnl.exe")) {
			ntoskrnl = LIEF::PE::Parser::parse(file);
		}
		else if (strstr(file, "cng.sys")) {
			cng_pe = LIEF::PE::Parser::parse(file);
		}
		else if (strstr(file, "fltmgr.sys")) {
			fltmgr_pe = LIEF::PE::Parser::parse(file);
		}
		else {
			exit(0);
		}
	}
	uint8_t* base = 0;

	if (isMainModule)
		base = Mapped_Driver;
	else if (strstr(file, "ntoskrnl.exe")) {
		base = Kernel_Image;
	}
	else if (strstr(file, "cng.sys")) {
		base = Cng_Image;
	}
	else if (strstr(file, "fltmgr.sys")) {
		base = Flt_Image;
	}
	else {
		exit(0);
	}


	memcpy(base, image_to_execute, 0x1000);


	for (auto section = pe_sections.cbegin(); section < pe_sections.cend(); section++) {

		auto sectionSize = PAGE_ALIGN(section->virtual_size());
		auto sectionRawSize = section->size();



		memset(base + section->virtual_address(), 0, sectionSize);
		memcpy(base + section->virtual_address(), image_to_execute + section->offset(), sectionRawSize);

		uint64_t success = 0;
		DWORD oldAccess;
		if (isMainModule) {

			auto ret = VirtualProtect(base + section->virtual_address(), sectionSize, PAGE_EXECUTE_READWRITE, &oldAccess);
			printf("%x - %x for %s\n", ret, GetLastError(), section->name().c_str());


		}
		else {
			VirtualProtect(base + section->virtual_address(), sectionSize, PAGE_READONLY, &oldAccess);
		}
	}

	free(image_to_execute);
	if (isMainModule) {
		ApplyRelocation(base, pe_binary->imagebase());
		FixImport(base, pe_binary->imagebase());
	}
	return (uint64_t)base + pe_binary->optional_header().addressof_entrypoint();
}

int main() {
	LoadPE("c:\\EMU\\ntoskrnl.exe", false);
	LoadPE("c:\\EMU\\cng.sys", false);
	LoadPE("c:\\EMU\\fltmgr.sys", false);

	//DriverEntry = (proxyCall)LoadPE("c:\\EMU\\EasyAntiCheat_2.sys", true);
	DriverEntry = (proxyCall)LoadPE("c:\\EMU\\VGK.sys", true);
	//DriverEntry = (proxyCall)LoadPE("C:\\Users\\Generic\\source\\repos\\KMDF Driver2\\x64\\Release\\KMDFDriver2.sys", true);

	//DriverEntry = (proxyCall)((uintptr_t)db + 0x11B0);

	CreateThread(0, 4096, (LPTHREAD_START_ROUTINE)fakeDriverEntry, 0, 0, 0);
	printf("Loaded entrypoint at : %llx (%llx)\n", DriverEntry, (uint64_t)DriverEntry - (uint64_t)Mapped_Driver);
	while (1) {
		Sleep(1000);
	}
	return 0;
}