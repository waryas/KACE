#pragma once

#define PAGE_SHIFT              12
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE-1))
#define PAGE_ALIGN(addr)        (((addr)+PAGE_SIZE-1)&PAGE_MASK)

#define KB 1024
#define MB 1024 * KB
#define GB 1024 * MB
#define MEMORY_ALLOCATION 1 * MB


#include <malloc.h>

#define MAX_MODULES 64

template <typename T> T makepointer(uint8_t* buffer, uint64_t offset) {
	return (T)((uint64_t)buffer + offset);
}

struct ModuleManager {
	const char* name;
	const char* fakepath;
	const char* realpath;
	uintptr_t base;
	bool isMainModule;
	std::unique_ptr<LIEF::PE::Binary> pedata;
} MappedModules[MAX_MODULES] = { 0 };



enum TYPE_ARGUMENT {
	TINT8 = 0x0,
	TINT16 = 0x1,
	TINT32 = 0x2,
	TINT64 = 0x3,
	TBUFFER = 0x4,
	TCSTRING = 0x5,
	TWSTRING = 0x6,
	TUNICODESTRING = 0x7
};


struct ArgumentPrototype {
	const char* name;
	TYPE_ARGUMENT type; //Actually wasn't needed, will probably remove this
	uint64_t value;

};
struct FunctionPrototype {
	const char* name;
	uint8_t argumentCount; //Used for unicorn version
	void* hook;
	ArgumentPrototype args[15];
};

struct MemoryMapping { //For symbolic tracking, was used in the unicorn version, will redevelop it soon
	char* regionName;
	uintptr_t realMemory;
	uintptr_t guestBase;
	size_t allocSize;
	MemoryMapping* next;
} MemAccess = { 0 };

struct HandleManager { //For tracking of handle
	char* handleName;
	HANDLE realHandle;
	HANDLE guestHandle;
	size_t allocSize;
	HandleManager* next;
} HandleAccess = { 0 };


uint8_t* image_to_execute = nullptr;


#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))


int fsize(FILE* fp) {
	int prev = ftell(fp);
	fseek(fp, 0L, SEEK_END);
	int sz = ftell(fp);
	fseek(fp, prev, SEEK_SET); //go back to where we were
	return sz;
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




#undef SeLoadDriverPrivilege;

typedef struct _SE_EXPORTS_NTOS {

	LUID    SeCreateTokenPrivilege;
	LUID    SeAssignPrimaryTokenPrivilege;
	LUID    SeLockMemoryPrivilege;
	LUID    SeIncreaseQuotaPrivilege;
	LUID    SeUnsolicitedInputPrivilege;
	LUID    SeTcbPrivilege;
	LUID    SeSecurityPrivilege;
	LUID    SeTakeOwnershipPrivilege;
	LUID    SeLoadDriverPrivilege;
	LUID    SeCreatePagefilePrivilege;
	LUID    SeIncreaseBasePriorityPrivilege;
	LUID    SeSystemProfilePrivilege;
	LUID    SeSystemtimePrivilege;
	LUID    SeProfileSingleProcessPrivilege;
	LUID    SeCreatePermanentPrivilege;
	LUID    SeBackupPrivilege;
	LUID    SeRestorePrivilege;
	LUID    SeShutdownPrivilege;
	LUID    SeDebugPrivilege;
	LUID    SeAuditPrivilege;
	LUID    SeSystemEnvironmentPrivilege;
	LUID    SeChangeNotifyPrivilege;
	LUID    SeRemoteShutdownPrivilege;


	PSID  SeNullSid;
	PSID  SeWorldSid;
	PSID  SeLocalSid;
	PSID  SeCreatorOwnerSid;
	PSID  SeCreatorGroupSid;

	PSID  SeNtAuthoritySid;
	PSID  SeDialupSid;
	PSID  SeNetworkSid;
	PSID  SeBatchSid;
	PSID  SeInteractiveSid;
	PSID  SeLocalSystemSid;
	PSID  SeAliasAdminsSid;
	PSID  SeAliasUsersSid;
	PSID  SeAliasGuestsSid;
	PSID  SeAliasPowerUsersSid;
	PSID  SeAliasAccountOpsSid;
	PSID  SeAliasSystemOpsSid;
	PSID  SeAliasPrintOpsSid;
	PSID  SeAliasBackupOpsSid;

	PSID  SeAuthenticatedUsersSid;

	PSID  SeRestrictedSid;
	PSID  SeAnonymousLogonSid;

	LUID  SeUndockPrivilege;
	LUID  SeSyncAgentPrivilege;
	LUID  SeEnableDelegationPrivilege;


	PSID  SeLocalServiceSid;
	PSID  SeNetworkServiceSid;

	LUID  SeManageVolumePrivilege;
	LUID  SeImpersonatePrivilege;
	LUID  SeCreateGlobalPrivilege;



	LUID  SeTrustedCredManAccessPrivilege;
	LUID  SeRelabelPrivilege;
	LUID  SeIncreaseWorkingSetPrivilege;

	LUID  SeTimeZonePrivilege;
	LUID  SeCreateSymbolicLinkPrivilege;


	PSID  SeIUserSid;


	PSID SeUntrustedMandatorySid;
	PSID SeLowMandatorySid;
	PSID SeMediumMandatorySid;
	PSID SeHighMandatorySid;
	PSID SeSystemMandatorySid;

	PSID SeOwnerRightsSid;

	

	PSID SeAllAppPackagesSid;
	PSID SeUserModeDriversSid;

	
	PSID SeProcTrustWinTcbSid;

	

	PSID SeTrustedInstallerSid;

	LUID  SeDelegateSessionUserImpersonatePrivilege;

} SE_EXPORTS_NTOS, * PSE_EXPORTS_NTOS;

#define SeLoadDriverPrivilege 10ull;
SE_EXPORTS_NTOS SeExportNtos = { 0 };


void InitSeExport() {
	//Dump from 21H2 win10
	auto Buffer = "\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x06"
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
	memcpy(&SeExportNtos, Buffer, sizeof(SeExportNtos));

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
					pIATThunk->u1.Function = (uintptr_t)&SeExportNtos;
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

ModuleManager* GetMainModule() {
	for (int i = 0; i < MAX_MODULES; i++) {
		if (!MappedModules[i].name)
			return 0;
		if (MappedModules[i].isMainModule)
			return &MappedModules[i];
	}
	return 0;
}

uint64_t GetModuleBase(const char* name) {
	for (int i = 0; i < MAX_MODULES; i++) {
		if (!MappedModules[i].name)
			return 0;
		if (strstr(MappedModules[i].name, name))
			return MappedModules[i].base;
	}
	return 0;
}



static HMODULE ntdll = LoadLibraryA("ntdll.dll");

extern FunctionPrototype myProvider[512];

uintptr_t FindFunctionInModulesFromIAT(uintptr_t ptr) {
	uintptr_t funcptr = 0;
	for (int i = 0; i < MAX_MODULES; i++) {

		if (!MappedModules[i].name)
			return 0;

		if (MappedModules[i].isMainModule) {

			auto pe_imports = MappedModules[i].pedata->imports();

			for (auto imports = pe_imports.cbegin(); imports < pe_imports.cend(); imports++) {
				for (auto entry = imports->entries().cbegin(); entry < imports->entries().cend(); entry++) {
					
					if (entry->iat_value() == ptr) {
						printf("Resolving %s::%s - ", imports->name().c_str(), entry->name().c_str());
						for (int k = 0; k < 512; k++) {
							if (!_stricmp(myProvider[k].name, entry->name().c_str())) {
								funcptr = (uintptr_t)myProvider[k].hook;
								if (funcptr) {
									printf("Prototyped\n");
								}
								else {
									funcptr = (uintptr_t)GetProcAddress(ntdll, entry->name().c_str());
									if (funcptr)
										printf("/!\\PASSTHROUGH TO NTDLL -UNTESTED- /!\\\n");
									else {
										printf("Needs to be prototyped\n");
										return 0;
									}
								}
								return funcptr;
							}
						}
						if (!funcptr) {
							funcptr = (uintptr_t)GetProcAddress(ntdll, entry->name().c_str());
							if (funcptr)
								printf("/!\\PASSTHROUGH TO NTDLL -UNTESTED- /!\\\n");
							else {
								printf("Needs to be prototyped\n");
								return 0;
							}
							return funcptr;
						}
					}
				}
			}


		}
	}

	return 0;
}


typedef int(__fastcall* RtlInsertInvertedFunctionTable)(PVOID BaseAddress, ULONG uImageSize);


int FixMainModuleSEH() { //Works on WIN 10 21H2 -- Need to find offset for other windows : RtlInsertInvertedFunctionTable in ntdll.dll
	auto ntdllbase = LoadLibraryA("ntdll.dll");
	auto x = GetProcAddress(ntdllbase, "AlpcGetMessageFromCompletionList");
	RtlInsertInvertedFunctionTable rtlinsert = (RtlInsertInvertedFunctionTable)((DWORD64)x - 0x170);
	auto mod = GetMainModule();

	auto ret = rtlinsert((PVOID)mod->base, mod->pedata->virtual_size());
	return ret;
}

uintptr_t FindFunctionInModulesFromEAT(uintptr_t ptr) {


	uintptr_t funcptr = 0;
	for (int i = 0; i < MAX_MODULES; i++) {

		if (!MappedModules[i].name)
			return 0;

		if (!MappedModules[i].isMainModule) {
			if (MappedModules[i].base <= ptr && ptr <= MappedModules[i].base + MappedModules[i].pedata->virtual_size()) {

				auto offset = ptr - MappedModules[i].base;
				auto funcs = MappedModules[i].pedata->exported_functions();

				for (auto function = funcs.cbegin(); function < funcs.cend(); function++) {

					if (function->address() == offset) {
						printf("Resolving %s::%s - ", MappedModules[i].name, function->name().c_str());
						for (int k = 0; k < NELEMS(myProvider); k++) {
							if (!_stricmp(myProvider[k].name, function->name().c_str())) {
								funcptr = (uintptr_t)myProvider[k].hook;
								if (funcptr) {
									printf("Prototyped\n");
								}
								else {
									funcptr = (uintptr_t)GetProcAddress(ntdll, function->name().c_str());
									if (funcptr)
										printf("/!\\PASSTHROUGH TO NTDLL -UNTESTED- /!\\\n");
									else {
										printf("Needs to be prototyped\n");
										return 0;
									}
								}
								return funcptr;
							}
						}
						if (!funcptr) {
							funcptr = (uintptr_t)GetProcAddress(ntdll, function->name().c_str());
							if (funcptr)
								printf("/!\\PASSTHROUGH TO NTDLL -UNTESTED- /!\\\n");
							else {
								printf("Needs to be prototyped\n");
								return 0;
							}
							return funcptr;
						}

					}
				}

			}
		}
	}

	return 0;
}

uintptr_t LoadModule(const char* path, const char* spoofedpath, const char* name, bool isMainModule) {
	uintptr_t ep = 0;
	if (!path || !spoofedpath || !name) {
		printf("LoadModule wrong parameters\n");
		exit(0);
	}
	bool loaded = false;

	for (int i = 0; i < MAX_MODULES; i++) {
		if (MappedModules[i].name)
			continue;

		FILE* f = 0;
		int image_size = 0;

		MappedModules[i].name = name;
		MappedModules[i].fakepath = spoofedpath;
		MappedModules[i].realpath = path;
		MappedModules[i].isMainModule = isMainModule;

		MappedModules[i].pedata = LIEF::PE::Parser::parse(MappedModules[i].realpath);

		f = fopen(MappedModules[i].realpath, "rb+");
		image_size = fsize(f);


		image_to_execute = (uint8_t*)malloc(image_size);

		fread(image_to_execute, 1, image_size, f);
		fclose(f);

		MappedModules[i].base = (uintptr_t)_aligned_malloc(MappedModules[i].pedata->virtual_size(), 0x10000);

		memset((PVOID)MappedModules[i].base, 0, MappedModules[i].pedata->virtual_size()); //Important, space should be padded with 0
		memcpy((PVOID)MappedModules[i].base, image_to_execute, 0x1000);

		auto pe_sections = MappedModules[i].pedata->sections();

		for (auto section = pe_sections.cbegin(); section < pe_sections.cend(); section++) {

			auto sectionSize = PAGE_ALIGN(section->virtual_size());
			auto sectionRawSize = section->size();

			memset((PVOID)(MappedModules[i].base + section->virtual_address()), 0, sectionSize);
			memcpy((PVOID)(MappedModules[i].base + section->virtual_address()), image_to_execute + section->offset(), sectionRawSize);

			DWORD oldAccess;

			if (MappedModules[i].isMainModule)
				VirtualProtect((PVOID)(MappedModules[i].base + section->virtual_address()), sectionSize, PAGE_EXECUTE_READWRITE, &oldAccess);
			else
				VirtualProtect((PVOID)(MappedModules[i].base + section->virtual_address()), sectionSize, PAGE_READONLY, &oldAccess);
		}


		if (MappedModules[i].isMainModule) {
			ApplyRelocation((uint8_t*)MappedModules[i].base, MappedModules[i].pedata->imagebase());
			FixImport((uint8_t*)MappedModules[i].base, MappedModules[i].pedata->imagebase());
		}

		free(image_to_execute);
		loaded = true;

		ep = MappedModules[i].base + MappedModules[i].pedata->optional_header().addressof_entrypoint();
		break;

	}
	if (!loaded) {
		printf("MAX_MODULES OVERLOAD\n");
		exit(0);
	}

	if (!ep) {
		printf("Entry point is 0, incorrect\n");
		exit(0);
	}
	return ep;
}


