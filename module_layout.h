#pragma once

#include "nt_define.h"
#include "static_export_provider.h"
#include "libs/PEMapper/pefile.h"
#include "libs/Logger/Logger.h"
#include "provider.h"
#include <cstdint>
#include <memory>
#include <malloc.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & PAGE_MASK)

#define PAGE_ALIGN_DOWN(addr) (((addr)) & PAGE_MASK)

#define KB 1024
#define MB 1024 * KB
#define GB 1024 * MB
#define MEMORY_ALLOCATION (1 * MB)



#define MAX_MODULES 64

extern const char* prototypedMsg;
extern const char* passthroughMsg;
extern const char* notimplementedMsg;



template <typename T>
T makepointer(uint8_t* buffer, uint64_t offset) {
	return (T)(reinterpret_cast<uint64_t>(buffer) + offset);
}

inline struct ModuleManager {
	const char* name;
	const char* fakepath;
	const char* realpath;
	uintptr_t base;
	uintptr_t size;
	bool isMainModule;
	PEFile* pedata;
} MappedModules[MAX_MODULES] = {};

inline PEFile* self_data;

enum TYPE_ARGUMENT
{
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

struct ConstantFunctionPrototype {
	uint8_t argumentCount; //Used for unicorn version
	void* hook;
	ArgumentPrototype args[15];
};

inline struct MemoryMapping { //For symbolic tracking, was used in the unicorn version, will redevelop it soon
	char* regionName;
	uintptr_t realMemory;
	uintptr_t guestBase;
	size_t allocSize;
	MemoryMapping* next;
} MemAccess = { 0 };

inline struct HandleManager { //For tracking of handle
	char* handleName;
	HANDLE realHandle;
	HANDLE guestHandle;
	size_t allocSize;
	HandleManager* next;
} HandleAccess = { 0 };

inline int fsize(FILE* fp) {
	int prev = ftell(fp);
	fseek(fp, 0L, SEEK_END);
	int sz = ftell(fp);
	fseek(fp, prev, SEEK_SET); //go back to where we were
	return sz;
}

extern std::unordered_map<std::string, ConstantFunctionPrototype> myConstantProvider;



#define IMAGE_REL_BASED_ABSOLUTE                                                                                                                          \
    0 /* The base relocation is skipped.
						 This type can be used to pad a
						 block. */
#define IMAGE_REL_BASED_HIGHLOW                                                                                                                           \
    3 /* The base relocation applies all
						 32 bits of the difference to the
						 32-bit field at offset. */
#define IMAGE_REL_BASED_DIR64                                                                                                                             \
    10 /* The base relocation applies the
						 difference to the 64-bit field at
						 offset. */

inline void __declspec(noinline) FixSecurityCookie(uint8_t* buffer, uint64_t origBase) {
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)buffer + pDosHeader->e_lfanew);

	auto load_cfg_dir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	if (load_cfg_dir.Size == 0 || load_cfg_dir.VirtualAddress == 0)
		return;
	auto load_cfg = (IMAGE_LOAD_CONFIG_DIRECTORY64*)((uintptr_t)buffer + load_cfg_dir.VirtualAddress);
	UINT64 cookie_va;
	if ((cookie_va = static_cast<UINT64>(load_cfg->SecurityCookie)) == 0)
		return;

	uint64_t* cookie = (uint64_t*)load_cfg->SecurityCookie;
	*cookie ^= GetTickCount64();

	return;
}

inline uint64_t ApplyRelocation(uint8_t* buffer, uint64_t origBase) {
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	DWORD64 x;
	DWORD64 dwTmp;
	PIMAGE_BASE_RELOCATION pBaseReloc;
	PIMAGE_RELOC pReloc;
	auto iRelocOffset = (uintptr_t)buffer - origBase;
	pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)buffer + pDosHeader->e_lfanew);

	pBaseReloc = (PIMAGE_BASE_RELOCATION)((uintptr_t)buffer + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
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
				*((DWORD*)(x + pReloc->offset)) += (DWORD)iRelocOffset;
				break;

			case 1:
				*((WORD*)(x + pReloc->offset)) += HIWORD(iRelocOffset);
				break;

			case 2:
				*((WORD*)(x + pReloc->offset)) += LOWORD(iRelocOffset);
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

inline bool FixImport(uint8_t* buffer, uint64_t origBase) {

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pImageNtHeader = makepointer<PIMAGE_NT_HEADERS>(buffer, pDosHeader->e_lfanew);

	if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0
		|| pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
		return true;

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor
		= makepointer<PIMAGE_IMPORT_DESCRIPTOR>(buffer, pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

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

			}
			else {
				PIMAGE_IMPORT_BY_NAME pImageImportByName = makepointer<PIMAGE_IMPORT_BY_NAME>(buffer, pOriginalThunk->u1.AddressOfData);
				auto iName = (LPCSTR)&pImageImportByName->Name;
				if (constantTimeExportProvider.contains(iName)) {
					pIATThunk->u1.Function = (uintptr_t)constantTimeExportProvider[iName];
				}

			}
		}
	}

	return true;
}

inline ModuleManager* FindModule(uintptr_t ptr) {
	for (int i = 0; i < MAX_MODULES; i++) {
		if (!MappedModules[i].name)
			return 0;
		if (MappedModules[i].base <= ptr && ptr <= MappedModules[i].base + MappedModules[i].size)
			return &MappedModules[i];
	}
	return 0;
}

inline ModuleManager* GetMainModule() {
	for (int i = 0; i < MAX_MODULES; i++) {
		if (!MappedModules[i].name)
			return 0;
		if (MappedModules[i].isMainModule)
			return &MappedModules[i];
	}
	return 0;
}

inline uint64_t GetModuleBase(const char* name) {
	for (int i = 0; i < MAX_MODULES; i++) {
		if (!MappedModules[i].name)
			return 0;
		if (!_stricmp(MappedModules[i].name, name))
			return MappedModules[i].base;
	}
	return 0;
}

inline HMODULE ntdll = LoadLibraryA("ntdll.dll");


inline uintptr_t FindFunctionInModulesFromIAT(uintptr_t ptr) {
	uintptr_t funcptr = 0;

	for (int i = 0; i < MAX_MODULES; i++) {

		if (!MappedModules[i].name)
			return 0;

		if (MappedModules[i].isMainModule) {
			auto Import = MappedModules[i].pedata->GetImport(ptr);
			if (Import) { //Found in IAT
				Logger::Log("\033[38;5;14m[Executing]\033[0m %s::%s - ", Import->library.c_str(), Import->name.c_str());
				if (myConstantProvider.contains(Import->name)) {
					funcptr = (uintptr_t)myConstantProvider[Import->name].hook;
					if (funcptr) {
						Logger::Log(prototypedMsg);
						return funcptr;
					}
				}
				funcptr = (uintptr_t)GetProcAddress(ntdll, Import->name.c_str());
				if (funcptr) {
					Logger::Log(passthroughMsg);
					return funcptr;
				}
				Logger::Log(notimplementedMsg);
				return 0;
			}
			else { //Not Found in IAT
				Logger::Log("Contact Waryas; Should never get to here.");
				exit(0);
			}
			break;
		}
	}
	return 0;
}

__forceinline uint64_t find_pattern(uint64_t start, size_t size, const uint8_t* binary, size_t len) 
{
    size_t bin_len = len;
    auto memory = (const uint8_t*)(start);

    for (size_t cur_offset = 0; cur_offset < (size - bin_len); cur_offset++) 
	{
        auto has_match = true;
        for (size_t pos_offset = 0; pos_offset < bin_len; pos_offset++) 
		{
            if (binary[pos_offset] != 0 && memory[cur_offset + pos_offset] != binary[pos_offset]) 
			{
                has_match = false;
                break;
            }
        }

        if (has_match) 
            return start + cur_offset;
    }

    return 0;
}

using RtlInsertInvertedFunctionTable = int(__fastcall*)(PVOID BaseAddress, ULONG uImageSize);

inline int FixMainModuleSEH() { //Works on WIN 10 21H2 -- Need to find offset for other windows : RtlInsertInvertedFunctionTable in ntdll.dll
	auto ntdllbase = LoadLibraryA("ntdll.dll");

	uint8_t rtlSig[] = "\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x30\x8B\xDA";
    auto rtlinsert = (RtlInsertInvertedFunctionTable)find_pattern((uint64_t)ntdllbase, 0x100000, rtlSig, sizeof(rtlSig) - 1);
    
	auto mod = GetMainModule();

	auto ret = rtlinsert((PVOID)mod->base, mod->size);
	return ret;
}

inline uintptr_t SetVariableInModulesEAT(uintptr_t ptr) {

	for (int i = 0; i < MAX_MODULES; i++) {

		if (!MappedModules[i].name)
			return 0;
		
		if (!MappedModules[i].isMainModule) {
			if (MappedModules[i].base <= ptr && ptr <= MappedModules[i].base + MappedModules[i].size) {

				auto offset = ptr - MappedModules[i].base;
				auto variableName = MappedModules[i].pedata->GetExport(offset);

				if (!variableName) {
					Logger::Log("Reading a non exported value|");
					return 0;
				}
				else {
					Logger::Log("\033[38;5;46m[Reading]\033[0m %s::%s - ", MappedModules[i].name, variableName);
					if (constantTimeExportProvider.contains(variableName)) {
						Logger::Log(prototypedMsg);
						DWORD oldAccess;
						DWORD oldAccess2;
						VirtualProtect((LPVOID)constantTimeExportProvider[variableName], 1, PAGE_READWRITE, &oldAccess);
						VirtualProtect((LPVOID)ptr, 1, PAGE_READWRITE, &oldAccess2);
						*(uint64_t*)ptr = *(uintptr_t*)constantTimeExportProvider[variableName];
						VirtualProtect((LPVOID)ptr, 1, oldAccess2, &oldAccess2);
						VirtualProtect((LPVOID)constantTimeExportProvider[variableName], 1, oldAccess, &oldAccess);
					}
					else {
						Logger::Log(notimplementedMsg);
						//exit(0);
					}
				}
			}
		}
	}

	return 0;
}

inline uintptr_t FindFunctionInModulesFromEAT(uintptr_t ptr) {

	uintptr_t funcptr = 0;
	for (int i = 0; i < MAX_MODULES; i++) {

		if (!MappedModules[i].name)
			return 0;

		if (!MappedModules[i].isMainModule) {
			if (MappedModules[i].base <= ptr && ptr <= MappedModules[i].base + MappedModules[i].size) {

				auto offset = ptr - MappedModules[i].base;
				auto functionName = MappedModules[i].pedata->GetExport(offset);

				if (!functionName) {
					Logger::Log("Executing a non exported function\n");
					exit(0);
				}
				else {
					Logger::Log("\033[38;5;14m[Executing]\033[0m %s::%s - ", MappedModules[i].name, functionName);
					if (myConstantProvider.contains(functionName)) {
						funcptr = (uintptr_t)myConstantProvider[functionName].hook;
						if (funcptr) {
							Logger::Log(prototypedMsg);
							return funcptr;
						}
					}
					funcptr = (uintptr_t)GetProcAddress(ntdll, functionName);
					if (funcptr) {
						Logger::Log(passthroughMsg);
						return funcptr;
					}
					Logger::Log(notimplementedMsg);
					return 0;
				}
			}
		}
	}
	return 0;
}

inline void HookSelf(char* path) {
	if (!path) {
		Logger::Log("HookSelf wrong parameters\n");
		exit(0);
	}

	self_data = PEFile::Open(path);

	DWORD oldProtect;
	auto hookPage = PAGE_ALIGN_DOWN((uintptr_t)&InitSafeBootMode); //BEGINNING OF MONITOR SECTION

	VirtualProtect((PVOID)hookPage, 0x1000, PAGE_READONLY | PAGE_GUARD, &oldProtect);
	return;
}

inline uintptr_t LoadModule(const char* path, const char* spoofedpath, const char* name, bool isMainModule) {
	uintptr_t ep = 0;
	if (!path || !spoofedpath || !name) {
		Logger::Log("LoadModule wrong parameters\n");
		exit(0);
	}
	bool loaded = false;

	if (isMainModule) {
		Logger::Log("Loading %s\n", name);
	}

	for (int i = 0; i < MAX_MODULES; ++i) {
		if (MappedModules[i].name)
			continue;

		FILE* f = 0;
		int image_size = 0;

		MappedModules[i].name = name;
		MappedModules[i].fakepath = spoofedpath;
		MappedModules[i].realpath = path;
		MappedModules[i].isMainModule = isMainModule;

		MappedModules[i].pedata = PEFile::Open(MappedModules[i].realpath);

		f = fopen(MappedModules[i].realpath, "rb+");
		image_size = fsize(f);

		uint8_t* image_to_execute = (uint8_t*)malloc(image_size);

		fread(image_to_execute, 1, image_size, f);
		fclose(f);

		MappedModules[i].base = (uintptr_t)_aligned_malloc(MappedModules[i].pedata->GetVirtualSize(), 0x10000);
		MappedModules[i].size = MappedModules[i].pedata->GetVirtualSize();
		memset((PVOID)MappedModules[i].base, 0, MappedModules[i].size); //Important, space should be padded with 0
		memcpy((PVOID)MappedModules[i].base, image_to_execute, 0x1000);


		auto section = MappedModules[i].pedata->sections.begin();
		while (section != MappedModules[i].pedata->sections.end()) {
			DWORD oldAccess;
			auto SectionName = section->first;
			auto SectionData = section->second;
			auto sectionSize = PAGE_ALIGN(SectionData.virtual_size);
			auto sectionRawSize = SectionData.raw_size;

			memset((PVOID)(MappedModules[i].base + SectionData.virtual_address), 0, sectionSize);
			memcpy((PVOID)(MappedModules[i].base + SectionData.virtual_address), image_to_execute + SectionData.raw_address, sectionRawSize);

			VirtualProtect((PVOID)(MappedModules[i].base + SectionData.virtual_address), sectionSize, PAGE_EXECUTE_READWRITE, &oldAccess);

			section++;
		}



		if (MappedModules[i].isMainModule) {
			ApplyRelocation((uint8_t*)MappedModules[i].base, MappedModules[i].pedata->GetImageBase());
			FixImport((uint8_t*)MappedModules[i].base, MappedModules[i].pedata->GetImageBase());
			FixSecurityCookie((uint8_t*)MappedModules[i].base, MappedModules[i].pedata->GetImageBase());
		}
		else { 
			//ApplyRelocation((uint8_t*)MappedModules[i].base, MappedModules[i].pedata->GetImageBase()); //Crashing ATM need to investigate
			//FixSecurityCookie((uint8_t*)MappedModules[i].base, MappedModules[i].pedata->GetImageBase());


		}
		section = MappedModules[i].pedata->sections.begin();

		while (section != MappedModules[i].pedata->sections.end()) {
			DWORD oldAccess;
			auto SectionName = section->first;
			auto SectionData = section->second;
			auto sectionSize = PAGE_ALIGN(SectionData.virtual_size);
			auto sectionRawSize = SectionData.raw_size;

			if (MappedModules[i].isMainModule) {
				VirtualProtect((PVOID)(MappedModules[i].base + SectionData.virtual_address), sectionSize, PAGE_EXECUTE_READWRITE, &oldAccess);
				if (SectionName == ".data") {
#if defined(MONITOR_DATA_ACCESS)
					VirtualProtect((PVOID)(MappedModules[i].base + SectionData.virtual_address), sectionSize, PAGE_READWRITE | PAGE_GUARD, &oldAccess);
#endif
				}
			}
			else {


#ifdef MONITOR_ACCESS
				VirtualProtect((PVOID)(MappedModules[i].base + SectionData.virtual_address), sectionSize, PAGE_READONLY | PAGE_GUARD, &oldAccess);
#elif defined(MONITOR_DATA_ACCESS)
				if (SectionName != ".text") {
					VirtualProtect((PVOID)(MappedModules[i].base + SectionData.virtual_address), sectionSize, PAGE_READONLY | PAGE_GUARD, &oldAccess);
				}
				else {
					VirtualProtect((PVOID)(MappedModules[i].base + SectionData.virtual_address), sectionSize, PAGE_READONLY, &oldAccess);
				}

#else
				VirtualProtect((PVOID)(MappedModules[i].base + SectionData.virtual_address), sectionSize, PAGE_READONLY, &oldAccess);
#endif
			}

			section++;
		}

		if (!MappedModules[i].isMainModule) { //PAGE_GUARD EXPORTED VARIABLE || Ideally USE PDB for non exported variable access too
			auto AllExports = MappedModules[i].pedata->GetAllExports();

			auto exports = AllExports.begin();

			while (exports != AllExports.end()) {
				auto funcPtr = exports->first;
				auto section = MappedModules[i].pedata->sections.begin();

				while (section != MappedModules[i].pedata->sections.end()) {
					auto sectionName = section->first;
					auto sectionData = section->second;

					if ((sectionData.virtual_address <= funcPtr) &&
						(funcPtr <= sectionData.virtual_address + sectionData.virtual_size) &&
						!(sectionData.characteristics & 0x20000000)) {
						DWORD oldAccess;
						VirtualProtect((PVOID)PAGE_ALIGN_DOWN(MappedModules[i].base + funcPtr), 0x1, PAGE_READONLY | PAGE_GUARD, &oldAccess);
					}

					section++;
				}
				exports++;
			}
		}

		free(image_to_execute);
		loaded = true;

		ep = MappedModules[i].base + MappedModules[i].pedata->GetEP();
		break;
	}
	if (!loaded) {
		Logger::Log("MAX_MODULES OVERLOAD\n");
		exit(0);
	}

	if (!ep) {
		Logger::Log("Entry point is 0, incorrect\n");
		exit(0);
	}
	return ep;
}