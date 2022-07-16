#pragma once


#include "nt_define.h"
#include "static_export_provider.h"
#include "LIEF/LIEF.hpp"
#include <cstdint>
#include <memory>

#define PAGE_SHIFT              12
#define PAGE_SIZE               (1ULL << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE-1))
#define PAGE_ALIGN(addr)        (((addr)+PAGE_SIZE-1)&PAGE_MASK)

#define PAGE_ALIGN_DOWN(addr) (((addr)) & PAGE_MASK)

#define KB 1024
#define MB 1024 * KB
#define GB 1024 * MB
#define MEMORY_ALLOCATION (1 * MB)

#include <malloc.h>



#define MAX_MODULES 64

template <typename T> T makepointer(uint8_t* buffer, uint64_t offset) {
	return (T)(reinterpret_cast<uint64_t>(buffer) + offset);
}

inline struct ModuleManager {
	const char* name;
	const char* fakepath;
	const char* realpath;
	uintptr_t base;
	uintptr_t size;
	bool isMainModule;
	std::unique_ptr<LIEF::PE::Binary> pedata;
} MappedModules[MAX_MODULES] = { };

inline std::unique_ptr<LIEF::PE::Binary> self_data;

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

inline struct MemoryMapping { //For symbolic tracking, was used in the unicorn version, will redevelop it soon
	char* regionName;
	uintptr_t realMemory;
	uintptr_t guestBase;
	size_t allocSize;
	MemoryMapping* next;
	MemoryMapping* next;
} MemAccess = { 0 };
inline struct HandleManager { //For tracking of handle
	char* handleName;
	HANDLE realHandle;
	HANDLE guestHandle;
	size_t allocSize;
	HandleManager* next;
	HandleManager* next;
} HandleAccess = { 0 };
inline int fsize(FILE* fp)
{
	int prev = ftell(fp);
	fseek(fp, 0L, SEEK_END);
	int sz = ftell(fp);
	fseek(fp, prev, SEEK_SET); //go back to where we were
	return sz;
	fseek(fp, 0L, SEEK_END);
	int sz = ftell(fp);
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

#define	IMAGE_REL_BASED_ABSOLUTE	0 /* The base relocation is skipped.
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

#define	IMAGE_REL_BASED_ABSOLUTE	0 /* The base relocation is skipped.


typedef struct
{
inline void __declspec(noinline) FixSecurityCookie(uint8_t* buffer, uint64_t origBase) {
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeaders;
	pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)buffer + pDosHeader->e_lfanew);
						 This type can be used to pad a
						 block. */


void __declspec(noinline) FixSecurityCookie(uint8_t* buffer, uint64_t origBase) {
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeaders;
	pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)buffer + pDosHeader->e_lfanew);
						 offset. */



void __declspec(noinline) FixSecurityCookie(uint8_t* buffer, uint64_t origBase) {
	PIMAGE_DOS_HEADER			pDosHeader;
inline uint64_t ApplyRelocation(uint8_t* buffer, uint64_t origBase) {
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeaders;
	DWORD64						x;
	DWORD64						dwTmp;
	PIMAGE_BASE_RELOCATION		pBaseReloc;
	PIMAGE_RELOC				pReloc;
	auto iRelocOffset = (uintptr_t)buffer - origBase;
	pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)buffer + pDosHeader->e_lfanew);
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeaders;
	DWORD64						x;
	DWORD64						dwTmp;
	PIMAGE_BASE_RELOCATION		pBaseReloc;
	PIMAGE_RELOC				pReloc;
	auto iRelocOffset = (uintptr_t)buffer - origBase;
	pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)buffer + pDosHeader->e_lfanew);
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeaders;
	DWORD64						x;
	DWORD64						dwTmp;
	PIMAGE_BASE_RELOCATION		pBaseReloc;
	PIMAGE_RELOC				pReloc;
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
                //*((DWORD*)(x + pReloc->offset)) += (DWORD)iRelocOffset;
                break;

            case 1:
                //*((WORD*)(x + pReloc->offset)) += HIWORD(iRelocOffset);
                break;

inline bool FixImport(uint8_t* buffer, uint64_t origBase) {

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pImageNtHeader = makepointer<PIMAGE_NT_HEADERS>(buffer, pDosHeader->e_lfanew);
            default:
                //printf("Unknown relocation type: 0x%08x", pReloc->type);
                break;
            }




bool FixImport(uint8_t* buffer, uint64_t origBase) {

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pImageNtHeader = makepointer<PIMAGE_NT_HEADERS>(buffer, pDosHeader->e_lfanew);
}




bool FixImport(uint8_t* buffer, uint64_t origBase) {

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
                //lpFunction = pfnGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
            } else {
                PIMAGE_IMPORT_BY_NAME pImageImportByName = makepointer<PIMAGE_IMPORT_BY_NAME>(buffer, pOriginalThunk->u1.AddressOfData);
                auto iName = (LPCSTR)&pImageImportByName->Name;

                for (int i = 0; i < MAX_STATIC_EXPORT; i++) {
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
		if (MappedModules[i].base <= ptr && ptr <= MappedModules[i].base + MappedModules[i].size)
			return &MappedModules[i];
inline uint64_t GetModuleBase(const char* name) {
	for (int i = 0; i < MAX_MODULES; i++) {
		if (!MappedModules[i].name)
			return 0;
		if (strstr(MappedModules[i].name, name))
			return MappedModules[i].base;
	}
	return 0;
		if (MappedModules[i].isMainModule)
			return &MappedModules[i];
inline HMODULE ntdll = LoadLibraryA("ntdll.dll");


ModuleManager* GetMainModule() {
inline uintptr_t FindFunctionInModulesFromIAT(uintptr_t ptr) {
	uintptr_t funcptr = 0;
	for (int i = 0; i < MAX_MODULES; i++) {
			return 0;
		if (strstr(MappedModules[i].name, name))
			return MappedModules[i].base;
	}
	return 0;

uint64_t GetModuleBase(const char* name) {



static HMODULE ntdll = LoadLibraryA("ntdll.dll");

	}
	return 0;
uintptr_t FindFunctionInModulesFromIAT(uintptr_t ptr) {
	uintptr_t funcptr = 0;
	for (int i = 0; i < MAX_MODULES; i++) {


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
                            if (!myProvider[k].name)
                                break;
                            if (!_stricmp(myProvider[k].name, entry->name().c_str())) {
                                funcptr = (uintptr_t)myProvider[k].hook;
                                if (funcptr) {
                                    printf("Prototyped\n");
                                } else {
                                    funcptr = (uintptr_t)GetProcAddress(ntdll, entry->name().c_str());
                                    if (funcptr)
                                        printf("/!\\PASSTHROUGH TO NTDLL -UNTESTED- /!\\\n");
                                    else {
using RtlInsertInvertedFunctionTable = int(__fastcall* )(PVOID BaseAddress, ULONG uImageSize);

inline int FixMainModuleSEH() { //Works on WIN 10 21H2 -- Need to find offset for other windows : RtlInsertInvertedFunctionTable in ntdll.dll
	auto ntdllbase = LoadLibraryA("ntdll.dll");
	auto x = GetProcAddress(ntdllbase, "AlpcGetMessageFromCompletionList");
	RtlInsertInvertedFunctionTable rtlinsert = (RtlInsertInvertedFunctionTable)((DWORD64)x - 0x170);
	auto mod = GetMainModule();
                        if (!funcptr) {
                            funcptr = (uintptr_t)GetProcAddress(ntdll, entry->name().c_str());
                            if (funcptr)
                                printf("/!\\PASSTHROUGH TO NTDLL -UNTESTED- /!\\\n");
                            else {
inline uintptr_t SetVariableInModulesEAT(uintptr_t ptr)
{

	for (int i = 0; i < MAX_MODULES; i++) {
                        }

typedef int(__fastcall* RtlInsertInvertedFunctionTable)(PVOID BaseAddress, ULONG uImageSize);


int FixMainModuleSEH() { //Works on WIN 10 21H2 -- Need to find offset for other windows : RtlInsertInvertedFunctionTable in ntdll.dll
	auto ntdllbase = LoadLibraryA("ntdll.dll");
	auto x = GetProcAddress(ntdllbase, "AlpcGetMessageFromCompletionList");
	RtlInsertInvertedFunctionTable rtlinsert = (RtlInsertInvertedFunctionTable)((DWORD64)x - 0x170);
	auto mod = GetMainModule();
				for (auto function = funcs.cbegin(); function < funcs.cend(); function++) {
					if (function->address() == offset) {
						printf("Reading %s::%s - ", MappedModules[i].name, function->name().c_str());
						for (int k = 0; k < std::size(staticExportProvider); k++) {
							if (!staticExportProvider[k].name)
								break;
							if (!_stricmp(staticExportProvider[k].name, function->name().c_str())) {
								DWORD oldAccess;
								VirtualProtect((LPVOID)ptr, 1, PAGE_READWRITE, &oldAccess);
								*(uint64_t*)ptr = *(uint64_t*)staticExportProvider[k].ptr;
								VirtualProtect((LPVOID)ptr, 1, oldAccess, &oldAccess);
							}
						}
						break;
					}
					
				}

			}
		}
	}
					if (function->address() == offset) {
						printf("Reading %s::%s - ", MappedModules[i].name, function->name().c_str());
						for (int k = 0; k < NELEMS(staticExportProvider); k++) {
							if (!staticExportProvider[k].name)
inline uintptr_t FindFunctionInModulesFromEAT(uintptr_t ptr) {

								DWORD oldAccess;
	uintptr_t funcptr = 0;
	for (int i = 0; i < MAX_MODULES; i++) {
								VirtualProtect((LPVOID)ptr, 1, oldAccess, &oldAccess);
							}
						}
						break;
					}
					
				}

			}
		}
	}
						}
					if (function->address() == offset) {
						printf("Resolving %s::%s - ", MappedModules[i].name, function->name().c_str());
						for (int k = 0; k < std::size(myProvider); k++) {
							if (!myProvider[k].name)
								break;
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
								}
								return funcptr;
							}
						}
inline void HookSelf(char* path) {
	if (!path) {
		printf("HookSelf wrong parameters\n");
		exit(0);
	}
								printf("Needs to be prototyped\n");
								return 0;
							}
							return funcptr;
						}

					}
				}

inline uintptr_t LoadModule(const char* path, const char* spoofedpath, const char* name, bool isMainModule) {
	uintptr_t ep = 0;
	if (!path || !spoofedpath || !name) {
		printf("LoadModule wrong parameters\n");
		exit(0);
	}
	bool loaded = false;

	for (int i = 0; i < MAX_MODULES; ++i) {
		if (MappedModules[i].name)
			continue;
		exit(0);
	}
    return 0;
}


void HookSelf(char* path) {
	if (!path) {
		printf("HookSelf wrong parameters\n");
		exit(0);
	}
uintptr_t LoadModule(const char* path, const char* spoofedpath, const char* name, bool isMainModule) {
	uintptr_t ep = 0;
	if (!path || !spoofedpath || !name) {

		uint8_t* image_to_execute = (uint8_t*)malloc(image_size);
	}
	bool loaded = false;
}
	for (int i = 0; i < MAX_MODULES; i++) {
		if (MappedModules[i].name)
			continue;
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

		image_to_execute = (uint8_t*)malloc(image_size);
        MappedModules[i].isMainModule = isMainModule;

        MappedModules[i].pedata = LIEF::PE::Parser::parse(MappedModules[i].realpath);

        f = fopen(MappedModules[i].realpath, "rb+");
        image_size = fsize(f);


		image_to_execute = (uint8_t*)malloc(image_size);

        fread(image_to_execute, 1, image_size, f);
        fclose(f);

        MappedModules[i].base = (uintptr_t)_aligned_malloc(MappedModules[i].pedata->virtual_size(), 0x10000);
        MappedModules[i].size = MappedModules[i].pedata->virtual_size();
        memset((PVOID)MappedModules[i].base, 0, MappedModules[i].size); //Important, space should be padded with 0
			auto funcs = MappedModules[i].pedata->exported_functions();
			for (auto function = funcs.cbegin(); function < funcs.cend(); ++function) {
				//
				for (auto section = pe_sections.cbegin(); section < pe_sections.cend(); ++section) {
					if (section->virtual_address() <= function->address() && function->address() <= section->virtual_address() + section->virtual_size()
						&& !(section->characteristics() & 0x20000000)) {
						
						DWORD oldAccess;
						VirtualProtect((PVOID)PAGE_ALIGN_DOWN(MappedModules[i].base + function->address()), 0x1000, PAGE_READONLY | PAGE_GUARD, &oldAccess);
					}
				}
			}
            DWORD oldAccess;

            if (MappedModules[i].isMainModule)
                VirtualProtect((PVOID)(MappedModules[i].base + section->virtual_address()), sectionSize, PAGE_EXECUTE_READWRITE, &oldAccess);
            else {
#ifdef MONITOR_ACCESS
                VirtualProtect((PVOID)(MappedModules[i].base + section->virtual_address()), sectionSize, PAGE_READONLY | PAGE_GUARD, &oldAccess);
#else
                VirtualProtect((PVOID)(MappedModules[i].base + section->virtual_address()), sectionSize, PAGE_READONLY, &oldAccess);
#endif
			auto funcs = MappedModules[i].pedata->exported_functions();
			for (auto function = funcs.cbegin(); function < funcs.cend(); function++) {
				//
				for (auto section = pe_sections.cbegin(); section < pe_sections.cend(); section++) {
					if (section->virtual_address() <= function->address() && function->address() <= section->virtual_address() + section->virtual_size()
						&& !(section->characteristics() & 0x20000000)) {
						
						DWORD oldAccess;
						VirtualProtect((PVOID)PAGE_ALIGN_DOWN(MappedModules[i].base + function->address()), 0x1000, PAGE_READONLY | PAGE_GUARD, &oldAccess);
					}
				}
			}
				for (auto section = pe_sections.cbegin(); section < pe_sections.cend(); section++) {
					if (section->virtual_address() <= function->address() && function->address() <= section->virtual_address() + section->virtual_size()
						&& !(section->characteristics() & 0x20000000)) {
						
	if (!ep) {
		printf("Entry point is 0, incorrect\n");
		exit(0);
	}
	return ep;
}            /* USE THIS TO DUMP EXPORTED VARIABLE FROM KERNEL
			auto funcs = MappedModules[i].pedata->exported_functions();
			for (auto function = funcs.cbegin(); function < funcs.cend(); function++) {
				//
				for (auto section = pe_sections.cbegin(); section < pe_sections.cend(); section++) {
					if (section->virtual_address() <= function->address() && function->address() <= section->virtual_address() + section->virtual_size()
						&& !(section->characteristics() & 0x20000000)) {
						printf("DbgPrint(\"%s - %%d bytes - %%llx\",sizeof(%s), *(uint64_t*)%s )\n", function->name().c_str(), function->name().c_str(), function->name().c_str());
					}
				}
			}
			*/
        }

        free(image_to_execute);
        loaded = true;
	if (!ep) {
		printf("Entry point is 0, incorrect\n");
		exit(0);
	}
	return ep;
}


	if (!ep) {
		printf("Entry point is 0, incorrect\n");
		exit(0);
	}
	return ep;
}


