#pragma once

#include "nt_define.h"
#include "static_export_provider.h"
#include <PEMapper/pefile.h>
#include <Logger/Logger.h>
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

void __declspec(noinline) FixSecurityCookie(uint8_t* buffer, uint64_t origBase);

uint64_t ApplyRelocation(uint8_t* buffer, uint64_t origBase);

bool FixImport(uint8_t* buffer, uint64_t origBase);

ModuleManager* FindModule(uintptr_t ptr);

ModuleManager* GetMainModule();
uint64_t GetModuleBase(const char* name);




uintptr_t FindFunctionInModulesFromIAT(uintptr_t ptr);


using RtlInsertInvertedFunctionTable = int(__fastcall*)(PVOID BaseAddress, ULONG uImageSize);

int FixMainModuleSEH();

uintptr_t SetVariableInModulesEAT(uintptr_t ptr);
uintptr_t FindFunctionInModulesFromEAT(uintptr_t ptr);

void HookSelf(char* path);

uintptr_t LoadModule(const char* path, const char* spoofedpath, const char* name, bool isMainModule);