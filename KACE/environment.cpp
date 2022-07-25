#include "environment.h"
#include <filesystem>
#include <PEMapper/pefile.h>
#include <Logger/Logger.h>

namespace fs = std::filesystem;

std::unordered_map<uintptr_t, windows_module&> environment_module;

using fnFreeCall = uint64_t(__fastcall*)(...);

template <typename... Params>
static NTSTATUS __NtRoutine(const char* Name, Params&&... params) {
	auto fn = (fnFreeCall)GetProcAddress(GetModuleHandleA("ntdll.dll"), Name);
	return fn(std::forward<Params>(params)...);
}


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	ULONG Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
	ULONG NextOffset;
	RTL_PROCESS_MODULE_INFORMATION BaseInfo;
	ULONG ImageCheckSum;
	ULONG TimeDateStamp;
	PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, * PRTL_PROCESS_MODULE_INFORMATION_EX;

#define IMPORT_MODULE_DIRECTORY "c:\\emu\\"

/*
struct windows_module {
	ULONG Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR FullPathName[256];
	ULONG Checksum;
	ULONG Timestamp;
	PVOID Defaultbase;
	bool overriden;
};

*/
void Environment::InitializeSystemModules() {
	uint64_t len = 0;
	PVOID data = 0;
	auto ret = __NtRoutine("NtQuerySystemInformation", 0x4D, 0, 0, &len);
	if (ret != 0) {
		data = malloc(len);
		memset(data, 0, len);
		ret = __NtRoutine("NtQuerySystemInformation", 0x4D, data, len, &len);
	}
	PRTL_PROCESS_MODULE_INFORMATION_EX pMods = (PRTL_PROCESS_MODULE_INFORMATION_EX)data;
	while (pMods && pMods->NextOffset) {
		if (!strrchr((const char*)pMods->BaseInfo.FullPathName, '\\')) {
			break;
		}
		auto filename = strrchr((const char*)pMods->BaseInfo.FullPathName, '\\')+1;
		windows_module wm = { 0 };
		
		if (fs::exists(std::string(IMPORT_MODULE_DIRECTORY) + filename)) {
			auto pe_file = PEFile::Open(std::string(IMPORT_MODULE_DIRECTORY) + filename, filename);
			wm.Section = pMods->BaseInfo.Section;
			wm.MappedBase = pMods->BaseInfo.MappedBase;
			wm.ImageBase = (PVOID)pe_file->GetMappedImageBase();
			wm.ImageSize = pe_file->GetVirtualSize();
			wm.Flags = pMods->BaseInfo.Flags;
			wm.LoadOrderIndex = pMods->BaseInfo.LoadOrderIndex;
			wm.InitOrderIndex = pMods->BaseInfo.InitOrderIndex;
			wm.LoadCount = pMods->BaseInfo.LoadCount;
			wm.Checksum = pMods->ImageCheckSum;
			wm.Timestamp = pMods->TimeDateStamp;
			wm.Defaultbase = pMods->DefaultBase;
			strcpy(wm.FullPathName, pMods->BaseInfo.FullPathName);
			wm.OffsetToFileName = pMods->BaseInfo.OffsetToFileName;
			wm.overriden = true;

		}
		else {
			wm.Section = pMods->BaseInfo.Section;
			wm.MappedBase = pMods->BaseInfo.MappedBase;
			wm.ImageBase = pMods->BaseInfo.ImageBase;
			wm.ImageSize = pMods->BaseInfo.ImageSize;
			wm.Flags = pMods->BaseInfo.Flags;
			wm.LoadOrderIndex = pMods->BaseInfo.LoadOrderIndex;
			wm.InitOrderIndex = pMods->BaseInfo.InitOrderIndex;
			wm.LoadCount = pMods->BaseInfo.LoadCount;
			wm.Checksum = pMods->ImageCheckSum;
			wm.Timestamp = pMods->TimeDateStamp;
			wm.Defaultbase = pMods->DefaultBase;
			strcpy(wm.FullPathName, pMods->BaseInfo.FullPathName);
			wm.OffsetToFileName = pMods->BaseInfo.OffsetToFileName;
			wm.overriden = false;
		}

		environment_module.insert(std::pair((uintptr_t)wm.ImageBase, wm));
		
		if (pMods->NextOffset != sizeof(_RTL_PROCESS_MODULE_INFORMATION_EX))
			break;
		pMods = (PRTL_PROCESS_MODULE_INFORMATION_EX)((uintptr_t)pMods + pMods->NextOffset);
		
	}

}

void Environment::CheckPtr(uint64_t ptr) {
	for (auto it = environment_module.begin(); it != environment_module.end(); it++) {
		uintptr_t base = (uintptr_t)it->second.ImageBase;

		if (base <= ptr && ptr <= base + it->second.ImageSize) {
			Logger::Log("Trying to access not overriden module : %s at offset %llx\n", it->second.FullPathName, ptr - base);
			DebugBreak();
			break;
		}
	}
	return;
}