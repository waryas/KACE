#include <PEMapper/pefile.h>
#include <Logger/Logger.h>

#include "provider.h"


namespace Provider {
	static std::unordered_map<std::string, PVOID> function_providers;
	static std::unordered_map<std::string, PVOID> passthrough_provider_cache;
	static std::unordered_map<std::string, PVOID> data_providers;
	static std::vector<std::pair<uintptr_t, size_t>> export_data_range;
}

static auto ntdll = LoadLibraryA("ntdll.dll");

uintptr_t Provider::FindFuncImpl(uintptr_t ptr) {
	uintptr_t implPtr = 0;

	auto pe_file = PEFile::FindModule(ptr);
	if (!pe_file)
		DebugBreak();

	auto exported_func = pe_file->GetExport(ptr - pe_file->GetMappedImageBase());
	if (!exported_func)
		DebugBreak();

	if (function_providers.contains(exported_func))
		return (uintptr_t)function_providers[exported_func];

	if (passthrough_provider_cache.contains(exported_func))
		return (uintptr_t)passthrough_provider_cache[exported_func];

	implPtr = (uintptr_t)GetProcAddress(ntdll, exported_func);

	if (!implPtr)
		implPtr = (uintptr_t)unimplemented_stub;

	passthrough_provider_cache.insert(std::pair(exported_func, (PVOID)implPtr));

	return implPtr;
}

uintptr_t Provider::FindDataImpl(uintptr_t ptr) {

	auto pe_file = PEFile::FindModule(ptr);
	if (!pe_file)
		return 0;

	auto exported_func = pe_file->GetExport(ptr - pe_file->GetMappedImageBase());

	if (!exported_func) {
		DebugBreak();
		return 0;
	}


	if (data_providers.contains(exported_func))
		return (uintptr_t)data_providers[exported_func];

	
	Logger::Log("Exported Data %s::%s is not implemented\n", pe_file->name.c_str(), exported_func);
	DebugBreak();
	return 0;

}

uintptr_t Provider::AddFuncImpl(const char* nameFunc, PVOID hookFunc) {
	function_providers.insert(std::pair(nameFunc, hookFunc));
	return 1;
}

uintptr_t Provider::AddDataImpl(const char* nameExport, PVOID hookExport, size_t exportSize) {
	data_providers.insert(std::pair(nameExport, hookExport));
	export_data_range.push_back(std::pair((uintptr_t)hookExport, exportSize));
	return 1;
}

uint64_t Provider::unimplemented_stub() {
	Logger::Log("\t\t\033[38;5;9mINSIDE STUB, RETURNING 0\033[0m\n");
	return 0;
}

