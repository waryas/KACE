#include "pefile.h"
#include <Logger/Logger.h>
#include <SymParser\symparser.hpp>

#define IMPORT_MODULE_DIRECTORY "c:\\emu\\"

std::unordered_map<std::string, PEFile*> PEFile::moduleList_namekey;
std::vector<PEFile*> PEFile::LoadedModuleArray;

PEFile* PEFile::FindModule(uintptr_t ptr) {
    for (int i = 0; i < LoadedModuleArray.size(); i++)
        if (LoadedModuleArray[i]->GetMappedImageBase() <= ptr
            && ptr <= LoadedModuleArray[i]->GetMappedImageBase() + LoadedModuleArray[i]->GetVirtualSize())
            return LoadedModuleArray[i];
    return 0;
}

PEFile* PEFile::FindModule(std::string name) {

    for (auto& c : name)
        c = tolower(c);

    if (moduleList_namekey.contains(name)) {
        return moduleList_namekey[name];
    }
    return 0;
}

void PEFile::ParseHeader() {

    pDosHeader = (PIMAGE_DOS_HEADER)mapped_buffer;
    pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)mapped_buffer + pDosHeader->e_lfanew);
    pOptionalHeader = &pNtHeaders->OptionalHeader;
    pImageFileHeader = &pNtHeaders->FileHeader;
    pImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)pImageFileHeader + sizeof(IMAGE_FILE_HEADER) + pImageFileHeader->SizeOfOptionalHeader);

    virtual_size = pOptionalHeader->SizeOfImage;
    imagebase = pOptionalHeader->ImageBase;
    entrypoint = pOptionalHeader->AddressOfEntryPoint;
}

void PEFile::ParseSection() {

    sections.clear();

    for (int i = 0; i < pImageFileHeader->NumberOfSections; i++) {

        char name[9] = { 0 };
        strncpy_s(name, (char*)pImageSectionHeader[i].Name, 8);

        SectionData data = { 0 };

        data.characteristics = pImageSectionHeader[i].Characteristics;
        data.virtual_address = pImageSectionHeader[i].VirtualAddress;
        data.virtual_size = pImageSectionHeader[i].Misc.VirtualSize;
        data.raw_size = pImageSectionHeader[i].SizeOfRawData;
        data.raw_address = pImageSectionHeader[i].PointerToRawData;

        while (sections.contains(std::string(name))) {
            name[strlen(name) - 1] = name[strlen(name) - 1] + 1;
        }

        sections.insert(std::pair(std::string(name), data));
    }
}

void PEFile::ParseImport() {
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0
        || pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
        return;

    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor
        = makepointer<PIMAGE_IMPORT_DESCRIPTOR>(mapped_buffer, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; pImageImportDescriptor->Name; pImageImportDescriptor++) {

        PCHAR pDllName = makepointer<PCHAR>(mapped_buffer, pImageImportDescriptor->Name);

        // Original thunk
        PIMAGE_THUNK_DATA pOriginalThunk = NULL;
        if (pImageImportDescriptor->OriginalFirstThunk)
            pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->OriginalFirstThunk);
        else
            pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);

        // IAT thunk
        PIMAGE_THUNK_DATA pIATThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);

        for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++) {
            FARPROC lpFunction = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {

            } else {
                ImportData id;
                PIMAGE_IMPORT_BY_NAME pImageImportByName = makepointer<PIMAGE_IMPORT_BY_NAME>(mapped_buffer, pOriginalThunk->u1.AddressOfData);

                id.library = pDllName;
                id.name = pImageImportByName->Name;
                id.rva = pIATThunk->u1.Function;

                imports_rvakey.insert(std::pair(id.rva, id));
                imports_namekey.insert(std::pair(id.name, id));
            }
        }
    }
}

void PEFile::ParseExport() {

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0
        || pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
        return;

    PIMAGE_EXPORT_DIRECTORY pImageExportDescriptor
        = makepointer<PIMAGE_EXPORT_DIRECTORY>(mapped_buffer, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImageExportDescriptor->NumberOfNames || !pImageExportDescriptor->NumberOfNames || !pImageExportDescriptor->AddressOfFunctions)
        return;
    PDWORD fAddr = (PDWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfNames);
    PWORD fOrd = (PWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImageExportDescriptor->NumberOfNames; i++) {
        LPSTR pFuncName = (LPSTR)((LPBYTE)mapped_buffer + fNames[i]);
        if (pFuncName && fOrd[i]) {
            exports_namekey.insert(std::pair(pFuncName, fAddr[fOrd[i]]));
            exports_rvakey.insert(std::pair(fAddr[fOrd[i]], pFuncName));
        }
    }
}

PEFile::PEFile(std::string filename, std::string name, uintmax_t size) {
    if (size) {

        mapped_buffer = (unsigned char*)LoadLibraryExA(filename.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (mapped_buffer) {

            this->isExecutable = false;
            this->filename = filename;
            this->name = name;

            ParseHeader();
            ParseSection();
            ParseImport();
            ParseExport();
        }
    }
}

void PEFile::ResolveImport() {

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0
        || pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
        return;

    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor
        = makepointer<PIMAGE_IMPORT_DESCRIPTOR>(mapped_buffer, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; pImageImportDescriptor->Name; pImageImportDescriptor++) {

        PCHAR pDllName = makepointer<PCHAR>(mapped_buffer, pImageImportDescriptor->Name);

        PEFile* importModule = nullptr;
        char tmpName[256] = { 0 };
        strcpy_s(tmpName, pDllName);
        for (int nl = 0; nl < strlen(tmpName); nl++)
            tmpName[nl] = tolower(tmpName[nl]);
        if (!moduleList_namekey.contains(tmpName)) {
            Logger::Log("Loading %s...\n", pDllName);
            importModule = PEFile::Open(std::string(IMPORT_MODULE_DIRECTORY) + pDllName, pDllName);
        } else {
            importModule = moduleList_namekey[tmpName];
        }
        auto modulebase = importModule->GetMappedImageBase();
        PIMAGE_THUNK_DATA pOriginalThunk = NULL;
        if (pImageImportDescriptor->OriginalFirstThunk)
            pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->OriginalFirstThunk);
        else
            pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);

        PIMAGE_THUNK_DATA pIATThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);
        DWORD oldProtect = 0;
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery(pIATThunk, &mbi, sizeof(mbi));
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect);
        for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++) {
            FARPROC lpFunction = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
                DebugBreak();
            } else {

                PIMAGE_IMPORT_BY_NAME pImageImportByName = makepointer<PIMAGE_IMPORT_BY_NAME>(mapped_buffer, pOriginalThunk->u1.AddressOfData);
                pIATThunk->u1.Function = modulebase + importModule->GetExport(pImageImportByName->Name);
                //Logger::Log("Resolved %s::%s to %llx\n", pDllName, pImageImportByName->Name, pIATThunk->u1.Function);
            }
        }
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
    }
}

uint64_t PEFile::GetImageBase() { return imagebase; }

uint64_t PEFile::GetMappedImageBase() { return (uint64_t)mapped_buffer; }

uint64_t PEFile::GetVirtualSize() { return virtual_size; }

ImportData* PEFile::GetImport(std::string name) {

    if (imports_namekey.contains(name)) {
        return &imports_namekey[name];
    }
    return 0;
}

ImportData* PEFile::GetImport(uint64_t rva) {

    if (imports_rvakey.contains(rva)) {
        return &imports_rvakey[rva];
    }
    return 0;
}

uint64_t PEFile::GetExport(std::string name) {
    if (name.empty())
        return 0;
    if (exports_namekey.contains(name)) {
        return exports_namekey[name];
    }
    return 0;
}

const char* PEFile::GetExport(uint64_t rva) {

    if (exports_rvakey.contains(rva)) {
        return exports_rvakey[rva].c_str();
    }
    return 0;
}

std::unordered_map<uint64_t, std::string> PEFile::GetAllExports() { return exports_rvakey; }

uintmax_t PEFile::GetEP() { return entrypoint; }

__forceinline uint64_t find_pattern(uint64_t start, size_t size, const uint8_t* binary, size_t len) {
    size_t bin_len = len;
    auto memory = (const uint8_t*)(start);

    for (size_t cur_offset = 0; cur_offset < (size - bin_len); cur_offset++) {
        auto has_match = true;
        for (size_t pos_offset = 0; pos_offset < bin_len; pos_offset++) {
            if (binary[pos_offset] != 0 && memory[cur_offset + pos_offset] != binary[pos_offset]) {
                has_match = false;
                break;
            }
        }

        if (has_match)
            return start + cur_offset;
    }

    return 0;
}

using RtlInsertInvertedFunctionTable = int(__fastcall*)(PVOID BaseAddress, uintmax_t uImageSize);

void PEFile::SetExecutable(bool isExecutable) {
    this->isExecutable = isExecutable;
    auto sym = symparser::find_symbol("c:\\Windows\\System32\\ntdll.dll", "RtlInsertInvertedFunctionTable");
    if (!sym || !sym->rva)
        __debugbreak();
    auto rtlinsert = reinterpret_cast<RtlInsertInvertedFunctionTable>((uint64_t)LoadLibraryA("ntdll.dll") + sym->rva);
    rtlinsert(mapped_buffer, virtual_size);
}

void PEFile::CreateShadowBuffer() {
    //MEMORY_BASIC_INFORMATION mbi;
    DWORD oldProtect = 0;
    shadow_buffer = (unsigned char*)_aligned_malloc(this->GetVirtualSize(), 0x10000);
    memcpy(shadow_buffer, mapped_buffer, this->GetVirtualSize());
    auto sections = this->sections;
    for (auto section = sections.begin(); section != sections.end(); section++) {
        auto sectionName = section->first;
        auto sectionData = section->second;
        if (sectionData.characteristics & 0x80000000 || sectionData.characteristics & 0x40000000) {
            if (sectionName != ".edata") {
                Logger::Log("Hooking READ/WRITE %s of %s\n", sectionName.c_str(), this->name.c_str());
                VirtualProtect(mapped_buffer + sectionData.virtual_address, sectionData.virtual_size, PAGE_NOACCESS, &oldProtect);
            }
        }

        if ((sectionData.characteristics & 0x20000000) || (sectionData.characteristics & 0x00000020)) {
            Logger::Log("Hooking EXECUTE %s of %s\n", sectionName.c_str(), this->name.c_str());
            VirtualProtect(mapped_buffer + sectionData.virtual_address, sectionData.virtual_size, PAGE_READONLY, &oldProtect);
        }
    }

    //Logger::Log("%llx\n", result);
}

uintptr_t PEFile::GetShadowBuffer() { return (uintptr_t)shadow_buffer; }
void PEFile::SetPermission() {
    for (int i = 0; i < LoadedModuleArray.size(); i++) {
        if (!LoadedModuleArray[i]->isExecutable) {
            LoadedModuleArray[i]->CreateShadowBuffer();
        }
    }
}

PEFile* PEFile::Open(std::string path, std::string name) {
    auto size = std::filesystem::file_size(path);

    if (size) {
        auto loadedModule = new PEFile(path, name, size);
        loadedModule->isExecutable = false;
        LoadedModuleArray.push_back(loadedModule);

        for (auto& c : name)
            c = tolower(c);

        moduleList_namekey.insert(std::pair(name, loadedModule));

        return loadedModule;

    } else {
        return 0;
    }
}