#pragma once

#include <cinttypes>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ranges>
#include <string>
#include <unordered_map>
#include <windows.h>

struct ImportData {
    std::string library;
    std::string name;
    uint64_t rva;
};

struct SectionData {
    uint64_t virtual_size;
    uint64_t virtual_address;
    uint64_t raw_size;
    uint64_t raw_address;
    uint64_t characteristics;
};

class PEFile {
private:
    static std::unordered_map<std::string, PEFile*> moduleList_namekey;

    uintmax_t size = 0;
    std::ifstream File;

    template <typename T>
    T makepointer(uint64_t buffer, uint64_t offset) {
        return (T)(buffer + offset);
    }

    template <typename T>
    T makepointer(unsigned char* buffer, uint64_t offset) {
        return (T)(reinterpret_cast<uint64_t>(buffer) + offset);
    }

    std::unordered_map<uint64_t, ImportData> imports_rvakey;
    std::unordered_map<uint64_t, std::string> exports_rvakey;

    std::unordered_map<std::string, ImportData> imports_namekey;
    std::unordered_map<std::string, uint64_t> exports_namekey;

    PIMAGE_DOS_HEADER pDosHeader = 0;
    PIMAGE_NT_HEADERS pNtHeaders = 0;

    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = 0;
    PIMAGE_FILE_HEADER pImageFileHeader = 0;
    PIMAGE_SECTION_HEADER pImageSectionHeader = 0;

    unsigned char* mapped_buffer = 0; //Will be set as NO_ACCESS once mapping is done
    unsigned char* shadow_buffer = 0; //A 1:1 copy of the mapped buffer that will be used for read/write

    uintmax_t virtual_size = 0;
    uintmax_t imagebase = 0;
    uintmax_t entrypoint = 0;

    bool isExecutable = false;

    void ParseHeader();
    void ParseSection();
    void ParseImport();
    void ParseExport();

    PEFile(std::string filename, std::string name, uintmax_t size);

public:
    std::string filename;
    std::string name;

    static std::vector<PEFile*> LoadedModuleArray;

    static PEFile* Open(std::string path, std::string name);
    static PEFile* FindModule(uintptr_t ptr);
    static PEFile* FindModule(std::string name); //find to which module a ptr belongs to.
    static void SetPermission(); //This will prepare the page access for every loaded executable

    std::unordered_map<std::string, SectionData> sections;

    void ResolveImport();

    ImportData* GetImport(std::string name);
    ImportData* GetImport(uint64_t rva);
    uint64_t GetExport(std::string name);
    const char* GetExport(uint64_t rva);
    uint64_t GetVirtualSize();
    uint64_t GetImageBase();
    void CreateShadowBuffer();
    uint64_t GetMappedImageBase();
    uintptr_t GetShadowBuffer();
    uintmax_t GetEP();
    void SetExecutable(bool isExecutable);
    std::unordered_map<uint64_t, std::string> GetAllExports();
};
