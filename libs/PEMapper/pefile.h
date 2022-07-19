#pragma once

#include <windows.h>
#include <string>
#include <cinttypes>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <filesystem>


typedef struct
{
    WORD	offset : 12;
    WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

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
    std::string filename;
    uintmax_t size = 0;
    std::ifstream File;

    template <typename T>
    T makepointer(uint64_t buffer, uint64_t offset) {
        return (T)(buffer + offset);
    }

    template <typename T>
    T makepointer(char* buffer, uint64_t offset) {
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


    char* filebuffer = 0;
    char* mapped_buffer = 0;
    uintmax_t virtual_size = 0;
    uintmax_t imagebase = 0;
    uintmax_t entrypoint = 0;

    void ParseHeader();
    void ParseSection();
    void RelocationFix();
    void ParseImport();
    void ParseExport();
    PEFile(std::string filename, uintmax_t size);

public:
    static PEFile* Open(std::string path) {
        auto size = std::filesystem::file_size(path);

        if (size) {
            return new PEFile(path, size);
        }
        else {
            return 0;
        }
    }

    std::unordered_map<std::string, SectionData> sections;

    ImportData* GetImport(std::string name);
    ImportData* GetImport(uint64_t rva);
    uint64_t GetExport(std::string name);
    const char* GetExport(uint64_t rva);
    uint64_t GetVirtualSize();
    uint64_t GetImageBase();
    uintmax_t GetEP();
    std::unordered_map<uint64_t, std::string> GetAllExports();
    ~PEFile();


};





