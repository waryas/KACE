#pragma once

#include <windows.h>
#include <string>
#include <cinttypes>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <filesystem>


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

    inline void ParseHeader();
    inline void ParseSection();
    inline void RelocationFix();
    inline void ParseImport();
    inline void ParseExport();
    inline PEFile(std::string filename, uintmax_t size);

public:
    inline static PEFile* Open(std::string path) {
        auto size = std::filesystem::file_size(path);

        if (size) {
            return new PEFile(path, size);
        }
        else {
            return 0;
        }
    }

    std::unordered_map<std::string, SectionData> sections;

    inline ImportData* GetImport(std::string name);
    inline ImportData* GetImport(uint64_t rva);
    inline uint64_t GetExport(std::string name);
    inline const char* GetExport(uint64_t rva);
    inline uint64_t GetVirtualSize();
    inline uint64_t GetImageBase();
    inline uintmax_t GetEP();
    inline std::unordered_map<uint64_t, std::string> GetAllExports();
    ~PEFile();


};


inline void PEFile::ParseHeader() {


	pDosHeader = (PIMAGE_DOS_HEADER)filebuffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)filebuffer + pDosHeader->e_lfanew);
	pOptionalHeader = &pNtHeaders->OptionalHeader;
	pImageFileHeader = &pNtHeaders->FileHeader;
	pImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)pImageFileHeader + sizeof(IMAGE_FILE_HEADER) + pImageFileHeader->SizeOfOptionalHeader);

	mapped_buffer = (char*)malloc(pOptionalHeader->SizeOfImage);
	memset(mapped_buffer, 0, pOptionalHeader->SizeOfImage);
	memcpy(mapped_buffer, filebuffer, pOptionalHeader->SizeOfHeaders);

	pDosHeader = (PIMAGE_DOS_HEADER)mapped_buffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)mapped_buffer + pDosHeader->e_lfanew);
	pOptionalHeader = &pNtHeaders->OptionalHeader;
	pImageFileHeader = &pNtHeaders->FileHeader;
	pImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)pImageFileHeader + sizeof(IMAGE_FILE_HEADER) + pImageFileHeader->SizeOfOptionalHeader);
	virtual_size = pOptionalHeader->SizeOfImage;
	imagebase = pOptionalHeader->ImageBase;
	entrypoint = pOptionalHeader->AddressOfEntryPoint;
}

inline void PEFile::ParseSection() {

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
		memcpy(mapped_buffer + data.virtual_address, filebuffer + data.raw_address, data.raw_size);
		while (sections.contains(std::string(name))) {
			name[strlen(name) - 1] = name[strlen(name) - 1] +1;

		}
		sections.insert(std::pair(std::string(name), data));

	}

}

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

inline void PEFile::RelocationFix() {

	DWORD64 x;
	DWORD64 dwTmp;
	PIMAGE_BASE_RELOCATION pBaseReloc;
	PIMAGE_RELOC pReloc;
	auto iRelocOffset = (uintptr_t)mapped_buffer - pOptionalHeader->ImageBase;
	pBaseReloc = (PIMAGE_BASE_RELOCATION)((uintptr_t)mapped_buffer + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (pBaseReloc->SizeOfBlock) {
		x = (uintptr_t)mapped_buffer + pBaseReloc->VirtualAddress;
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
				//printf("Type reloc unknown : %d", pReloc->type);
				break;
			}

			pReloc += 1;
		}

		pBaseReloc = (PIMAGE_BASE_RELOCATION)(((DWORD64)pBaseReloc) + pBaseReloc->SizeOfBlock);
	}

}
inline void PEFile::ParseImport() {
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

			}
			else {
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


inline void PEFile::ParseExport() {
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0
		|| pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
		return;

	PIMAGE_EXPORT_DIRECTORY pImageExportDescriptor
		= makepointer<PIMAGE_EXPORT_DIRECTORY>(mapped_buffer, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!pImageExportDescriptor->NumberOfNames || !pImageExportDescriptor->NumberOfNames || !pImageExportDescriptor->AddressOfFunctions)
		return;
	PDWORD fAddr = (PDWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfFunctions);
	PDWORD fNames = (PDWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfNames);
	PWORD  fOrd = (PWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImageExportDescriptor->NumberOfNames; i++) {
		LPSTR pFuncName = (LPSTR)((LPBYTE)mapped_buffer + fNames[i]);
		if (pFuncName && fOrd[i]) {
			exports_namekey.insert(std::pair(pFuncName, fAddr[fOrd[i]]));
			exports_rvakey.insert(std::pair(fAddr[fOrd[i]], pFuncName));
		}
	}



}

inline PEFile::PEFile(std::string filename, uintmax_t size) {
	if (size) {

		this->filename = filename;
		this->File.open(filename, std::ios::binary);
		this->filebuffer = (char*)malloc(size);
		if (filebuffer) {
			this->File.read(filebuffer, size);
			ParseHeader();

			ParseSection();
			//RelocationFix();
			ParseImport();
			ParseExport();
			File.close();
			free(filebuffer);
			free(mapped_buffer);
		}

	}
}






inline uint64_t PEFile::GetImageBase() {
	return imagebase;
}

inline uint64_t PEFile::GetVirtualSize() {
	return virtual_size;
}

inline ImportData* PEFile::GetImport(std::string name) {

	if (imports_namekey.contains(name)) {
		return &imports_namekey[name];
	}
	return 0;
}

inline ImportData* PEFile::GetImport(uint64_t rva) {

	if (imports_rvakey.contains(rva)) {
		return &imports_rvakey[rva];
	}
	return 0;
}

inline uint64_t PEFile::GetExport(std::string name) {
	if (name.empty())
		return 0;
	if (exports_namekey.contains(name)) {
		return exports_namekey[name];
	}
	return 0;
}

inline const char* PEFile::GetExport(uint64_t rva) {

	if (exports_rvakey.contains(rva)) {
		return exports_rvakey[rva].c_str();
	}
	return 0;
}

inline std::unordered_map<uint64_t, std::string> PEFile::GetAllExports() {
	return exports_rvakey;
}

inline uintmax_t PEFile::GetEP() {
	return entrypoint;
}


