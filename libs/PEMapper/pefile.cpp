

#include "pefile.h"

void PEFile::ParseHeader() {


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
		memcpy(mapped_buffer + data.virtual_address, filebuffer + data.raw_address, data.raw_size);
		while (sections.contains(std::string(name))) {
			name[strlen(name) - 1] = name[strlen(name) - 1] + 1;

		}
		sections.insert(std::pair(std::string(name), data));

	}

}


void PEFile::RelocationFix() {

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
	PWORD  fOrd = (PWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImageExportDescriptor->NumberOfNames; i++) {
		LPSTR pFuncName = (LPSTR)((LPBYTE)mapped_buffer + fNames[i]);
		if (pFuncName && fOrd[i]) {
			exports_namekey.insert(std::pair(pFuncName, fAddr[fOrd[i]]));
			exports_rvakey.insert(std::pair(fAddr[fOrd[i]], pFuncName));
		}
	}



}

PEFile::PEFile(std::string filename, uintmax_t size) {
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






uint64_t PEFile::GetImageBase() {
	return imagebase;
}

uint64_t PEFile::GetVirtualSize() {
	return virtual_size;
}

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

std::unordered_map<uint64_t, std::string> PEFile::GetAllExports() {
	return exports_rvakey;
}

uintmax_t PEFile::GetEP() {
	return entrypoint;
}