#pragma once
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace util {
    inline std::vector<uint8_t> read_file(const std::filesystem::path& path) {
        std::fstream f(path, std::ios::in | std::ios::binary);
        if (!f)
            return {};

        f.seekg(0, f.end);
        const auto f_size = f.tellg();
        f.seekg(0, f.beg);

        std::vector<uint8_t> buffer(f_size);
        f.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

        return buffer;
    }

    __forceinline std::wstring str_to_wstr(const std::string_view data) noexcept {
        if (data.empty())
            return {};

        std::wstring out;
        out.resize(data.size());

        for (size_t i = 0; i < data.size(); ++i)
            out[i] = static_cast<wchar_t>(data[i]);
        return out;
    }

    // @credits: https://stackoverflow.com/a/4524873
    template <class T>
    __declspec(noinline) inline PIMAGE_SECTION_HEADER get_enclosing_section_header(DWORD rva, T* pNTHeader) {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
        unsigned i;

        for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++) {
            DWORD size = section->Misc.VirtualSize;
            if (0 == size)
                size = section->SizeOfRawData;

            if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size)))
                return section;
        }

        return 0;
    }

    // @credits: https://stackoverflow.com/a/4524873
    template <class T>
    __declspec(noinline) inline LPVOID get_ptr_for_rva(DWORD rva, T* pNTHeader, PBYTE imageBase) {
        PIMAGE_SECTION_HEADER pSectionHdr;
        INT delta;

        pSectionHdr = get_enclosing_section_header(rva, pNTHeader);
        if (!pSectionHdr)
            return 0;

        delta = (INT)(pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData);
        return (PVOID)(imageBase + rva - delta);
    }
} // namespace util
