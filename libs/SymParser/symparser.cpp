#include "symparser.hpp"

// @note: @es3n1n: UrlDownloadToFileW
#include <urlmon.h>
#pragma comment(lib, "urlmon")

namespace symparser {
    namespace detail {
        std::filesystem::path get_cache_folder() {
            std::filesystem::path ret = CACHE_DIR;
            if (!std::filesystem::exists(ret))
                std::filesystem::create_directory(ret);
            return ret;
        }
    } // namespace detail

    namespace {
        std::vector<std::uint8_t> get_stream_directory(uint8_t* pdb_raw) noexcept {
            std::vector<std::uint8_t> stream_dir;

            const auto super = reinterpret_cast<structs::SuperBlock*>(pdb_raw);
            const auto size = super->NumDirectoryBytes;
            if (!size)
                return {};

            const auto block_size = super->BlockSize;
            const auto block_count = (size + block_size - 1) / block_size;
            if (!block_count || !block_size)
                return {};

            const auto block_id_array = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(pdb_raw) + block_size * super->BlockMapAddr);

            stream_dir.reserve(block_count * block_size);
            for (uint32_t i = 0; i < block_count; ++i) {
                const auto block = static_cast<uint8_t*>(pdb_raw) + block_size * block_id_array[i];
                stream_dir.insert(stream_dir.end(), block, block + block_size);
            }

            stream_dir.resize(size);
            return stream_dir;
        }

        std::vector<std::vector<std::uint8_t>> get_streams(uint8_t* pdb_raw) noexcept {
            std::vector<std::vector<std::uint8_t>> streams;

            const auto super = reinterpret_cast<structs::SuperBlock*>(pdb_raw);
            if (!super->is_magic_valid())
                return {};

            const auto block_size = super->BlockSize;

            auto stream_dir = get_stream_directory(pdb_raw);

            auto stream_dir_iter = reinterpret_cast<uint32_t*>(stream_dir.data());

            const auto stream_num = *stream_dir_iter++;
            const auto stream_array = stream_dir_iter;
            stream_dir_iter += stream_num;

            streams.reserve(stream_num);

            for (auto i = 0u; i < stream_num; ++i) {
                std::vector<std::uint8_t> current_stream;

                const auto current_stream_size = stream_array[i];
                const auto current_stream_block_count = (current_stream_size + block_size - 1) / block_size;

                current_stream.reserve(current_stream_block_count * block_size);

                for (uint32_t j = 0; j < current_stream_block_count; ++j) {
                    const auto block_id = *stream_dir_iter++;
                    const auto block = static_cast<uint8_t*>(pdb_raw) + block_size * block_id;

                    current_stream.insert(current_stream.end(), block, block + block_size);
                }

                current_stream.resize(current_stream_size);
                streams.emplace_back(std::move(current_stream));
            }

            return streams;
        }

        std::vector<sym_t> parse_symbols(uint8_t* pdb_buffer, uint8_t* image_buffer) noexcept {
            auto&& streams = get_streams(pdb_buffer);

            if (streams.size() < 4)
                return {};

            const auto dbi_header = reinterpret_cast<structs::DBIHeader*>(streams[3].data());
            const auto symbols_id = dbi_header->SymRecordStream;

            if (streams.size() <= symbols_id)
                return {};

            auto raw_symbols = streams[symbols_id];
            auto it = raw_symbols.data();
            const auto end = it + raw_symbols.size();

            const auto dos_hdr = reinterpret_cast<PIMAGE_DOS_HEADER>(image_buffer);
            auto nt_hdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(image_buffer + dos_hdr->e_lfanew);
            auto sections
                = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<uint8_t*>(&nt_hdrs->OptionalHeader) + nt_hdrs->FileHeader.SizeOfOptionalHeader);

            std::vector<sym_t> symbols;
            while (it != end) {
                const auto curr = reinterpret_cast<const structs::PUBSYM32*>(it);

                if (curr->rectyp == 0x110e) {
                    if (curr->seg - 1 < nt_hdrs->FileHeader.NumberOfSections) {
                        auto section = sections + (curr->seg - 1);
                        const auto sym_rva = section->VirtualAddress + curr->off;
                        symbols.push_back({ sym_rva, curr->name });
                    }
                }

                it += curr->reclen + 2;
            }

            return symbols;
        }

        structs::cv_pdb70_t* image_find_codeview(uint8_t* image) noexcept {
            const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
            const auto nt_hdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(image + dos->e_lfanew);

            const auto debug_dir_data = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            if (!debug_dir_data.VirtualAddress || !debug_dir_data.Size)
                return nullptr;

            auto debug_dir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(util::get_ptr_for_rva(debug_dir_data.VirtualAddress, nt_hdrs, image));

            while (debug_dir) {
                if (debug_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
                    debug_dir++;
                    continue;
                }

                return reinterpret_cast<structs::cv_pdb70_t*>(image + debug_dir->PointerToRawData);
            }

            return nullptr;
        }

        std::wstring codeview_to_pdbpath(structs::cv_pdb70_t* codeview) noexcept {
            std::wstringstream pdbpath;
            pdbpath << codeview->pdb_name << L"\\";

            pdbpath << std::setfill(L'0') << std::setw(8) << std::hex << codeview->guid.dword << std::setw(4) << std::hex << codeview->guid.word[0]
                    << std::setw(4) << std::hex << codeview->guid.word[1];

            for (const auto i : codeview->guid.byte)
                pdbpath << std::setw(2) << std::hex << +i;

            pdbpath << "1\\" << codeview->pdb_name;

            return pdbpath.str();
        }

        std::optional<std::filesystem::path> cache_pdb(structs::cv_pdb70_t* codeview) noexcept {
            namespace fs = std::filesystem;

            if (!codeview)
                return {};

            const auto pdbpath = codeview_to_pdbpath(codeview);

            auto pdb_dir = detail::get_cache_folder();

            const auto local_pdbpath = pdb_dir.wstring() + pdbpath;

            if (fs::exists(local_pdbpath)) {
                return local_pdbpath;
            }

            fs::create_directory(pdb_dir.wstring() + util::str_to_wstr(codeview->pdb_name));
            fs::create_directory(local_pdbpath.substr(0, local_pdbpath.find_last_of('\\')));

            Logger::Log("symparser: Downloading %s\n", codeview->pdb_name);

            const auto download_stat = URLDownloadToFileW(nullptr, std::wstring { L"http://msdl.microsoft.com/download/symbols/" + pdbpath }.c_str(),
                local_pdbpath.c_str(), 0, nullptr);

            if (download_stat != S_OK) {
#ifdef _DEBUG
                __debugbreak();
#endif
                return {};
            }

            if (fs::exists(local_pdbpath))
                return local_pdbpath;

            return {};
        }
    } // namespace

    std::vector<sym_t> download_symbols(const std::filesystem::path& img) {
        auto img_path_str = img.string();

        // @note: @es3n1n: if this image has cached parsed symbols
        //
        if (!cached_symbols[img_path_str].empty())
            return cached_symbols[img_path_str];

        auto image = util::read_file(img);
        if (image.empty())
            __debugbreak();

        const auto codeview = image_find_codeview(image.data());
        if (!strstr(codeview->pdb_name, ".pdb"))
            return  std::vector<sym_t>();
        const auto pdb_path = cache_pdb(codeview);
        if (!pdb_path)
            __debugbreak();

        auto pdb = util::read_file(*pdb_path);
        auto symbols = parse_symbols(pdb.data(), image.data());

        // @note: @es3n1n: caching the result and returning it
        //
        cached_symbols[img_path_str] = symbols;
        return symbols;
    }

    std::optional<sym_t> find_symbol(const std::filesystem::path& img, std::string_view symbol) {
        const auto symbols = download_symbols(img);
        if (symbols.empty())
            return {};

        const auto s = std::ranges::find_if(symbols, [&symbol](const auto& ss) noexcept -> bool { return ss.name == symbol; });

        if (s != std::end(symbols))
            return *s;

        return {};
    }

    std::optional<sym_t> find_symbol(const std::filesystem::path& img, std::ptrdiff_t rva) {
        const auto symbols = download_symbols(img);
        if (symbols.empty())
            return {};

        const auto s = std::ranges::find_if(symbols, [&rva](const auto& ss) noexcept -> bool { return ss.rva == rva; });

        if (s != std::end(symbols))
            return *s;

        return {};
    }
} // namespace symparser
