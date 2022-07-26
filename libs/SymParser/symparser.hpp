#pragma once
#include "structs.hpp"
#include "util.hpp"
#include <Logger/Logger.h>
#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <unordered_map>
#include <vcruntime.h>

// @note: @es3n1n: this str should end with trailing slash
//
#define CACHE_DIR "c:\\emu\\pdb_cache\\"

namespace symparser {
    struct sym_t {
    public:
        std::ptrdiff_t rva;
        std::string name;
    };

    namespace detail {
        std::filesystem::path get_cache_folder();
    }

    // @note: @es3n1n: {img_path, {symbol, symbol, symbol}}
    //
    inline std::unordered_map<std::string, std::vector<sym_t>> cached_symbols = {};

    std::vector<sym_t> download_symbols(const std::filesystem::path& img);
    std::optional<sym_t> find_symbol(const std::filesystem::path& img, std::string_view symbol);
    std::optional<sym_t> find_symbol(const std::filesystem::path& img, std::ptrdiff_t rva);
} // namespace symparser
