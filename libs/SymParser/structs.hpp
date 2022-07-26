#pragma once
#include <Windows.h>
#include <cstdint>

namespace structs {

#pragma pack(push, 1)
    struct SuperBlock {
        static constexpr char kMagic[] = { 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x2F, 0x43, 0x2B, 0x2B, 0x20, 0x4D, 0x53,
            0x46, 0x20, 0x37, 0x2E, 0x30, 0x30, 0x0D, 0x0A, 0x1A, 0x44, 0x53, 0x00, 0x00, 0x00 };

        char FileMagic[sizeof(kMagic)];
        uint32_t BlockSize;
        uint32_t FreeBlockMapBlock;
        uint32_t NumBlocks;
        uint32_t NumDirectoryBytes;
        uint32_t Unknown;
        uint32_t BlockMapAddr;

        bool is_magic_valid() const { return 0 == memcmp(FileMagic, kMagic, sizeof(kMagic)); }
    };

    struct DBIHeader {
        int32_t VersionSignature;
        uint32_t VersionHeader;
        uint32_t Age;
        uint16_t GlobalStreamIndex;
        uint16_t BuildNumber;
        uint16_t PublicStreamIndex;
        uint16_t PdbDllVersion;
        uint16_t SymRecordStream;
        uint16_t PdbDllRbld;
        int32_t ModInfoSize;
        int32_t SectionContributionSize;
        int32_t SectionMapSize;
        int32_t SourceInfoSize;
        int32_t TypeServerSize;
        uint32_t MFCTypeServerIndex;
        int32_t OptionalDbgHeaderSize;
        int32_t ECSubstreamSize;
        uint16_t Flags;
        uint16_t Machine;
        uint32_t Padding;
    };
#pragma pack(pop)

    struct PUBSYM32 {
        std::uint16_t reclen; // Record length
        std::uint16_t rectyp; // S_PUB32
        std::uint32_t pubsymflags;
        std::uint32_t off;
        std::uint16_t seg;
        char name[1]; // Length-prefixed name
    };

    // @credits: can1357
    enum class cv_signature : uint32_t {
        cv41 = 0x3930424E, // 'NB09'
        pdb20 = 0x3031424E, // 'NB10'
        cv50 = 0x3131424E, // 'NB11'
        pdb70 = 0x53445352, // 'RSDS'
    };

    struct guid_t {
        uint32_t dword;
        uint16_t word[2];
        uint8_t byte[8];
    };

    struct cv_header_t {
        cv_signature signature;
    };

    struct cv_pdb70_t : cv_header_t {
        guid_t guid;
        uint32_t age;
        char pdb_name[];
    };
} // namespace structs
