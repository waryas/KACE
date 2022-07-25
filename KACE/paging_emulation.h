#include <windows.h>
#include <inttypes.h>

namespace PagingEmulation {
    void SetupCR3();
}

typedef struct _PML4E
{
    union
    {
        struct
        {
            ULONG64 Present : 1;              // Must be 1, region invalid if 0.
            ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
            ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access PDPT.
            ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access PDPT.
            ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
            ULONG64 Ignored1 : 1;
            ULONG64 PageSize : 1;             // Must be 0 for PML4E.
            ULONG64 Ignored2 : 4;
            ULONG64 PageFrameNumber : 36;     // The page frame number of the PDPT of this PML4E.
            ULONG64 Reserved : 4;
            ULONG64 Ignored3 : 11;
            ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        ULONG64 Value;
    };
} PML4E, * PPML4E;

typedef struct _PDPTE
{
    union
    {
        struct
        {
            ULONG64 Present : 1;              // Must be 1, region invalid if 0.
            ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
            ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access PD.
            ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access PD.
            ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
            ULONG64 Ignored1 : 1;
            ULONG64 PageSize : 1;             // If 1, this entry maps a 1GB page.
            ULONG64 Ignored2 : 4;
            ULONG64 PageFrameNumber : 36;     // The page frame number of the PD of this PDPTE.
            ULONG64 Reserved : 4;
            ULONG64 Ignored3 : 11;
            ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        ULONG64 Value;
    };
} PDPTE, * PPDPTE;


typedef struct _PDE
{
    union
    {
        struct
        {
            ULONG64 Present : 1;              // Must be 1, region invalid if 0.
            ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
            ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access PT.
            ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access PT.
            ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
            ULONG64 Ignored1 : 1;
            ULONG64 PageSize : 1;             // If 1, this entry maps a 2MB page.
            ULONG64 Ignored2 : 4;
            ULONG64 PageFrameNumber : 36;     // The page frame number of the PT of this PDE.
            ULONG64 Reserved : 4;
            ULONG64 Ignored3 : 11;
            ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        ULONG64 Value;
    };
} PDE, * PPDE;

typedef struct _PTE
{
    union
    {
        struct
        {
            ULONG64 Present : 1;              // Must be 1, region invalid if 0.
            ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
            ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access the memory.
            ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access the memory.
            ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
            ULONG64 Dirty : 1;                // If 0, the memory backing this page has not been written to.
            ULONG64 PageAccessType : 1;       // Determines the memory type used to access the memory.
            ULONG64 Global : 1;                // If 1 and the PGE bit of CR4 is set, translations are global.
            ULONG64 Ignored2 : 3;
            ULONG64 PageFrameNumber : 36;     // The page frame number of the backing physical page.
            ULONG64 Reserved : 4;
            ULONG64 Ignored3 : 7;
            ULONG64 ProtectionKey : 4;         // If the PKE bit of CR4 is set, determines the protection key.
            ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        ULONG64 Value;
    };
} PTE, * PPTE;

static struct PML4 {
    PML4E entries[512] = { 0 };
} PML4;

static struct PDPT {
    PDPTE entries[512]{ 0 };
} PDPT;

static struct PD {
    PDE entries[512] = { 0 };
} PD;

static struct PT {
    PTE entries[512] = { 0 };
}PT;

