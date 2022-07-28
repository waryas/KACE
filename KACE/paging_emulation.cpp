#include "paging_emulation.h"
#include "emulation.h"
#include <MemoryTracker/memorytracker.h>
namespace PagingEmulation {
    namespace PML4 {
        static __declspec(align(0x1000)) PML4E entries[512];
    }


    namespace PDPT {
        static __declspec(align(0x1000)) PDPTE entries[512];
    };

    namespace PD {
        static __declspec(align(0x1000)) PDE entries[512];
    };

    namespace PT {
        static __declspec(align(0x1000)) PTE entries[512];
    };
}

PML4E* PagingEmulation::GetPML4() {
    return &PML4::entries[0];
}
void PagingEmulation::SetupCR3() {
    for (int i = 0; i < 512; i++) {
        PML4::entries[i].Value = 0x0;
        PML4::entries[i].PageSize = 0;
        PML4::entries[i].Present = 1;
        PML4::entries[i].UserSupervisor = 1;
        PML4::entries[i].Accessed = 0;
        PML4::entries[i].ReadWrite = 0;
        PML4::entries[i].PageFrameNumber = 0;
        PML4::entries[i].ExecuteDisable = 0;
        PML4::entries[i].PageCacheDisable = 0;
        PML4::entries[i].PageWriteThrough = 0;
    }

    for (int i = 0; i < 512; i++) {
        PDPT::entries[i].Value = 0x0;
        PDPT::entries[i].Present = 1;
        PDPT::entries[i].UserSupervisor = 1;
        PDPT::entries[i].Accessed = 1;
        PDPT::entries[i].PageFrameNumber = 100;
        PDPT::entries[i].ExecuteDisable = 0;
        PDPT::entries[i].PageSize = 0;
    }

    for (int i = 0; i < 512; i++) {
        PD::entries[i].Value = 0x0;
        PD::entries[i].Present = 0;
        PD::entries[i].UserSupervisor = 1;
        PD::entries[i].Accessed = 1;
        PD::entries[i].PageFrameNumber = 0;
        PD::entries[i].ExecuteDisable = 0;
    }

    for (int i = 0; i < 512; i++) {
        PT::entries[i].Value = 0x0;
        PT::entries[i].Present = 1;
        PT::entries[i].UserSupervisor = 1;
        PT::entries[i].Accessed = 1;
        PT::entries[i].PageFrameNumber = 0;
        PT::entries[i].ExecuteDisable = 0;
    }

   // PML4::entries[0x19f].Value = 0;
    //PML4::entries[0x19f].PageFrameNumber = 0x19f;
    //PML4::entries[0xff].PageFrameNumber = 0xff;
    
    //PML4::entries[0x19f].Accessed = 1;
    //PML4::entries[0x19f].ReadWrite = 1;
    //PML4::entries[0x19f].Present = 0;
    //PML4::entries[0xff].Value = 0;
    //PML4::entries[0xff].PageFrameNumber = 0x19f;
    //PML4::entries[0xff].ExecuteDisable = 1;
    //PML4::entries[0xff].ExecuteDisable = 1;
    //PML4::entries[0x19f].Accessed = 1;
    //PML4::entries[0x19f].ReadWrite = 1;
    


    
    PML4::entries[255].PageFrameNumber = 0x401d9e;
    PDPT::entries[255].PageFrameNumber = 0x401d9e;
    PML4::entries[481].PageFrameNumber = VCPU::CR3 / 4096;
    PDPT::entries[481].PageFrameNumber = VCPU::CR3 / 4096;
    PD::entries[481].PageFrameNumber = VCPU::CR3 / 4096;
    PT::entries[481].PageFrameNumber = VCPU::CR3 / 4096;
    //auto xxx = MemoryTracker::AllocateVariable(0x1000);
    //memset((PVOID)xxx, 1, 0x1000);
    //MemoryTracker::TrackVariable((uintptr_t)&PML4::entries[0], 0x1000, "PML4", 0xfffff0f87c3e1000);
    //MemoryTracker::TrackVariable((uintptr_t)&PDPT::entries[0], 0x1000, "PDPT", 0xFFFFF0F87C2FF000);
    //MemoryTracker::TrackVariable((uintptr_t)&PD::entries[0], 0x1000, "PD", 0xFFFFF0F85FFDF000);
    //MemoryTracker::TrackVariable((uintptr_t)&PT::entries[0], 0x1000, "PT", 0xFFFFF0F87C3F0000);
    //MemoryTracker::TrackVariable(xxx, 0x1000, "zzz", 0xfffff0f87e001000);

        
    
}
