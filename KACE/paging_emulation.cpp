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
        PML4::entries[i].Value = 0xFFFFFFFFFFFFFFFF;
        PML4::entries[i].Present = 1;
        PML4::entries[i].UserSupervisor = 1;
        PML4::entries[i].Accessed = 1;
        PML4::entries[i].PageFrameNumber = (uint64_t)(&PDPT::entries[0]) / 4096;
        PML4::entries[i].ExecuteDisable = 0;
    }

    for (int i = 0; i < 512; i++) {
        PDPT::entries[i].Value = 0xFFFFFFFFFFFFFFFF;
        PDPT::entries[i].Present = 1;
        PDPT::entries[i].UserSupervisor = 1;
        PDPT::entries[i].Accessed = 1;
        PDPT::entries[i].PageFrameNumber = (uint64_t)(&PD::entries[i]) / 4096;
        PDPT::entries[i].ExecuteDisable = 0;
    }

    for (int i = 0; i < 512; i++) {
        PD::entries[i].Value = 0xFFFFFFFFFFFFFFFF;
        PD::entries[i].Present = 1;
        PD::entries[i].UserSupervisor = 1;
        PD::entries[i].Accessed = 1;
        PD::entries[i].PageFrameNumber = (uint64_t)(&PT::entries[i]) / 4096;
        PD::entries[i].ExecuteDisable = 0;
    }

    for (int i = 0; i < 512; i++) {
        PT::entries[i].Value = 0xFFFFFFFFFFFFFFFF;
        PT::entries[i].Present = 1;
        PT::entries[i].UserSupervisor = 1;
        PT::entries[i].Accessed = 1;
        PT::entries[i].PageFrameNumber = 0;
        PT::entries[i].ExecuteDisable = 0;
    }

   // PML4::entries[0x19f].Value = 0;
    //PML4::entries[0x19f].PageFrameNumber = VCPU::CR3 / 4096;
    //PML4::entries[0x19f].Accessed = 1;
    //PML4::entries[0x19f].ReadWrite = 1;
    //PML4::entries[0x19f].Present = 0;
    //PML4::entries[0xff].Value = 0;
    //PML4::entries[0xff].PageFrameNumber = 0x19f;
    //PML4::entries[0xff].ExecuteDisable = 1;
    //PML4::entries[0xff].ExecuteDisable = 1;
    //PML4::entries[0x19f].Accessed = 1;
    //PML4::entries[0x19f].ReadWrite = 1;
    



    PT::entries[0x19f].PageFrameNumber = VCPU::CR3 / 4096;
    MemoryTracker::TrackVariable((uintptr_t)&PML4::entries[0], 0x1000, "PML4", 0xffffcfe7f3f9f000);
    MemoryTracker::TrackVariable((uintptr_t)&PDPT::entries[0], 0x1000, "PDPT");
    MemoryTracker::TrackVariable((uintptr_t)&PD::entries[0], 0x1000, "PD");
    MemoryTracker::TrackVariable((uintptr_t)&PT::entries[0], 0x1000, "PT");
}
