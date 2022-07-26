#include "paging_emulation.h"
#include "emulation.h"

void PagingEmulation::SetupCR3() {
    for (int i = 0; i < 512; i++) {
        PML4.entries[i].Value = 0xFFFFFFFFFFFFFFFF;
        PML4.entries[i].Present = 1;
        PML4.entries[i].UserSupervisor = 1;
        PML4.entries[i].Accessed = 1;
        PML4.entries[i].PageFrameNumber = (uint64_t)(&PDPT.entries[0]) / 4096;
        PML4.entries[i].ExecuteDisable = 0;
    }

    for (int i = 0; i < 512; i++) {
        PDPT.entries[i].Value = 0xFFFFFFFFFFFFFFFF;
        PDPT.entries[i].Present = 1;
        PDPT.entries[i].UserSupervisor = 1;
        PDPT.entries[i].Accessed = 1;
        PDPT.entries[i].PageFrameNumber = (uint64_t)(&PD.entries[i]) / 4096;
        PDPT.entries[i].ExecuteDisable = 0;
    }

    for (int i = 0; i < 512; i++) {
        PD.entries[i].Value = 0xFFFFFFFFFFFFFFFF;
        PD.entries[i].Present = 1;
        PD.entries[i].UserSupervisor = 1;
        PD.entries[i].Accessed = 1;
        PD.entries[i].PageFrameNumber = (uint64_t)(&PT.entries[i]) / 4096;
        PD.entries[i].ExecuteDisable = 0;
    }

    for (int i = 0; i < 512; i++) {
        PT.entries[i].Value = 0xFFFFFFFFFFFFFFFF;
        PT.entries[i].Present = 1;
        PT.entries[i].UserSupervisor = 1;
        PT.entries[i].Accessed = 1;
        PT.entries[i].PageFrameNumber = 0;
        PT.entries[i].ExecuteDisable = 0;
    }

    PT.entries[0x19f].PageFrameNumber = VCPU::CR3 / 4096;
}
