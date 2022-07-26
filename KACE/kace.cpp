#include <cassert>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <intrin.h>
#include <iostream>
#include <mutex>

#include <PEMapper/pefile.h>

#include <Logger/Logger.h>
#include <MemoryTracker/memorytracker.h>
#include <SymParser/symparser.hpp>

#include "emulation.h"
#include "environment.h"
#include "paging_emulation.h"

#include "ntoskrnl_provider.h"
#include "provider.h"

//#define MONITOR_ACCESS //This will monitor every read/write with a page_guard - SLOW - Better debugging

//This will monitor every read/write with a page_guard - SLOW - Better debugging

using proxyCall = uint64_t(__fastcall*)(...);
proxyCall DriverEntry = nullptr;

#define READ_VIOLATION 0
#define WRITE_VIOLATION 1
#define EXECUTE_VIOLATION 8

uint64_t passthrough(...) { return 0; }

//POC STAGE, NEED TO MAKE THIS DYNAMIC - Most performance issue come from this, also for some reason i only got this to work in Visual studio, not outside of it.

uintptr_t lastPG = 0;

extern "C" void u_iret();

std::mutex exceptionMutex;

LONG ExceptionHandler(EXCEPTION_POINTERS* e) {
    exceptionMutex.lock();
    uintptr_t ep = (uintptr_t)e->ExceptionRecord->ExceptionAddress;

    if (e->ExceptionRecord->ExceptionCode == EXCEPTION_FLT_DIVIDE_BY_ZERO) {
        exceptionMutex.unlock();
        return EXCEPTION_CONTINUE_SEARCH;
    } else if (e->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION) {
        bool wasEmulated = false;

        wasEmulated = VCPU::PrivilegedInstruction::Parse(e->ContextRecord);

        if (wasEmulated) {
            exceptionMutex.unlock();
            return EXCEPTION_CONTINUE_EXECUTION;
        } else {
            exceptionMutex.unlock();
            Logger::Log("Failed to emulate instruction\n");

            return EXCEPTION_CONTINUE_SEARCH;
        }

    }

    else if (e->ExceptionRecord->ExceptionCode = EXCEPTION_ACCESS_VIOLATION) {
        auto bufferopcode = (uint8_t*)e->ContextRecord->Rip;
        auto addr_access = e->ExceptionRecord->ExceptionInformation[1];
        bool wasEmulated = false;

        switch (e->ExceptionRecord->ExceptionInformation[0]) {
        case WRITE_VIOLATION:

            wasEmulated = VCPU::MemoryWrite::Parse(addr_access, e->ContextRecord);

            if (wasEmulated) {
                exceptionMutex.unlock();
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            exceptionMutex.unlock();
            exit(0);
            break;

        case READ_VIOLATION:

            wasEmulated = VCPU::MemoryRead::Parse(addr_access, e->ContextRecord);

            if (wasEmulated) {
                exceptionMutex.unlock();
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if (e->ExceptionRecord->ExceptionInformation[1] == e->ExceptionRecord->ExceptionInformation[0]
                && e->ExceptionRecord->ExceptionInformation[0] == 0) {
                exceptionMutex.unlock();
                return EXCEPTION_CONTINUE_SEARCH;
            }

            if (bufferopcode[0] == 0xCD && bufferopcode[1] == 0x20) {
                Logger::Log("\033[38;5;46m[Info]\033[0m Checking for Patchguard (int 20)\n");
                e->ContextRecord->Rip += 2;
                exceptionMutex.unlock();
                return EXCEPTION_CONTINUE_EXECUTION;
            } else if (bufferopcode[0] == 0x48 && bufferopcode[1] == 0xCF) {
                e->ContextRecord->Rip = (uintptr_t)u_iret;
                Logger::Log("\033[38;5;46m[Info]\033[0m IRET Timing Emulation\n");
                exceptionMutex.unlock();
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            break;
        case EXECUTE_VIOLATION:

            auto rip = Provider::FindFuncImpl(addr_access);

            if (!rip)
                DebugBreak();

            e->ContextRecord->Rip = rip;

            exceptionMutex.unlock();
            return EXCEPTION_CONTINUE_EXECUTION;
            break;
        }
    }
    exceptionMutex.unlock();
    return EXCEPTION_CONTINUE_SEARCH;
}

const wchar_t* driverName = L"\\Driver\\vgk";
const wchar_t* registryBuffer = L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\vgk";

DWORD FakeDriverEntry(LPVOID) {

    AddVectoredExceptionHandler(true, ExceptionHandler);

    Logger::Log("Calling the driver entrypoint\n");

    drvObj.Size = sizeof(drvObj);
    drvObj.DriverName.Buffer = (WCHAR*)driverName;
    drvObj.DriverName.Length = lstrlenW(driverName);
    drvObj.DriverName.MaximumLength = 16;

    RegistryPath.Buffer = (WCHAR*)registryBuffer;
    RegistryPath.Length = lstrlenW(RegistryPath.Buffer) * 2;
    RegistryPath.MaximumLength = lstrlenW(RegistryPath.Buffer) * 2;

    memset(&FakeKernelThread, 0, sizeof(FakeKernelThread));
    memset(&FakeSystemProcess, 0, sizeof(FakeSystemProcess));
    memset(&FakeKPCR, 0, sizeof(FakeKPCR));
    memset(&FakeCPU, 0, sizeof(FakeCPU));

    InitializeListHead(&FakeKernelThread.Tcb.Header.WaitListHead);
    InitializeListHead(&FakeSystemProcess.Pcb.Header.WaitListHead);

    __writegsqword(0x188, (DWORD64)&FakeKernelThread); //Fake KTHREAD
    __writegsqword(0x18, (DWORD64)&FakeKPCR); //Fake _KPCR
    __writegsqword(0x20, (DWORD64)&FakeCPU); //Fake _KPRCB

    FakeKernelThread.Tcb.Process = (_KPROCESS*)&FakeSystemProcess; //PsGetThreadProcess
    FakeKernelThread.Tcb.ApcState.Process = (_KPROCESS*)&FakeSystemProcess; //PsGetCurrentProcess

    FakeKernelThread.Cid.UniqueProcess = (void*)4; //PsGetThreadProcessId
    FakeKernelThread.Cid.UniqueThread = (void*)0x8; //PsGetThreadId

    FakeKernelThread.Tcb.PreviousMode = 0; //PsGetThreadPreviousMode
    FakeKernelThread.Tcb.State = 1; //
    FakeKernelThread.Tcb.InitialStack = (void*)0x1000;
    FakeKernelThread.Tcb.StackBase = (void*)0x1500;
    FakeKernelThread.Tcb.StackLimit = (void*)0x2000;
    FakeKernelThread.Tcb.ThreadLock = 11;
    FakeKernelThread.Tcb.LockEntries = (_KLOCK_ENTRY*)22;

    FakeSystemProcess.UniqueProcessId = (void*)4;
    FakeSystemProcess.Protection.Level = 7;
    FakeSystemProcess.WoW64Process = nullptr;
    FakeSystemProcess.CreateTime.QuadPart = GetTickCount64();

    FakeCPU.CurrentThread = (_KTHREAD*)&FakeKernelThread;
    FakeCPU.IdleThread = (_KTHREAD*)&FakeKernelThread;
    FakeCPU.CoresPerPhysicalProcessor = 2;
    FakeCPU.LogicalProcessorsPerCore = 2;
    FakeCPU.MajorVersion = 10;
    FakeCPU.MinorVersion = 0;
    FakeCPU.RspBase = __readgsqword(0x8);

    FakeKPCR.CurrentPrcb = &FakeCPU;
    FakeKPCR.NtTib.StackBase = (PVOID)__readgsqword(0x8);
    FakeKPCR.NtTib.StackLimit = (PVOID)__readgsqword(0x10);
    FakeKPCR.MajorVersion = 10;
    FakeKPCR.MinorVersion = 0;
    FakeKPCR.Used_Self = (void*)__readgsqword(0x30); //Usermode TEB is actually in kernel gs:0x30
    FakeKPCR.Self = &FakeKPCR;

    __writeeflags(0x10286);

    drvObj.DriverSection = (_KLDR_DATA_TABLE_ENTRY*)MemoryTracker::AllocateVariable(sizeof(_KLDR_DATA_TABLE_ENTRY) * 2);

    MemoryTracker::TrackVariable((uintptr_t)drvObj.DriverSection, sizeof(_KLDR_DATA_TABLE_ENTRY) * 2, "MainModule.DriverObject.DriverSection");
    MemoryTracker::TrackVariable((uintptr_t)&FakeKPCR, sizeof(FakeKPCR), (char*)"KPCR");
    MemoryTracker::TrackVariable((uintptr_t)&FakeCPU, sizeof(FakeCPU), (char*)"CPU");
    MemoryTracker::TrackVariable((uintptr_t)&drvObj, sizeof(drvObj), (char*)"MainModule.DriverObject");
    MemoryTracker::TrackVariable((uintptr_t)&RegistryPath, sizeof(RegistryPath), (char*)"MainModule.RegistryPath");
    MemoryTracker::TrackVariable((uintptr_t)&FakeSystemProcess, sizeof(FakeSystemProcess), (char*)"PID4.EPROCESS");
    MemoryTracker::TrackVariable((uintptr_t)&FakeKernelThread, sizeof(FakeKernelThread), (char*)"PID4.ETHREAD");

    auto result = DriverEntry(&drvObj, &RegistryPath);
    Logger::Log("Main Thread Done! Return = %llx\n", result);
    system("pause");
    return 0;
}

__forceinline void init_dirs() {
    std::filesystem::path p = "c:\\";
    for (auto& key : { "\\kace", "\\ca", "\\ca", "\\windows" }) {
        p += key;
        if (!std::filesystem::exists(p))
            std::filesystem::create_directory(p);
    }
}

int main(int argc, char* argv[]) {
    init_dirs();

    symparser::download_symbols("c:\\Windows\\System32\\ntdll.dll");
    symparser::download_symbols("c:\\Windows\\System32\\ntoskrnl.exe");

    Environment::InitializeSystemModules();
    MemoryTracker::Initiate();
    VCPU::Initialize();
    PagingEmulation::SetupCR3();
    ntoskrnl_provider::Initialize();

    DWORD dwMode;

    auto hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    Logger::Log("Loading modules\n");

    auto MainModule = PEFile::Open("C:\\emu\\easyanticheat_03.sys", "easyanticheat_03.sys");
    MainModule->ResolveImport();
    MainModule->SetExecutable(true);

    PEFile::SetPermission();

    for (int i = 0; i < PEFile::LoadedModuleArray.size(); i++) {
        if (PEFile::LoadedModuleArray[i]->GetShadowBuffer()) {
            MemoryTracker::AddMapping(PEFile::LoadedModuleArray[i]->GetMappedImageBase(), PEFile::LoadedModuleArray[i]->GetVirtualSize(),
                PEFile::LoadedModuleArray[i]->GetShadowBuffer());
        }
    }

    DriverEntry = (proxyCall)(MainModule->GetMappedImageBase() + MainModule->GetEP());

    const HANDLE ThreadHandle = CreateThread(nullptr, 4096, FakeDriverEntry, nullptr, 0, nullptr);

    if (!ThreadHandle)
        return 0;

    while (true) {
        Sleep(1000);

        DWORD ExitCode;
        if (GetExitCodeThread(ThreadHandle, &ExitCode)) {
            if (ExitCode != STILL_ACTIVE) {
                break;
            }
        }
    }

    CloseHandle(ThreadHandle);

    return 0;
}
