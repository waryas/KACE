#pragma once
#include <windows.h>

//Our emulation is simulating the struct of Windows 10 | 2016 2110 21H2 (November 2021 Update) x64 - Make sure you use ntoskrnl.exe of that version

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING* PUNICODE_STRING;

struct _KAFFINITY_EX {
    USHORT Count; //0x0
    USHORT Size; //0x2
    ULONG Reserved; //0x4
    ULONGLONG Bitmap[20]; //0x8
};

union _KEXECUTE_OPTIONS {
    UCHAR ExecuteDisable : 1; //0x0
    UCHAR ExecuteEnable : 1; //0x0
    UCHAR DisableThunkEmulation : 1; //0x0
    UCHAR Permanent : 1; //0x0
    UCHAR ExecuteDispatchEnable : 1; //0x0
    UCHAR ImageDispatchEnable : 1; //0x0
    UCHAR DisableExceptionChainValidation : 1; //0x0
    UCHAR Spare : 1; //0x0
    volatile UCHAR ExecuteOptions; //0x0
    UCHAR ExecuteOptionsNV; //0x0
};

union _KSTACK_COUNT {
    LONG Value; //0x0
    ULONG State : 3; //0x0
    ULONG StackCount : 29; //0x0
};

struct _DISPATCHER_HEADER {
    union {
        volatile LONG Lock; //0x0
        LONG LockNV; //0x0
        struct {
            UCHAR Type; //0x0
            UCHAR Signalling; //0x1
            UCHAR Size; //0x2
            UCHAR Reserved1; //0x3
        };
        struct {
            UCHAR TimerType; //0x0
            union {
                UCHAR TimerControlFlags; //0x1
                struct {
                    UCHAR Absolute : 1; //0x1
                    UCHAR Wake : 1; //0x1
                    UCHAR EncodedTolerableDelay : 6; //0x1
                };
            };
            UCHAR Hand; //0x2
            union {
                UCHAR TimerMiscFlags; //0x3
                struct {
                    UCHAR Index : 6; //0x3
                    UCHAR Inserted : 1; //0x3
                    volatile UCHAR Expired : 1; //0x3
                };
            };
        };
        struct {
            UCHAR Timer2Type; //0x0
            union {
                UCHAR Timer2Flags; //0x1
                struct {
                    UCHAR Timer2Inserted : 1; //0x1
                    UCHAR Timer2Expiring : 1; //0x1
                    UCHAR Timer2CancelPending : 1; //0x1
                    UCHAR Timer2SetPending : 1; //0x1
                    UCHAR Timer2Running : 1; //0x1
                    UCHAR Timer2Disabled : 1; //0x1
                    UCHAR Timer2ReservedFlags : 2; //0x1
                };
            };
            UCHAR Timer2ComponentId; //0x2
            UCHAR Timer2RelativeId; //0x3
        };
        struct {
            UCHAR QueueType; //0x0
            union {
                UCHAR QueueControlFlags; //0x1
                struct {
                    UCHAR Abandoned : 1; //0x1
                    UCHAR DisableIncrement : 1; //0x1
                    UCHAR QueueReservedControlFlags : 6; //0x1
                };
            };
            UCHAR QueueSize; //0x2
            UCHAR QueueReserved; //0x3
        };
        struct {
            UCHAR ThreadType; //0x0
            UCHAR ThreadReserved; //0x1
            union {
                UCHAR ThreadControlFlags; //0x2
                struct {
                    UCHAR CycleProfiling : 1; //0x2
                    UCHAR CounterProfiling : 1; //0x2
                    UCHAR GroupScheduling : 1; //0x2
                    UCHAR AffinitySet : 1; //0x2
                    UCHAR Tagged : 1; //0x2
                    UCHAR EnergyProfiling : 1; //0x2
                    UCHAR SchedulerAssist : 1; //0x2
                    UCHAR ThreadReservedControlFlags : 1; //0x2
                };
            };
            union {
                UCHAR DebugActive; //0x3
                struct {
                    UCHAR ActiveDR7 : 1; //0x3
                    UCHAR Instrumented : 1; //0x3
                    UCHAR Minimal : 1; //0x3
                    UCHAR Reserved4 : 2; //0x3
                    UCHAR AltSyscall : 1; //0x3
                    UCHAR UmsScheduled : 1; //0x3
                    UCHAR UmsPrimary : 1; //0x3
                };
            };
        };
        struct {
            UCHAR MutantType; //0x0
            UCHAR MutantSize; //0x1
            UCHAR DpcActive; //0x2
            UCHAR MutantReserved; //0x3
        };
    };
    LONG SignalState; //0x4
    struct _LIST_ENTRY WaitListHead; //0x8
};

struct _KPROCESS {
    struct _DISPATCHER_HEADER Header; //0x0
    struct _LIST_ENTRY ProfileListHead; //0x18
    ULONGLONG DirectoryTableBase; //0x28
    struct _LIST_ENTRY ThreadListHead; //0x30
    ULONG ProcessLock; //0x40
    ULONG ProcessTimerDelay; //0x44
    ULONGLONG DeepFreezeStartTime; //0x48
    struct _KAFFINITY_EX Affinity; //0x50
    ULONGLONG AffinityPadding[12]; //0xf8
    struct _LIST_ENTRY ReadyListHead; //0x158
    struct _SINGLE_LIST_ENTRY SwapListEntry; //0x168
    volatile struct _KAFFINITY_EX ActiveProcessors; //0x170
    ULONGLONG ActiveProcessorsPadding[12]; //0x218
    union {
        struct {
            ULONG AutoAlignment : 1; //0x278
            ULONG DisableBoost : 1; //0x278
            ULONG DisableQuantum : 1; //0x278
            ULONG DeepFreeze : 1; //0x278
            ULONG TimerVirtualization : 1; //0x278
            ULONG CheckStackExtents : 1; //0x278
            ULONG CacheIsolationEnabled : 1; //0x278
            ULONG PpmPolicy : 3; //0x278
            ULONG VaSpaceDeleted : 1; //0x278
            ULONG ReservedFlags : 21; //0x278
        };
        volatile LONG ProcessFlags; //0x278
    };
    ULONG ActiveGroupsMask; //0x27c
    CHAR BasePriority; //0x280
    CHAR QuantumReset; //0x281
    CHAR Visited; //0x282
    union _KEXECUTE_OPTIONS Flags; //0x283
    USHORT ThreadSeed[20]; //0x284
    USHORT ThreadSeedPadding[12]; //0x2ac
    USHORT IdealProcessor[20]; //0x2c4
    USHORT IdealProcessorPadding[12]; //0x2ec
    USHORT IdealNode[20]; //0x304
    USHORT IdealNodePadding[12]; //0x32c
    USHORT IdealGlobalNode; //0x344
    USHORT Spare1; //0x346
    union _KSTACK_COUNT StackCount; //0x348
    struct _LIST_ENTRY ProcessListEntry; //0x350
    ULONGLONG CycleTime; //0x360
    ULONGLONG ContextSwitches; //0x368
    struct _KSCHEDULING_GROUP* SchedulingGroup; //0x370
    ULONG FreezeCount; //0x378
    ULONG KernelTime; //0x37c
    ULONG UserTime; //0x380
    ULONG ReadyTime; //0x384
    ULONGLONG UserDirectoryTableBase; //0x388
    UCHAR AddressPolicy; //0x390
    UCHAR Spare2[71]; //0x391
    VOID* InstrumentationCallback; //0x3d8
    union {
        ULONGLONG SecureHandle; //0x3e0
        struct {
            ULONGLONG SecureProcess : 1; //0x3e0
            ULONGLONG Unused : 1; //0x3e0
        } Flags; //0x3e0
    } SecureState; //0x3e0
    ULONGLONG KernelWaitTime; //0x3e8
    ULONGLONG UserWaitTime; //0x3f0
    ULONGLONG EndPadding[8]; //0x3f8
};

struct _KEVENT {
    struct _DISPATCHER_HEADER Header; //0x0
};

union _KWAIT_STATUS_REGISTER {
    UCHAR Flags; //0x0
    UCHAR State : 3; //0x0
    UCHAR Affinity : 1; //0x0
    UCHAR Priority : 1; //0x0
    UCHAR Apc : 1; //0x0
    UCHAR UserApc : 1; //0x0
    UCHAR Alert : 1; //0x0
};

struct _KAPC_STATE {
    struct _LIST_ENTRY ApcListHead[2]; //0x0
    struct _KPROCESS* Process; //0x20
    union {
        UCHAR InProgressFlags; //0x28
        struct {
            UCHAR KernelApcInProgress : 1; //0x28
            UCHAR SpecialApcInProgress : 1; //0x28
        };
    };
    UCHAR KernelApcPending; //0x29
    union {
        UCHAR UserApcPendingAll; //0x2a
        struct {
            UCHAR SpecialUserApcPending : 1; //0x2a
            UCHAR UserApcPending : 1; //0x2a
        };
    };
};

struct _KTIMER {
    struct _DISPATCHER_HEADER Header; //0x0
    union _ULARGE_INTEGER DueTime; //0x18
    struct _LIST_ENTRY TimerListEntry; //0x20
    struct _KDPC* Dpc; //0x30
    USHORT Processor; //0x38
    USHORT TimerType; //0x3a
    ULONG Period; //0x3c
};

struct _KWAIT_BLOCK {
    struct _LIST_ENTRY WaitListEntry; //0x0
    UCHAR WaitType; //0x10
    volatile UCHAR BlockState; //0x11
    USHORT WaitKey; //0x12
    LONG SpareLong; //0x14
    union {
        struct _KTHREAD* Thread; //0x18
        struct _KQUEUE* NotificationQueue; //0x18
    };
    VOID* Object; //0x20
    VOID* SparePtr; //0x28
};

struct _KAPC {
    UCHAR Type; //0x0
    UCHAR SpareByte0; //0x1
    UCHAR Size; //0x2
    UCHAR SpareByte1; //0x3
    ULONG SpareLong0; //0x4
    struct _KTHREAD* Thread; //0x8
    struct _LIST_ENTRY ApcListEntry; //0x10
    VOID* Reserved[3]; //0x20
    VOID* NormalContext; //0x38
    VOID* SystemArgument1; //0x40
    VOID* SystemArgument2; //0x48
    CHAR ApcStateIndex; //0x50
    CHAR ApcMode; //0x51
    UCHAR Inserted; //0x52
};

struct _KTHREAD {
    struct _DISPATCHER_HEADER Header; //0x0
    VOID* SListFaultAddress; //0x18
    ULONGLONG QuantumTarget; //0x20
    VOID* InitialStack; //0x28
    VOID* volatile StackLimit; //0x30
    VOID* StackBase; //0x38
    ULONGLONG ThreadLock; //0x40
    volatile ULONGLONG CycleTime; //0x48
    ULONG CurrentRunTime; //0x50
    ULONG ExpectedRunTime; //0x54
    VOID* KernelStack; //0x58
    struct _XSAVE_FORMAT* StateSaveArea; //0x60
    struct _KSCHEDULING_GROUP* volatile SchedulingGroup; //0x68
    union _KWAIT_STATUS_REGISTER WaitRegister; //0x70
    volatile UCHAR Running; //0x71
    UCHAR Alerted[2]; //0x72
    union {
        struct {
            ULONG AutoBoostActive : 1; //0x74
            ULONG ReadyTransition : 1; //0x74
            ULONG WaitNext : 1; //0x74
            ULONG SystemAffinityActive : 1; //0x74
            ULONG Alertable : 1; //0x74
            ULONG UserStackWalkActive : 1; //0x74
            ULONG ApcInterruptRequest : 1; //0x74
            ULONG QuantumEndMigrate : 1; //0x74
            ULONG UmsDirectedSwitchEnable : 1; //0x74
            ULONG TimerActive : 1; //0x74
            ULONG SystemThread : 1; //0x74
            ULONG ProcessDetachActive : 1; //0x74
            ULONG CalloutActive : 1; //0x74
            ULONG ScbReadyQueue : 1; //0x74
            ULONG ApcQueueable : 1; //0x74
            ULONG ReservedStackInUse : 1; //0x74
            ULONG UmsPerformingSyscall : 1; //0x74
            ULONG TimerSuspended : 1; //0x74
            ULONG SuspendedWaitMode : 1; //0x74
            ULONG SuspendSchedulerApcWait : 1; //0x74
            ULONG CetUserShadowStack : 1; //0x74
            ULONG BypassProcessFreeze : 1; //0x74
            ULONG Reserved : 10; //0x74
        };
        LONG MiscFlags; //0x74
    };
    union {
        struct {
            ULONG ThreadFlagsSpare : 2; //0x78
            ULONG AutoAlignment : 1; //0x78
            ULONG DisableBoost : 1; //0x78
            ULONG AlertedByThreadId : 1; //0x78
            ULONG QuantumDonation : 1; //0x78
            ULONG EnableStackSwap : 1; //0x78
            ULONG GuiThread : 1; //0x78
            ULONG DisableQuantum : 1; //0x78
            ULONG ChargeOnlySchedulingGroup : 1; //0x78
            ULONG DeferPreemption : 1; //0x78
            ULONG QueueDeferPreemption : 1; //0x78
            ULONG ForceDeferSchedule : 1; //0x78
            ULONG SharedReadyQueueAffinity : 1; //0x78
            ULONG FreezeCount : 1; //0x78
            ULONG TerminationApcRequest : 1; //0x78
            ULONG AutoBoostEntriesExhausted : 1; //0x78
            ULONG KernelStackResident : 1; //0x78
            ULONG TerminateRequestReason : 2; //0x78
            ULONG ProcessStackCountDecremented : 1; //0x78
            ULONG RestrictedGuiThread : 1; //0x78
            ULONG VpBackingThread : 1; //0x78
            ULONG ThreadFlagsSpare2 : 1; //0x78
            ULONG EtwStackTraceApcInserted : 8; //0x78
        };
        volatile LONG ThreadFlags; //0x78
    };
    volatile UCHAR Tag; //0x7c
    UCHAR SystemHeteroCpuPolicy; //0x7d
    UCHAR UserHeteroCpuPolicy : 7; //0x7e
    UCHAR ExplicitSystemHeteroCpuPolicy : 1; //0x7e
    union {
        struct {
            UCHAR RunningNonRetpolineCode : 1; //0x7f
            UCHAR SpecCtrlSpare : 7; //0x7f
        };
        UCHAR SpecCtrl; //0x7f
    };
    ULONG SystemCallNumber; //0x80
    ULONG ReadyTime; //0x84
    VOID* FirstArgument; //0x88
    struct _KTRAP_FRAME* TrapFrame; //0x90
    union {
        struct _KAPC_STATE ApcState; //0x98
        struct {
            UCHAR ApcStateFill[43]; //0x98
            CHAR Priority; //0xc3
            ULONG UserIdealProcessor; //0xc4
        };
    };
    volatile LONGLONG WaitStatus; //0xc8
    struct _KWAIT_BLOCK* WaitBlockList; //0xd0
    union {
        struct _LIST_ENTRY WaitListEntry; //0xd8
        struct _SINGLE_LIST_ENTRY SwapListEntry; //0xd8
    };
    struct _DISPATCHER_HEADER* volatile Queue; //0xe8
    VOID* Teb; //0xf0
    ULONGLONG RelativeTimerBias; //0xf8
    struct _KTIMER Timer; //0x100
    union {
        struct _KWAIT_BLOCK WaitBlock[4]; //0x140
        struct {
            UCHAR WaitBlockFill4[20]; //0x140
            ULONG ContextSwitches; //0x154
        };
        struct {
            UCHAR WaitBlockFill5[68]; //0x140
            volatile UCHAR State; //0x184
            CHAR Spare13; //0x185
            UCHAR WaitIrql; //0x186
            CHAR WaitMode; //0x187
        };
        struct {
            UCHAR WaitBlockFill6[116]; //0x140
            ULONG WaitTime; //0x1b4
        };
        struct {
            UCHAR WaitBlockFill7[164]; //0x140
            union {
                struct {
                    SHORT KernelApcDisable; //0x1e4
                    SHORT SpecialApcDisable; //0x1e6
                };
                ULONG CombinedApcDisable; //0x1e4
            };
        };
        struct {
            UCHAR WaitBlockFill8[40]; //0x140
            struct _KTHREAD_COUNTERS* ThreadCounters; //0x168
        };
        struct {
            UCHAR WaitBlockFill9[88]; //0x140
            struct _XSTATE_SAVE* XStateSave; //0x198
        };
        struct {
            UCHAR WaitBlockFill10[136]; //0x140
            VOID* volatile Win32Thread; //0x1c8
        };
        struct {
            UCHAR WaitBlockFill11[176]; //0x140
            struct _UMS_CONTROL_BLOCK* Ucb; //0x1f0
            struct _KUMS_CONTEXT_HEADER* volatile Uch; //0x1f8
        };
    };
    union {
        volatile LONG ThreadFlags2; //0x200
        struct {
            ULONG BamQosLevel : 8; //0x200
            ULONG ThreadFlags2Reserved : 24; //0x200
        };
    };
    ULONG Spare21; //0x204
    struct _LIST_ENTRY QueueListEntry; //0x208
    union {
        volatile ULONG NextProcessor; //0x218
        struct {
            ULONG NextProcessorNumber : 31; //0x218
            ULONG SharedReadyQueue : 1; //0x218
        };
    };
    LONG QueuePriority; //0x21c
    struct _KPROCESS* Process; //0x220
    union {
        struct _GROUP_AFFINITY UserAffinity; //0x228
        struct {
            UCHAR UserAffinityFill[10]; //0x228
            CHAR PreviousMode; //0x232
            CHAR BasePriority; //0x233
            union {
                CHAR PriorityDecrement; //0x234
                struct {
                    UCHAR ForegroundBoost : 4; //0x234
                    UCHAR UnusualBoost : 4; //0x234
                };
            };
            UCHAR Preempted; //0x235
            UCHAR AdjustReason; //0x236
            CHAR AdjustIncrement; //0x237
        };
    };
    ULONGLONG AffinityVersion; //0x238
    union {
        struct _GROUP_AFFINITY Affinity; //0x240
        struct {
            UCHAR AffinityFill[10]; //0x240
            UCHAR ApcStateIndex; //0x24a
            UCHAR WaitBlockCount; //0x24b
            ULONG IdealProcessor; //0x24c
        };
    };
    ULONGLONG NpxState; //0x250
    union {
        struct _KAPC_STATE SavedApcState; //0x258
        struct {
            UCHAR SavedApcStateFill[43]; //0x258
            UCHAR WaitReason; //0x283
            CHAR SuspendCount; //0x284
            CHAR Saturation; //0x285
            USHORT SListFaultCount; //0x286
        };
    };
    union {
        struct _KAPC SchedulerApc; //0x288
        struct {
            UCHAR SchedulerApcFill0[1]; //0x288
            UCHAR ResourceIndex; //0x289
        };
        struct {
            UCHAR SchedulerApcFill1[3]; //0x288
            UCHAR QuantumReset; //0x28b
        };
        struct {
            UCHAR SchedulerApcFill2[4]; //0x288
            ULONG KernelTime; //0x28c
        };
        struct {
            UCHAR SchedulerApcFill3[64]; //0x288
            struct _KPRCB* volatile WaitPrcb; //0x2c8
        };
        struct {
            UCHAR SchedulerApcFill4[72]; //0x288
            VOID* LegoData; //0x2d0
        };
        struct {
            UCHAR SchedulerApcFill5[83]; //0x288
            UCHAR CallbackNestingLevel; //0x2db
            ULONG UserTime; //0x2dc
        };
    };
    struct _KEVENT SuspendEvent; //0x2e0
    struct _LIST_ENTRY ThreadListEntry; //0x2f8
    struct _LIST_ENTRY MutantListHead; //0x308
    UCHAR AbEntrySummary; //0x318
    UCHAR AbWaitEntryCount; //0x319
    UCHAR AbAllocationRegionCount; //0x31a
    CHAR SystemPriority; //0x31b
    ULONG SecureThreadCookie; //0x31c
    struct _KLOCK_ENTRY* LockEntries; //0x320
    struct _SINGLE_LIST_ENTRY PropagateBoostsEntry; //0x328
    struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry; //0x330
    UCHAR PriorityFloorCounts[16]; //0x338
    UCHAR PriorityFloorCountsReserved[16]; //0x348
    ULONG PriorityFloorSummary; //0x358
    volatile LONG AbCompletedIoBoostCount; //0x35c
    volatile LONG AbCompletedIoQoSBoostCount; //0x360
    volatile SHORT KeReferenceCount; //0x364
    UCHAR AbOrphanedEntrySummary; //0x366
    UCHAR AbOwnedEntryCount; //0x367
    ULONG ForegroundLossTime; //0x368
    union {
        struct _LIST_ENTRY GlobalForegroundListEntry; //0x370
        struct {
            struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry; //0x370
            ULONGLONG InGlobalForegroundList; //0x378
        };
    };
    LONGLONG ReadOperationCount; //0x380
    LONGLONG WriteOperationCount; //0x388
    LONGLONG OtherOperationCount; //0x390
    LONGLONG ReadTransferCount; //0x398
    LONGLONG WriteTransferCount; //0x3a0
    LONGLONG OtherTransferCount; //0x3a8
    struct _KSCB* QueuedScb; //0x3b0
    volatile ULONG ThreadTimerDelay; //0x3b8
    union {
        volatile LONG ThreadFlags3; //0x3bc
        struct {
            ULONG ThreadFlags3Reserved : 8; //0x3bc
            ULONG PpmPolicy : 2; //0x3bc
            ULONG ThreadFlags3Reserved2 : 22; //0x3bc
        };
    };
    ULONGLONG TracingPrivate[1]; //0x3c0
    VOID* SchedulerAssist; //0x3c8
    VOID* volatile AbWaitObject; //0x3d0
    ULONG ReservedPreviousReadyTimeValue; //0x3d8
    ULONGLONG KernelWaitTime; //0x3e0
    ULONGLONG UserWaitTime; //0x3e8
    union {
        struct _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry; //0x3f0
        struct {
            struct _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry; //0x3f0
            ULONGLONG InGlobalUpdateVpThreadPriorityList; //0x3f8
        };
    };
    LONG SchedulerAssistPriorityFloor; //0x400
    ULONG Spare28; //0x404
    ULONGLONG EndPadding[5]; //0x408
};

struct _PRIMITIVE_UNICODE_STRING {
    USHORT Length; //0x0
    USHORT MaximumLength; //0x2
    WCHAR* Buffer; //0x8
};

struct _DRIVER_OBJECT {
    SHORT Type; //0x0
    SHORT Size; //0x2
    struct _DEVICE_OBJECT* DeviceObject; //0x8
    ULONG Flags; //0x10
    VOID* DriverStart; //0x18
    ULONG DriverSize; //0x20
    VOID* DriverSection; //0x28
    struct _DRIVER_EXTENSION* DriverExtension; //0x30
    struct _PRIMITIVE_UNICODE_STRING DriverName; //0x38
    struct _PRIMITIVE_UNICODE_STRING* HardwareDatabase; //0x48
    struct _FAST_IO_DISPATCH* FastIoDispatch; //0x50
    LONG (*DriverInit)(struct _DRIVER_OBJECT* arg1, struct _UNICODE_STRING* arg2); //0x58
    VOID (*DriverStartIo)(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2); //0x60
    VOID (*DriverUnload)(struct _DRIVER_OBJECT* arg1); //0x68
    LONG (*MajorFunction[28])(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2); //0x70
};

struct _KDEVICE_QUEUE_ENTRY {
    struct _LIST_ENTRY DeviceListEntry; //0x0
    ULONG SortKey; //0x10
    UCHAR Inserted; //0x14
};
struct _WAIT_CONTEXT_BLOCK {
    union {
        struct _KDEVICE_QUEUE_ENTRY WaitQueueEntry; //0x0
        struct {
            struct _LIST_ENTRY DmaWaitEntry; //0x0
            ULONG NumberOfChannels; //0x10
            ULONG SyncCallback : 1; //0x14
            ULONG DmaContext : 1; //0x14
            ULONG ZeroMapRegisters : 1; //0x14
            ULONG Reserved : 9; //0x14
            ULONG NumberOfRemapPages : 20; //0x14
        };
    };
    enum _IO_ALLOCATION_ACTION (*DeviceRoutine)(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2, VOID* arg3, VOID* arg4); //0x18
    VOID* DeviceContext; //0x20
    ULONG NumberOfMapRegisters; //0x28
    VOID* DeviceObject; //0x30
    VOID* CurrentIrp; //0x38
    struct _KDPC* BufferChainingDpc; //0x40
};

struct _KDEVICE_QUEUE {
    SHORT Type; //0x0
    SHORT Size; //0x2
    struct _LIST_ENTRY DeviceListHead; //0x8
    ULONGLONG Lock; //0x18
    union {
        UCHAR Busy; //0x20
        struct {
            LONGLONG Reserved : 8; //0x20
            LONGLONG Hint : 56; //0x20
        };
    };
};

struct _KDPC {
    union {
        ULONG TargetInfoAsUlong; //0x0
        struct {
            UCHAR Type; //0x0
            UCHAR Importance; //0x1
            volatile USHORT Number; //0x2
        };
    };
    struct _SINGLE_LIST_ENTRY DpcListEntry; //0x8
    ULONGLONG ProcessorHistory; //0x10
    VOID (*DeferredRoutine)(struct _KDPC* arg1, VOID* arg2, VOID* arg3, VOID* arg4); //0x18
    VOID* DeferredContext; //0x20
    VOID* SystemArgument1; //0x28
    VOID* SystemArgument2; //0x30
    VOID* DpcData; //0x38
};

struct _DEVICE_OBJECT {
    SHORT Type; //0x0
    USHORT Size; //0x2
    LONG ReferenceCount; //0x4
    struct _DRIVER_OBJECT* DriverObject; //0x8
    struct _DEVICE_OBJECT* NextDevice; //0x10
    struct _DEVICE_OBJECT* AttachedDevice; //0x18
    struct _IRP* CurrentIrp; //0x20
    struct _IO_TIMER* Timer; //0x28
    ULONG Flags; //0x30
    ULONG Characteristics; //0x34
    struct _VPB* Vpb; //0x38
    VOID* DeviceExtension; //0x40
    ULONG DeviceType; //0x48
    CHAR StackSize; //0x4c
    union {
        struct _LIST_ENTRY ListEntry; //0x50
        struct _WAIT_CONTEXT_BLOCK Wcb; //0x50
    } Queue; //0x50
    ULONG AlignmentRequirement; //0x98
    struct _KDEVICE_QUEUE DeviceQueue; //0xa0
    struct _KDPC Dpc; //0xc8
    ULONG ActiveThreadCount; //0x108
    VOID* SecurityDescriptor; //0x110
    struct _KEVENT DeviceLock; //0x118
    USHORT SectorSize; //0x130
    USHORT Spare1; //0x132
    struct _DEVOBJ_EXTENSION* DeviceObjectExtension; //0x138
    VOID* Reserved; //0x140
};

struct _EX_PUSH_LOCK {
    union {
        struct {
            ULONGLONG Locked : 1; //0x0
            ULONGLONG Waiting : 1; //0x0
            ULONGLONG Waking : 1; //0x0
            ULONGLONG MultipleShared : 1; //0x0
            ULONGLONG Shared : 60; //0x0
        };
        ULONGLONG Value; //0x0
        VOID* Ptr; //0x0
    };
};

struct _EX_RUNDOWN_REF {
    union {
        ULONGLONG Count; //0x0
        VOID* Ptr; //0x0
    };
};

struct _EX_FAST_REF {
    union {
        VOID* Object; //0x0
        ULONGLONG RefCnt : 4; //0x0
        ULONGLONG Value; //0x0
    };
};

struct _RTL_AVL_TREE {
    struct _RTL_BALANCED_NODE* Root; //0x0
};

struct _SE_AUDIT_PROCESS_CREATION_INFO {
    struct _OBJECT_NAME_INFORMATION* ImageFileName; //0x0
};

struct _ALPC_PROCESS_CONTEXT {
    struct _EX_PUSH_LOCK Lock; //0x0
    struct _LIST_ENTRY ViewListHead; //0x8
    volatile ULONGLONG PagedPoolQuotaCache; //0x18
};

struct _PS_PROTECTION {
    union {
        UCHAR Level; //0x0
        struct {
            UCHAR Type : 3; //0x0
            UCHAR Audit : 1; //0x0
            UCHAR Signer : 4; //0x0
        };
    };
};

struct _MMSUPPORT_FLAGS {
    union {
        struct {
            UCHAR WorkingSetType : 3; //0x0
            UCHAR Reserved0 : 3; //0x0
            UCHAR MaximumWorkingSetHard : 1; //0x0
            UCHAR MinimumWorkingSetHard : 1; //0x0
            UCHAR SessionMaster : 1; //0x1
            UCHAR TrimmerState : 2; //0x1
            UCHAR Reserved : 1; //0x1
            UCHAR PageStealers : 4; //0x1
        };
        USHORT u1; //0x0
    };
    UCHAR MemoryPriority; //0x2
    union {
        struct {
            UCHAR WsleDeleted : 1; //0x3
            UCHAR SvmEnabled : 1; //0x3
            UCHAR ForceAge : 1; //0x3
            UCHAR ForceTrim : 1; //0x3
            UCHAR NewMaximum : 1; //0x3
            UCHAR CommitReleaseState : 2; //0x3
        };
        UCHAR u2; //0x3
    };
};

struct _MMSUPPORT_INSTANCE {
    ULONG NextPageColor; //0x0
    ULONG PageFaultCount; //0x4
    ULONGLONG TrimmedPageCount; //0x8
    struct _MMWSL_INSTANCE* VmWorkingSetList; //0x10
    struct _LIST_ENTRY WorkingSetExpansionLinks; //0x18
    ULONGLONG AgeDistribution[8]; //0x28
    struct _KGATE* ExitOutswapGate; //0x68
    ULONGLONG MinimumWorkingSetSize; //0x70
    ULONGLONG WorkingSetLeafSize; //0x78
    ULONGLONG WorkingSetLeafPrivateSize; //0x80
    ULONGLONG WorkingSetSize; //0x88
    ULONGLONG WorkingSetPrivateSize; //0x90
    ULONGLONG MaximumWorkingSetSize; //0x98
    ULONGLONG PeakWorkingSetSize; //0xa0
    ULONG HardFaultCount; //0xa8
    USHORT LastTrimStamp; //0xac
    USHORT PartitionId; //0xae
    ULONGLONG SelfmapLock; //0xb0
    struct _MMSUPPORT_FLAGS Flags; //0xb8
};

struct _MMSUPPORT_SHARED {
    volatile LONG WorkingSetLock; //0x0
    LONG GoodCitizenWaiting; //0x4
    ULONGLONG ReleasedCommitDebt; //0x8
    ULONGLONG ResetPagesRepurposedCount; //0x10
    VOID* WsSwapSupport; //0x18
    VOID* CommitReleaseContext; //0x20
    VOID* AccessLog; //0x28
    volatile ULONGLONG ChargedWslePages; //0x30
    ULONGLONG ActualWslePages; //0x38
    ULONGLONG WorkingSetCoreLock; //0x40
    VOID* ShadowMapping; //0x48
};

struct _MMSUPPORT_FULL {
    struct _MMSUPPORT_INSTANCE Instance; //0x0
    struct _MMSUPPORT_SHARED Shared; //0xc0
};

union _PS_INTERLOCKED_TIMER_DELAY_VALUES {
    ULONGLONG DelayMs : 30; //0x0
    ULONGLONG CoalescingWindowMs : 30; //0x0
    ULONGLONG Reserved : 1; //0x0
    ULONGLONG NewTimerWheel : 1; //0x0
    ULONGLONG Retry : 1; //0x0
    ULONGLONG Locked : 1; //0x0
    ULONGLONG All; //0x0
};

struct _WNF_STATE_NAME {
    ULONG Data[2]; //0x0
};

struct _JOBOBJECT_WAKE_FILTER {
    ULONG HighEdgeFilter; //0x0
    ULONG LowEdgeFilter; //0x4
};

struct _PS_PROCESS_WAKE_INFORMATION {
    ULONGLONG NotificationChannel; //0x0
    ULONG WakeCounters[7]; //0x8
    struct _JOBOBJECT_WAKE_FILTER WakeFilter; //0x24
    ULONG NoWakeCounter; //0x2c
};

struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES {
    struct _RTL_AVL_TREE Tree; //0x0
    struct _EX_PUSH_LOCK Lock; //0x8
};

struct _CLIENT_ID {
    VOID* UniqueProcess; //0x0
    VOID* UniqueThread; //0x8
};

struct _KSEMAPHORE {
    struct _DISPATCHER_HEADER Header; //0x0
    LONG Limit; //0x18
};

union _PS_CLIENT_SECURITY_CONTEXT {
    ULONGLONG ImpersonationData; //0x0
    VOID* ImpersonationToken; //0x0
    ULONGLONG ImpersonationLevel : 2; //0x0
    ULONGLONG EffectiveOnly : 1; //0x0
};

struct _PS_PROPERTY_SET {
    struct _LIST_ENTRY ListHead; //0x0
    ULONGLONG Lock; //0x10
};

struct _RTL_BALANCED_NODE {
    union {
        struct _RTL_BALANCED_NODE* Children[2]; //0x0
        struct {
            struct _RTL_BALANCED_NODE* Left; //0x0
            struct _RTL_BALANCED_NODE* Right; //0x8
        };
    };
    union {
        struct {
            UCHAR Red : 1; //0x10
            UCHAR Balance : 2; //0x10
        };
        ULONGLONG ParentValue; //0x10
    };
};

struct _KLOCK_ENTRY_LOCK_STATE {
    union {
        struct {
            ULONGLONG CrossThreadReleasable : 1; //0x0
            ULONGLONG Busy : 1; //0x0
            ULONGLONG Reserved : 61; //0x0
            ULONGLONG InTree : 1; //0x0
        };
        VOID* LockState; //0x0
    };
    union {
        VOID* SessionState; //0x8
        struct {
            ULONG SessionId; //0x8
            ULONG SessionPad; //0xc
        };
    };
};

struct _RTL_RB_TREE {
    struct _RTL_BALANCED_NODE* Root; //0x0
    union {
        UCHAR Encoded : 1; //0x8
        struct _RTL_BALANCED_NODE* Min; //0x8
    };
};

union _KLOCK_ENTRY_BOOST_BITMAP {
    ULONG AllFields; //0x0
    ULONG AllBoosts : 17; //0x0
    ULONG Reserved : 15; //0x0
    USHORT CpuBoostsBitmap : 15; //0x0
    struct {
        USHORT IoBoost : 1; //0x0
        USHORT IoQoSBoost : 1; //0x2
        USHORT IoNormalPriorityWaiterCount : 8; //0x2
    };
    USHORT IoQoSWaiterCount : 7; //0x2
};

struct _KLOCK_ENTRY {
    union {
        struct _RTL_BALANCED_NODE TreeNode; //0x0
        struct _SINGLE_LIST_ENTRY FreeListEntry; //0x0
    };
    union {
        ULONG EntryFlags; //0x18
        struct {
            UCHAR EntryOffset; //0x18
            union {
                UCHAR ThreadLocalFlags; //0x19
                struct {
                    UCHAR WaitingBit : 1; //0x19
                    UCHAR Spare0 : 7; //0x19
                };
            };
            union {
                UCHAR AcquiredByte; //0x1a
                UCHAR AcquiredBit : 1; //0x1a
            };
            union {
                UCHAR CrossThreadFlags; //0x1b
                struct {
                    UCHAR HeadNodeBit : 1; //0x1b
                    UCHAR IoPriorityBit : 1; //0x1b
                    UCHAR IoQoSWaiter : 1; //0x1b
                    UCHAR Spare1 : 5; //0x1b
                };
            };
        };
        struct {
            ULONG StaticState : 8; //0x18
            ULONG AllFlags : 24; //0x18
        };
    };
    ULONG SpareFlags; //0x1c
    union {
        struct _KLOCK_ENTRY_LOCK_STATE LockState; //0x20
        VOID* volatile LockUnsafe; //0x20
        struct {
            volatile UCHAR CrossThreadReleasableAndBusyByte; //0x20
            UCHAR Reserved[6]; //0x21
            volatile UCHAR InTreeByte; //0x27
            union {
                VOID* SessionState; //0x28
                struct {
                    ULONG SessionId; //0x28
                    ULONG SessionPad; //0x2c
                };
            };
        };
    };
    union {
        struct {
            struct _RTL_RB_TREE OwnerTree; //0x30
            struct _RTL_RB_TREE WaiterTree; //0x40
        };
        CHAR CpuPriorityKey; //0x30
    };
    ULONGLONG EntryLock; //0x50
    union _KLOCK_ENTRY_BOOST_BITMAP BoostBitmap; //0x58
    ULONG SparePad; //0x5c
};

struct _ETHREAD {
    struct _KTHREAD Tcb; //0x0
    union _LARGE_INTEGER CreateTime; //0x430
    union {
        union _LARGE_INTEGER ExitTime; //0x438
        struct _LIST_ENTRY KeyedWaitChain; //0x438
    };
    union {
        struct _LIST_ENTRY PostBlockList; //0x448
        struct {
            VOID* ForwardLinkShadow; //0x448
            VOID* StartAddress; //0x450
        };
    };
    union {
        struct _TERMINATION_PORT* TerminationPort; //0x458
        struct _ETHREAD* ReaperLink; //0x458
        VOID* KeyedWaitValue; //0x458
    };
    ULONGLONG ActiveTimerListLock; //0x460
    struct _LIST_ENTRY ActiveTimerListHead; //0x468
    struct _CLIENT_ID Cid; //0x478
    union {
        struct _KSEMAPHORE KeyedWaitSemaphore; //0x488
        struct _KSEMAPHORE AlpcWaitSemaphore; //0x488
    };
    union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity; //0x4a8
    struct _LIST_ENTRY IrpList; //0x4b0
    ULONGLONG TopLevelIrp; //0x4c0
    struct _DEVICE_OBJECT* DeviceToVerify; //0x4c8
    VOID* Win32StartAddress; //0x4d0
    VOID* ChargeOnlySession; //0x4d8
    VOID* LegacyPowerObject; //0x4e0
    struct _LIST_ENTRY ThreadListEntry; //0x4e8
    struct _EX_RUNDOWN_REF RundownProtect; //0x4f8
    struct _EX_PUSH_LOCK ThreadLock; //0x500
    ULONG ReadClusterSize; //0x508
    volatile LONG MmLockOrdering; //0x50c
    union {
        ULONG CrossThreadFlags; //0x510
        struct {
            ULONG Terminated : 1; //0x510
            ULONG ThreadInserted : 1; //0x510
            ULONG HideFromDebugger : 1; //0x510
            ULONG ActiveImpersonationInfo : 1; //0x510
            ULONG HardErrorsAreDisabled : 1; //0x510
            ULONG BreakOnTermination : 1; //0x510
            ULONG SkipCreationMsg : 1; //0x510
            ULONG SkipTerminationMsg : 1; //0x510
            ULONG CopyTokenOnOpen : 1; //0x510
            ULONG ThreadIoPriority : 3; //0x510
            ULONG ThreadPagePriority : 3; //0x510
            ULONG RundownFail : 1; //0x510
            ULONG UmsForceQueueTermination : 1; //0x510
            ULONG IndirectCpuSets : 1; //0x510
            ULONG DisableDynamicCodeOptOut : 1; //0x510
            ULONG ExplicitCaseSensitivity : 1; //0x510
            ULONG PicoNotifyExit : 1; //0x510
            ULONG DbgWerUserReportActive : 1; //0x510
            ULONG ForcedSelfTrimActive : 1; //0x510
            ULONG SamplingCoverage : 1; //0x510
            ULONG ReservedCrossThreadFlags : 8; //0x510
        };
    };
    union {
        ULONG SameThreadPassiveFlags; //0x514
        struct {
            ULONG ActiveExWorker : 1; //0x514
            ULONG MemoryMaker : 1; //0x514
            ULONG StoreLockThread : 2; //0x514
            ULONG ClonedThread : 1; //0x514
            ULONG KeyedEventInUse : 1; //0x514
            ULONG SelfTerminate : 1; //0x514
            ULONG RespectIoPriority : 1; //0x514
            ULONG ActivePageLists : 1; //0x514
            ULONG SecureContext : 1; //0x514
            ULONG ZeroPageThread : 1; //0x514
            ULONG WorkloadClass : 1; //0x514
            ULONG ReservedSameThreadPassiveFlags : 20; //0x514
        };
    };
    union {
        ULONG SameThreadApcFlags; //0x518
        struct {
            UCHAR OwnsProcessAddressSpaceExclusive : 1; //0x518
            UCHAR OwnsProcessAddressSpaceShared : 1; //0x518
            UCHAR HardFaultBehavior : 1; //0x518
            volatile UCHAR StartAddressInvalid : 1; //0x518
            UCHAR EtwCalloutActive : 1; //0x518
            UCHAR SuppressSymbolLoad : 1; //0x518
            UCHAR Prefetching : 1; //0x518
            UCHAR OwnsVadExclusive : 1; //0x518
            UCHAR SystemPagePriorityActive : 1; //0x519
            UCHAR SystemPagePriority : 3; //0x519
            UCHAR AllowUserWritesToExecutableMemory : 1; //0x519
            UCHAR AllowKernelWritesToExecutableMemory : 1; //0x519
            UCHAR OwnsVadShared : 1; //0x519
        };
    };
    UCHAR CacheManagerActive; //0x51c
    UCHAR DisablePageFaultClustering; //0x51d
    UCHAR ActiveFaultCount; //0x51e
    UCHAR LockOrderState; //0x51f
    ULONG PerformanceCountLowReserved; //0x520
    LONG PerformanceCountHighReserved; //0x524
    ULONGLONG AlpcMessageId; //0x528
    union {
        VOID* AlpcMessage; //0x530
        ULONG AlpcReceiveAttributeSet; //0x530
    };
    struct _LIST_ENTRY AlpcWaitListEntry; //0x538
    LONG ExitStatus; //0x548
    ULONG CacheManagerCount; //0x54c
    ULONG IoBoostCount; //0x550
    ULONG IoQoSBoostCount; //0x554
    ULONG IoQoSThrottleCount; //0x558
    ULONG KernelStackReference; //0x55c
    struct _LIST_ENTRY BoostList; //0x560
    struct _LIST_ENTRY DeboostList; //0x570
    ULONGLONG BoostListLock; //0x580
    ULONGLONG IrpListLock; //0x588
    VOID* ReservedForSynchTracking; //0x590
    struct _SINGLE_LIST_ENTRY CmCallbackListHead; //0x598
    struct _GUID* ActivityId; //0x5a0
    struct _SINGLE_LIST_ENTRY SeLearningModeListHead; //0x5a8
    VOID* VerifierContext; //0x5b0
    VOID* AdjustedClientToken; //0x5b8
    VOID* WorkOnBehalfThread; //0x5c0
    struct _PS_PROPERTY_SET PropertySet; //0x5c8
    VOID* PicoContext; //0x5e0
    ULONGLONG UserFsBase; //0x5e8
    ULONGLONG UserGsBase; //0x5f0
    struct _THREAD_ENERGY_VALUES* EnergyValues; //0x5f8
    union {
        ULONGLONG SelectedCpuSets; //0x600
        ULONGLONG* SelectedCpuSetsIndirect; //0x600
    };
    struct _EJOB* Silo; //0x608
    struct _UNICODE_STRING* ThreadName; //0x610
    struct _CONTEXT* SetContextState; //0x618
    ULONG LastExpectedRunTime; //0x620
    ULONG HeapData; //0x624
    struct _LIST_ENTRY OwnerEntryListHead; //0x628
    ULONGLONG DisownedOwnerEntryListLock; //0x638
    struct _LIST_ENTRY DisownedOwnerEntryListHead; //0x640
    struct _KLOCK_ENTRY LockEntries[6]; //0x650
    VOID* CmDbgInfo; //0x890
};

struct _EPROCESS {
    struct _KPROCESS Pcb; //0x0
    struct _EX_PUSH_LOCK ProcessLock; //0x438
    VOID* UniqueProcessId; //0x440
    struct _LIST_ENTRY ActiveProcessLinks; //0x448
    struct _EX_RUNDOWN_REF RundownProtect; //0x458
    union {
        ULONG Flags2; //0x460
        struct {
            ULONG JobNotReallyActive : 1; //0x460
            ULONG AccountingFolded : 1; //0x460
            ULONG NewProcessReported : 1; //0x460
            ULONG ExitProcessReported : 1; //0x460
            ULONG ReportCommitChanges : 1; //0x460
            ULONG LastReportMemory : 1; //0x460
            ULONG ForceWakeCharge : 1; //0x460
            ULONG CrossSessionCreate : 1; //0x460
            ULONG NeedsHandleRundown : 1; //0x460
            ULONG RefTraceEnabled : 1; //0x460
            ULONG PicoCreated : 1; //0x460
            ULONG EmptyJobEvaluated : 1; //0x460
            ULONG DefaultPagePriority : 3; //0x460
            ULONG PrimaryTokenFrozen : 1; //0x460
            ULONG ProcessVerifierTarget : 1; //0x460
            ULONG RestrictSetThreadContext : 1; //0x460
            ULONG AffinityPermanent : 1; //0x460
            ULONG AffinityUpdateEnable : 1; //0x460
            ULONG PropagateNode : 1; //0x460
            ULONG ExplicitAffinity : 1; //0x460
            ULONG ProcessExecutionState : 2; //0x460
            ULONG EnableReadVmLogging : 1; //0x460
            ULONG EnableWriteVmLogging : 1; //0x460
            ULONG FatalAccessTerminationRequested : 1; //0x460
            ULONG DisableSystemAllowedCpuSet : 1; //0x460
            ULONG ProcessStateChangeRequest : 2; //0x460
            ULONG ProcessStateChangeInProgress : 1; //0x460
            ULONG InPrivate : 1; //0x460
        };
    };
    union {
        ULONG Flags; //0x464
        struct {
            ULONG CreateReported : 1; //0x464
            ULONG NoDebugInherit : 1; //0x464
            ULONG ProcessExiting : 1; //0x464
            ULONG ProcessDelete : 1; //0x464
            ULONG ManageExecutableMemoryWrites : 1; //0x464
            ULONG VmDeleted : 1; //0x464
            ULONG OutswapEnabled : 1; //0x464
            ULONG Outswapped : 1; //0x464
            ULONG FailFastOnCommitFail : 1; //0x464
            ULONG Wow64VaSpace4Gb : 1; //0x464
            ULONG AddressSpaceInitialized : 2; //0x464
            ULONG SetTimerResolution : 1; //0x464
            ULONG BreakOnTermination : 1; //0x464
            ULONG DeprioritizeViews : 1; //0x464
            ULONG WriteWatch : 1; //0x464
            ULONG ProcessInSession : 1; //0x464
            ULONG OverrideAddressSpace : 1; //0x464
            ULONG HasAddressSpace : 1; //0x464
            ULONG LaunchPrefetched : 1; //0x464
            ULONG Background : 1; //0x464
            ULONG VmTopDown : 1; //0x464
            ULONG ImageNotifyDone : 1; //0x464
            ULONG PdeUpdateNeeded : 1; //0x464
            ULONG VdmAllowed : 1; //0x464
            ULONG ProcessRundown : 1; //0x464
            ULONG ProcessInserted : 1; //0x464
            ULONG DefaultIoPriority : 3; //0x464
            ULONG ProcessSelfDelete : 1; //0x464
            ULONG SetTimerResolutionLink : 1; //0x464
        };
    };
    union _LARGE_INTEGER CreateTime; //0x468
    ULONGLONG ProcessQuotaUsage[2]; //0x470
    ULONGLONG ProcessQuotaPeak[2]; //0x480
    ULONGLONG PeakVirtualSize; //0x490
    ULONGLONG VirtualSize; //0x498
    struct _LIST_ENTRY SessionProcessLinks; //0x4a0
    union {
        VOID* ExceptionPortData; //0x4b0
        ULONGLONG ExceptionPortValue; //0x4b0
        ULONGLONG ExceptionPortState : 3; //0x4b0
    };
    struct _EX_FAST_REF Token; //0x4b8
    ULONGLONG MmReserved; //0x4c0
    struct _EX_PUSH_LOCK AddressCreationLock; //0x4c8
    struct _EX_PUSH_LOCK PageTableCommitmentLock; //0x4d0
    struct _ETHREAD* RotateInProgress; //0x4d8
    struct _ETHREAD* ForkInProgress; //0x4e0
    struct _EJOB* volatile CommitChargeJob; //0x4e8
    struct _RTL_AVL_TREE CloneRoot; //0x4f0
    volatile ULONGLONG NumberOfPrivatePages; //0x4f8
    volatile ULONGLONG NumberOfLockedPages; //0x500
    VOID* Win32Process; //0x508
    struct _EJOB* volatile Job; //0x510
    VOID* SectionObject; //0x518
    VOID* SectionBaseAddress; //0x520
    ULONG Cookie; //0x528
    struct _PAGEFAULT_HISTORY* WorkingSetWatch; //0x530
    VOID* Win32WindowStation; //0x538
    VOID* InheritedFromUniqueProcessId; //0x540
    volatile ULONGLONG OwnerProcessId; //0x548
    struct _PEB* Peb; //0x550
    struct _MM_SESSION_SPACE* Session; //0x558
    VOID* Spare1; //0x560
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock; //0x568
    struct _HANDLE_TABLE* ObjectTable; //0x570
    VOID* DebugPort; //0x578
    struct _EWOW64PROCESS* WoW64Process; //0x580
    VOID* DeviceMap; //0x588
    VOID* EtwDataSource; //0x590
    ULONGLONG PageDirectoryPte; //0x598
    struct _FILE_OBJECT* ImageFilePointer; //0x5a0
    UCHAR ImageFileName[15]; //0x5a8
    UCHAR PriorityClass; //0x5b7
    VOID* SecurityPort; //0x5b8
    struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo; //0x5c0
    struct _LIST_ENTRY JobLinks; //0x5c8
    VOID* HighestUserAddress; //0x5d8
    struct _LIST_ENTRY ThreadListHead; //0x5e0
    volatile ULONG ActiveThreads; //0x5f0
    ULONG ImagePathHash; //0x5f4
    ULONG DefaultHardErrorProcessing; //0x5f8
    LONG LastThreadExitStatus; //0x5fc
    struct _EX_FAST_REF PrefetchTrace; //0x600
    VOID* LockedPagesList; //0x608
    union _LARGE_INTEGER ReadOperationCount; //0x610
    union _LARGE_INTEGER WriteOperationCount; //0x618
    union _LARGE_INTEGER OtherOperationCount; //0x620
    union _LARGE_INTEGER ReadTransferCount; //0x628
    union _LARGE_INTEGER WriteTransferCount; //0x630
    union _LARGE_INTEGER OtherTransferCount; //0x638
    ULONGLONG CommitChargeLimit; //0x640
    volatile ULONGLONG CommitCharge; //0x648
    volatile ULONGLONG CommitChargePeak; //0x650
    struct _MMSUPPORT_FULL Vm; //0x680
    struct _LIST_ENTRY MmProcessLinks; //0x7c0
    ULONG ModifiedPageCount; //0x7d0
    LONG ExitStatus; //0x7d4
    struct _RTL_AVL_TREE VadRoot; //0x7d8
    VOID* VadHint; //0x7e0
    ULONGLONG VadCount; //0x7e8
    volatile ULONGLONG VadPhysicalPages; //0x7f0
    ULONGLONG VadPhysicalPagesLimit; //0x7f8
    struct _ALPC_PROCESS_CONTEXT AlpcContext; //0x800
    struct _LIST_ENTRY TimerResolutionLink; //0x820
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord; //0x830
    ULONG RequestedTimerResolution; //0x838
    ULONG SmallestTimerResolution; //0x83c
    union _LARGE_INTEGER ExitTime; //0x840
    struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable; //0x848
    struct _EX_PUSH_LOCK InvertedFunctionTableLock; //0x850
    ULONG ActiveThreadsHighWatermark; //0x858
    ULONG LargePrivateVadCount; //0x85c
    struct _EX_PUSH_LOCK ThreadListLock; //0x860
    VOID* WnfContext; //0x868
    struct _EJOB* ServerSilo; //0x870
    UCHAR SignatureLevel; //0x878
    UCHAR SectionSignatureLevel; //0x879
    struct _PS_PROTECTION Protection; //0x87a
    UCHAR HangCount : 3; //0x87b
    UCHAR GhostCount : 3; //0x87b
    UCHAR PrefilterException : 1; //0x87b
    union {
        ULONG Flags3; //0x87c
        struct {
            ULONG Minimal : 1; //0x87c
            ULONG ReplacingPageRoot : 1; //0x87c
            ULONG Crashed : 1; //0x87c
            ULONG JobVadsAreTracked : 1; //0x87c
            ULONG VadTrackingDisabled : 1; //0x87c
            ULONG AuxiliaryProcess : 1; //0x87c
            ULONG SubsystemProcess : 1; //0x87c
            ULONG IndirectCpuSets : 1; //0x87c
            ULONG RelinquishedCommit : 1; //0x87c
            ULONG HighGraphicsPriority : 1; //0x87c
            ULONG CommitFailLogged : 1; //0x87c
            ULONG ReserveFailLogged : 1; //0x87c
            ULONG SystemProcess : 1; //0x87c
            ULONG HideImageBaseAddresses : 1; //0x87c
            ULONG AddressPolicyFrozen : 1; //0x87c
            ULONG ProcessFirstResume : 1; //0x87c
            ULONG ForegroundExternal : 1; //0x87c
            ULONG ForegroundSystem : 1; //0x87c
            ULONG HighMemoryPriority : 1; //0x87c
            ULONG EnableProcessSuspendResumeLogging : 1; //0x87c
            ULONG EnableThreadSuspendResumeLogging : 1; //0x87c
            ULONG SecurityDomainChanged : 1; //0x87c
            ULONG SecurityFreezeComplete : 1; //0x87c
            ULONG VmProcessorHost : 1; //0x87c
            ULONG VmProcessorHostTransition : 1; //0x87c
            ULONG AltSyscall : 1; //0x87c
            ULONG TimerResolutionIgnore : 1; //0x87c
            ULONG DisallowUserTerminate : 1; //0x87c
        };
    };
    LONG DeviceAsid; //0x880
    VOID* SvmData; //0x888
    struct _EX_PUSH_LOCK SvmProcessLock; //0x890
    ULONGLONG SvmLock; //0x898
    struct _LIST_ENTRY SvmProcessDeviceListHead; //0x8a0
    ULONGLONG LastFreezeInterruptTime; //0x8b0
    struct _PROCESS_DISK_COUNTERS* DiskCounters; //0x8b8
    VOID* PicoContext; //0x8c0
    VOID* EnclaveTable; //0x8c8
    ULONGLONG EnclaveNumber; //0x8d0
    struct _EX_PUSH_LOCK EnclaveLock; //0x8d8
    ULONG HighPriorityFaultsAllowed; //0x8e0
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext; //0x8e8
    VOID* VmContext; //0x8f0
    ULONGLONG SequenceNumber; //0x8f8
    ULONGLONG CreateInterruptTime; //0x900
    ULONGLONG CreateUnbiasedInterruptTime; //0x908
    ULONGLONG TotalUnbiasedFrozenTime; //0x910
    ULONGLONG LastAppStateUpdateTime; //0x918
    ULONGLONG LastAppStateUptime : 61; //0x920
    ULONGLONG LastAppState : 3; //0x920
    volatile ULONGLONG SharedCommitCharge; //0x928
    struct _EX_PUSH_LOCK SharedCommitLock; //0x930
    struct _LIST_ENTRY SharedCommitLinks; //0x938
    union {
        struct {
            ULONGLONG AllowedCpuSets; //0x948
            ULONGLONG DefaultCpuSets; //0x950
        };
        struct {
            ULONGLONG* AllowedCpuSetsIndirect; //0x948
            ULONGLONG* DefaultCpuSetsIndirect; //0x950
        };
    };
    VOID* DiskIoAttribution; //0x958
    VOID* DxgProcess; //0x960
    ULONG Win32KFilterSet; //0x968
    union _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay; //0x970
    volatile ULONG KTimerSets; //0x978
    volatile ULONG KTimer2Sets; //0x97c
    volatile ULONG ThreadTimerSets; //0x980
    ULONGLONG VirtualTimerListLock; //0x988
    struct _LIST_ENTRY VirtualTimerListHead; //0x990
    union {
        struct _WNF_STATE_NAME WakeChannel; //0x9a0
        struct _PS_PROCESS_WAKE_INFORMATION WakeInfo; //0x9a0
    };
    union {
        ULONG MitigationFlags; //0x9d0
        struct {
            ULONG ControlFlowGuardEnabled : 1; //0x9d0
            ULONG ControlFlowGuardExportSuppressionEnabled : 1; //0x9d0
            ULONG ControlFlowGuardStrict : 1; //0x9d0
            ULONG DisallowStrippedImages : 1; //0x9d0
            ULONG ForceRelocateImages : 1; //0x9d0
            ULONG HighEntropyASLREnabled : 1; //0x9d0
            ULONG StackRandomizationDisabled : 1; //0x9d0
            ULONG ExtensionPointDisable : 1; //0x9d0
            ULONG DisableDynamicCode : 1; //0x9d0
            ULONG DisableDynamicCodeAllowOptOut : 1; //0x9d0
            ULONG DisableDynamicCodeAllowRemoteDowngrade : 1; //0x9d0
            ULONG AuditDisableDynamicCode : 1; //0x9d0
            ULONG DisallowWin32kSystemCalls : 1; //0x9d0
            ULONG AuditDisallowWin32kSystemCalls : 1; //0x9d0
            ULONG EnableFilteredWin32kAPIs : 1; //0x9d0
            ULONG AuditFilteredWin32kAPIs : 1; //0x9d0
            ULONG DisableNonSystemFonts : 1; //0x9d0
            ULONG AuditNonSystemFontLoading : 1; //0x9d0
            ULONG PreferSystem32Images : 1; //0x9d0
            ULONG ProhibitRemoteImageMap : 1; //0x9d0
            ULONG AuditProhibitRemoteImageMap : 1; //0x9d0
            ULONG ProhibitLowILImageMap : 1; //0x9d0
            ULONG AuditProhibitLowILImageMap : 1; //0x9d0
            ULONG SignatureMitigationOptIn : 1; //0x9d0
            ULONG AuditBlockNonMicrosoftBinaries : 1; //0x9d0
            ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1; //0x9d0
            ULONG LoaderIntegrityContinuityEnabled : 1; //0x9d0
            ULONG AuditLoaderIntegrityContinuity : 1; //0x9d0
            ULONG EnableModuleTamperingProtection : 1; //0x9d0
            ULONG EnableModuleTamperingProtectionNoInherit : 1; //0x9d0
            ULONG RestrictIndirectBranchPrediction : 1; //0x9d0
            ULONG IsolateSecurityDomain : 1; //0x9d0
        } MitigationFlagsValues; //0x9d0
    };
    union {
        ULONG MitigationFlags2; //0x9d4
        struct {
            ULONG EnableExportAddressFilter : 1; //0x9d4
            ULONG AuditExportAddressFilter : 1; //0x9d4
            ULONG EnableExportAddressFilterPlus : 1; //0x9d4
            ULONG AuditExportAddressFilterPlus : 1; //0x9d4
            ULONG EnableRopStackPivot : 1; //0x9d4
            ULONG AuditRopStackPivot : 1; //0x9d4
            ULONG EnableRopCallerCheck : 1; //0x9d4
            ULONG AuditRopCallerCheck : 1; //0x9d4
            ULONG EnableRopSimExec : 1; //0x9d4
            ULONG AuditRopSimExec : 1; //0x9d4
            ULONG EnableImportAddressFilter : 1; //0x9d4
            ULONG AuditImportAddressFilter : 1; //0x9d4
            ULONG DisablePageCombine : 1; //0x9d4
            ULONG SpeculativeStoreBypassDisable : 1; //0x9d4
            ULONG CetUserShadowStacks : 1; //0x9d4
            ULONG AuditCetUserShadowStacks : 1; //0x9d4
            ULONG AuditCetUserShadowStacksLogged : 1; //0x9d4
            ULONG UserCetSetContextIpValidation : 1; //0x9d4
            ULONG AuditUserCetSetContextIpValidation : 1; //0x9d4
            ULONG AuditUserCetSetContextIpValidationLogged : 1; //0x9d4
            ULONG CetUserShadowStacksStrictMode : 1; //0x9d4
            ULONG BlockNonCetBinaries : 1; //0x9d4
            ULONG BlockNonCetBinariesNonEhcont : 1; //0x9d4
            ULONG AuditBlockNonCetBinaries : 1; //0x9d4
            ULONG AuditBlockNonCetBinariesLogged : 1; //0x9d4
            ULONG Reserved1 : 1; //0x9d4
            ULONG Reserved2 : 1; //0x9d4
            ULONG Reserved3 : 1; //0x9d4
            ULONG Reserved4 : 1; //0x9d4
            ULONG Reserved5 : 1; //0x9d4
            ULONG CetDynamicApisOutOfProcOnly : 1; //0x9d4
            ULONG UserCetSetContextIpValidationRelaxedMode : 1; //0x9d4
        } MitigationFlags2Values; //0x9d4
    };
    VOID* PartitionObject; //0x9d8
    ULONGLONG SecurityDomain; //0x9e0
    ULONGLONG ParentSecurityDomain; //0x9e8
    VOID* CoverageSamplerContext; //0x9f0
    VOID* MmHotPatchContext; //0x9f8
    struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree; //0xa00
    struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock; //0xa08
    struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges; //0xa10
    ULONG DisabledComponentFlags; //0xa20
};

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // qs: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // 80
    ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage,
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange, // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures,
    ProcessAltPrefetchParam, // since 22H1
    ProcessAssignCpuPartitions,
    ProcessPriorityClassEx,
    ProcessMembershipInformation,
    ProcessEffectiveIoPriority,
    ProcessEffectivePagePriority,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION {
    GUID BootIdentifier;
    FIRMWARE_TYPE FirmwareType;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

struct RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    uint64_t MappedBase;
    uint64_t ImageBase;
    uint32_t ImageSize;
    uint32_t Flags;
    uint16_t LoadOrderIndex;
    uint16_t InitOrderIndex;
    uint16_t LoadCount;
    uint16_t OffsetToFileName;
    uint8_t FullPathName[256];
};

struct RTL_PROCESS_MODULES {
    uint32_t NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
};

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;

typedef struct _FAST_MUTEX {
    LONG Count;
    _KTHREAD* Owner;
    ULONG Contention;
    _KEVENT Gate;
    ULONG OldIrql;
} FAST_MUTEX, *PFAST_MUTEX;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
    SystemModuleInformation1, // q: RTL_PROCESS_MODULES
    SystemLocksInformation, // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation, // not implemented
    SystemNonPagedPoolInformation, // not implemented
    SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation, // not implemented // 20
    SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemLoadGdiDriverInformation, // s (kernel-mode only)
    SystemUnloadGdiDriverInformation, // s (kernel-mode only)
    SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0, // not implemented
    SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeperation, // s (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
    SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate, // not implemented
    SystemSessionDetach, // not implemented
    SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend, // s (kernel-mode only)
    SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage, // q; s: ULONG
    SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation, // q: ULONG
    SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode, // q: ULONG // 70
    SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
    SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemWow64SharedInformationObsolete, // not implemented
    SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
    SystemVerifierTriageInformation, // not implemented
    SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
    SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx, // not implemented
    SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation, // s (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
    SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
    SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
    SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
    SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation,
    SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation, // q; s: SYSTEM_CONSOLE_INFORMATION
    SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION
    SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
    SystemCriticalProcessErrorLogInformation,
    SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation,
    SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation, // 150
    SystemSoftRebootInformation, // q: ULONG
    SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation,
    SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
    SystemInterruptSteeringInformation, // SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT // 180
    SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
    SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition,
    SystemKernelDebuggingAllowed, // s: ULONG
    SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation,
    SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation,
    SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
    SystemSecureDumpEncryptionInformation,
    SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation,
    SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation,
    SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
    SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
    SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation,
    SystemFeatureConfigurationInformation, // SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation, // SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
    SystemFeatureUsageSubscriptionInformation, // SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
    SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation, // since 20H2
    SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation,
    SystemDifSetRuleClassInformation,
    SystemDifClearRuleClassInformation,
    SystemDifApplyPluginVerificationOnDriver,
    SystemDifRemovePluginVerificationOnDriver, // 220
    SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation, // SYSTEM_BUILD_VERSION_INFORMATION
    SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION
    SystemCodeIntegrityAddDynamicStore,
    SystemCodeIntegrityClearDynamicStores,
    SystemDifPoolTrackingInformation,
    SystemPoolZeroingInformation, // SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation,
    SystemDpcWatchdogInformation2,
    SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx  // 230
    SystemSingleProcessorRelationshipInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
    SystemXfgCheckFailureInformation,
    SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation,
    SystemOriginalImageFeatureInformation,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation, // 2
    FileBothDirectoryInformation, // 3
    FileBasicInformation, // 4
    FileStandardInformation, // 5
    FileInternalInformation, // 6
    FileEaInformation, // 7
    FileAccessInformation, // 8
    FileNameInformation, // 9
    FileRenameInformation, // 10
    FileLinkInformation, // 11
    FileNamesInformation, // 12
    FileDispositionInformation, // 13
    FilePositionInformation, // 14
    FileFullEaInformation, // 15
    FileModeInformation, // 16
    FileAlignmentInformation, // 17
    FileAllInformation, // 18
    FileAllocationInformation, // 19
    FileEndOfFileInformation, // 20
    FileAlternateNameInformation, // 21
    FileStreamInformation, // 22
    FilePipeInformation, // 23
    FilePipeLocalInformation, // 24
    FilePipeRemoteInformation, // 25
    FileMailslotQueryInformation, // 26
    FileMailslotSetInformation, // 27
    FileCompressionInformation, // 28
    FileObjectIdInformation, // 29
    FileCompletionInformation, // 30
    FileMoveClusterInformation, // 31
    FileQuotaInformation, // 32
    FileReparsePointInformation, // 33
    FileNetworkOpenInformation, // 34
    FileAttributeTagInformation, // 35
    FileTrackingInformation, // 36
    FileIdBothDirectoryInformation, // 37
    FileIdFullDirectoryInformation, // 38
    FileValidDataLengthInformation, // 39
    FileShortNameInformation, // 40
    FileIoCompletionNotificationInformation, // 41
    FileIoStatusBlockRangeInformation, // 42
    FileIoPriorityHintInformation, // 43
    FileSfioReserveInformation, // 44
    FileSfioVolumeInformation, // 45
    FileHardLinkInformation, // 46
    FileProcessIdsUsingFileInformation, // 47
    FileNormalizedNameInformation, // 48
    FileNetworkPhysicalNameInformation, // 49
    FileIdGlobalTxDirectoryInformation, // 50
    FileIsRemoteDeviceInformation, // 51
    FileUnusedInformation, // 52
    FileNumaNodeInformation, // 53
    FileStandardLinkInformation, // 54
    FileRemoteProtocolInformation, // 55

    //
    //  These are special versions of these operations (defined earlier)
    //  which can be used by kernel mode drivers only to bypass security
    //  access checks for Rename and HardLink operations.  These operations
    //  are only recognized by the IOManager, a file system should never
    //  receive these.
    //

    FileRenameInformationBypassAccessCheck, // 56
    FileLinkInformationBypassAccessCheck, // 57

    //
    // End of special information classes reserved for IOManager.
    //

    FileVolumeNameInformation, // 58
    FileIdInformation, // 59
    FileIdExtdDirectoryInformation, // 60
    FileReplaceCompletionInformation, // 61
    FileHardLinkFullIdInformation, // 62
    FileIdExtdBothDirectoryInformation, // 63
    FileDispositionInformationEx, // 64
    FileRenameInformationEx, // 65
    FileRenameInformationExBypassAccessCheck, // 66
    FileDesiredStorageClassInformation, // 67
    FileStatInformation, // 68
    FileMemoryPartitionInformation, // 69
    FileStatLxInformation, // 70
    FileCaseSensitiveInformation, // 71
    FileLinkInformationEx, // 72
    FileLinkInformationExBypassAccessCheck, // 73
    FileStorageReserveIdInformation, // 74
    FileCaseSensitiveInformationForceAccessCheck, // 75
    FileKnownFolderInformation, // 76

    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

#define InitializeListHead(ListHead) ((ListHead)->Flink = (ListHead)->Blink = (ListHead)) //TY ReactOS

enum _EVENT_TYPE {
    NotificationEvent = 0,
    SynchronizationEvent = 1
};

typedef struct _TIME_FIELDS {
    SHORT Year;
    SHORT Month;
    SHORT Day;
    SHORT Hour;
    SHORT Minute;
    SHORT Second;
    SHORT Milliseconds;
    SHORT Weekday;
} TIME_FIELDS, *PTIME_FIELDS;

struct _KPCR {
    union {
        struct _NT_TIB NtTib; //0x0
        struct {
            union _KGDTENTRY64* GdtBase; //0x0
            struct _KTSS64* TssBase; //0x8
            ULONGLONG UserRsp; //0x10
            struct _KPCR* Self; //0x18
            struct _KPRCB* CurrentPrcb; //0x20
            struct _KSPIN_LOCK_QUEUE* LockArray; //0x28
            VOID* Used_Self; //0x30
        };
    };
    union _KIDTENTRY64* IdtBase; //0x38
    ULONGLONG Unused[2]; //0x40
    UCHAR Irql; //0x50
    UCHAR SecondLevelCacheAssociativity; //0x51
    UCHAR ObsoleteNumber; //0x52
    UCHAR Fill0; //0x53
    ULONG Unused0[3]; //0x54
    USHORT MajorVersion; //0x60
    USHORT MinorVersion; //0x62
    ULONG StallScaleFactor; //0x64
    VOID* Unused1[3]; //0x68
    ULONG KernelReserved[15]; //0x80
    ULONG SecondLevelCacheSize; //0xbc
    ULONG HalReserved[16]; //0xc0
    ULONG Unused2; //0x100
    VOID* KdVersionBlock; //0x108
    VOID* Unused3; //0x110
    ULONG PcrAlign1[24]; //0x118
};

struct _KDESCRIPTOR {
    USHORT Pad[3]; //0x0
    USHORT Limit; //0x6
    VOID* Base; //0x8
};

struct _KSPECIAL_REGISTERS {
    ULONGLONG Cr0; //0x0
    ULONGLONG Cr2; //0x8
    ULONGLONG Cr3; //0x10
    ULONGLONG Cr4; //0x18
    ULONGLONG KernelDr0; //0x20
    ULONGLONG KernelDr1; //0x28
    ULONGLONG KernelDr2; //0x30
    ULONGLONG KernelDr3; //0x38
    ULONGLONG KernelDr6; //0x40
    ULONGLONG KernelDr7; //0x48
    struct _KDESCRIPTOR Gdtr; //0x50
    struct _KDESCRIPTOR Idtr; //0x60
    USHORT Tr; //0x70
    USHORT Ldtr; //0x72
    ULONG MxCsr; //0x74
    ULONGLONG DebugControl; //0x78
    ULONGLONG LastBranchToRip; //0x80
    ULONGLONG LastBranchFromRip; //0x88
    ULONGLONG LastExceptionToRip; //0x90
    ULONGLONG LastExceptionFromRip; //0x98
    ULONGLONG Cr8; //0xa0
    ULONGLONG MsrGsBase; //0xa8
    ULONGLONG MsrGsSwap; //0xb0
    ULONGLONG MsrStar; //0xb8
    ULONGLONG MsrLStar; //0xc0
    ULONGLONG MsrCStar; //0xc8
    ULONGLONG MsrSyscallMask; //0xd0
    ULONGLONG Xcr0; //0xd8
    ULONGLONG MsrFsBase; //0xe0
    ULONGLONG SpecialPadding0; //0xe8
};

struct _KPROCESSOR_STATE {
    struct _KSPECIAL_REGISTERS SpecialRegisters; //0x0
    struct _CONTEXT ContextFrame; //0xf0
};

struct _KPRCB {
    ULONG MxCsr; //0x0
    UCHAR LegacyNumber; //0x4
    UCHAR ReservedMustBeZero; //0x5
    UCHAR InterruptRequest; //0x6
    UCHAR IdleHalt; //0x7
    struct _KTHREAD* CurrentThread; //0x8
    struct _KTHREAD* NextThread; //0x10
    struct _KTHREAD* IdleThread; //0x18
    UCHAR NestingLevel; //0x20
    UCHAR ClockOwner; //0x21
    union {
        UCHAR PendingTickFlags; //0x22
        struct {
            UCHAR PendingTick : 1; //0x22
            UCHAR PendingBackupTick : 1; //0x22
        };
    };
    UCHAR IdleState; //0x23
    ULONG Number; //0x24
    ULONGLONG RspBase; //0x28
    ULONGLONG PrcbLock; //0x30
    CHAR* PriorityState; //0x38
    CHAR CpuType; //0x40
    CHAR CpuID; //0x41
    union {
        USHORT CpuStep; //0x42
        struct {
            UCHAR CpuStepping; //0x42
            UCHAR CpuModel; //0x43
        };
    };
    ULONG MHz; //0x44
    ULONGLONG HalReserved[8]; //0x48
    USHORT MinorVersion; //0x88
    USHORT MajorVersion; //0x8a
    UCHAR BuildType; //0x8c
    UCHAR CpuVendor; //0x8d
    UCHAR CoresPerPhysicalProcessor; //0x8e
    UCHAR LogicalProcessorsPerCore; //0x8f
    ULONGLONG TscFrequency; //0x90
    ULONGLONG PrcbPad04[5]; //0x98
    struct _KNODE* ParentNode; //0xc0
    ULONGLONG GroupSetMember; //0xc8
    UCHAR Group; //0xd0
    UCHAR GroupIndex; //0xd1
    UCHAR PrcbPad05[2]; //0xd2
    ULONG InitialApicId; //0xd4
    ULONG ScbOffset; //0xd8
    ULONG ApicMask; //0xdc
    VOID* AcpiReserved; //0xe0
    ULONG CFlushSize; //0xe8
    ULONGLONG PrcbPad11[2]; //0xf0
    struct _KPROCESSOR_STATE ProcessorState; //0x100
    struct _XSAVE_AREA_HEADER* ExtendedSupervisorState; //0x6c0
    ULONG ProcessorSignature; //0x6c8
    ULONG ProcessorFlags; //0x6cc
    ULONGLONG PrcbPad12a; //0x6d0
    ULONGLONG PrcbPad12[3]; //0x6d8
};

struct _OWNER_ENTRY {
    ULONGLONG OwnerThread; //0x0
    union {
        struct {
            ULONG IoPriorityBoosted : 1; //0x8
            ULONG OwnerReferenced : 1; //0x8
            ULONG IoQoSPriorityBoosted : 1; //0x8
            ULONG OwnerCount : 29; //0x8
        };
        ULONG TableSize; //0x8
    };
};

struct _ERESOURCE {
    struct _LIST_ENTRY SystemResourcesList; //0x0
    struct _OWNER_ENTRY* OwnerTable; //0x10
    SHORT ActiveCount; //0x18
    union {
        USHORT Flag; //0x1a
        struct {
            UCHAR ReservedLowFlags; //0x1a
            UCHAR WaiterPriority; //0x1b
        };
    };
    VOID* SharedWaiters; //0x20
    VOID* ExclusiveWaiters; //0x28
    struct _OWNER_ENTRY OwnerEntry; //0x30
    ULONG ActiveEntries; //0x40
    ULONG ContentionCount; //0x44
    ULONG NumberOfSharedWaiters; //0x48
    ULONG NumberOfExclusiveWaiters; //0x4c
    VOID* Reserved2; //0x50
    union {
        VOID* Address; //0x58
        ULONGLONG CreatorBackTraceIndex; //0x58
    };
    ULONGLONG SpinLock; //0x60
};

#define ushort unsigned short
#define ulong unsigned long
#define ulonglong uint64_t

struct _SYSTEM_MODULE_EX {
    ushort Size; //at 0x0
    ushort Pad0; //at 0x2
    ulong Pad1; //at 0x4
    ulonglong Pad2; //at 0x8
    ulonglong AlwaysZero; //at 0x10
    void* ImageBase; //at 0x18
    ulong SizeOfImage; //at 0x20
    ulong Flags; //at 0x24
    ushort Index; //at 0x28
    ushort bUserMode; //at 0x2A,0 kernelmodule,sameas Index user
    ushort LoadCount; //at 0x2C
    ushort BaseNameOffset; //at 0x2E
    unsigned char FullDllName[0x100]; //at 0x30
    ulong CheckSum; //at 0x130
    ulong PadZero0; //at 0x134
    ulonglong PadZero1; //at 0x138
};

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        ULONG SectionPointer;
    };
    ULONG CheckSum;
    union {
        ULONG TimeDateStamp;
        ULONG LoadedImports;
    };
    ULONG EntryPointActivationContext;
    ULONG PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

struct _KLDR_DATA_TABLE_ENTRY {
    struct _LIST_ENTRY InLoadOrderLinks; //0x0
    VOID* ExceptionTable; //0x8
    ULONG ExceptionTableSize; //0xc
    VOID* GpValue; //0x10
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo; //0x14
    VOID* DllBase; //0x18
    VOID* EntryPoint; //0x1c
    ULONG SizeOfImage; //0x20
    struct _UNICODE_STRING FullDllName; //0x24
    struct _UNICODE_STRING BaseDllName; //0x2c
    ULONG Flags; //0x34
    USHORT LoadCount; //0x38
    union {
        USHORT SignatureLevel : 4; //0x3a
        USHORT SignatureType : 3; //0x3a
        USHORT Unused : 9; //0x3a
        USHORT EntireField; //0x3a
    } u1; //0x3a
    VOID* SectionPointer; //0x3c
    ULONG CheckSum; //0x40
    ULONG CoverageSectionSize; //0x44
    VOID* CoverageSection; //0x48
    VOID* LoadedImports; //0x4c
    VOID* Spare; //0x50
    ULONG SizeOfImageNotRounded; //0x54
    ULONG TimeDateStamp; //0x58
};

typedef struct _MDL {
    struct _MDL* Next;
    USHORT Size;
    USHORT MdlFlags;
    struct _EPROCESS* Process;
    PVOID MappedSystemVa;
    PVOID StartVa;
    ULONG ByteCount;
    ULONG ByteOffset;
} MDL, *PMDL;

struct _IO_STATUS_BLOCK {
    union {
        LONG Status; //0x0
        VOID* Pointer; //0x0
    };
    ULONGLONG Information; //0x8
};

struct _IRP {
    SHORT Type; //0x0
    USHORT Size; //0x2
    USHORT AllocationProcessorNumber; //0x4
    USHORT Reserved; //0x6
    struct _MDL* MdlAddress; //0x8
    ULONG Flags; //0x10
    union {
        struct _IRP* MasterIrp; //0x18
        LONG IrpCount; //0x18
        VOID* SystemBuffer; //0x18
    } AssociatedIrp; //0x18
    struct _LIST_ENTRY ThreadListEntry; //0x20
    struct _IO_STATUS_BLOCK IoStatus; //0x30
    CHAR RequestorMode; //0x40
    UCHAR PendingReturned; //0x41
    CHAR StackCount; //0x42
    CHAR CurrentLocation; //0x43
    UCHAR Cancel; //0x44
    UCHAR CancelIrql; //0x45
    CHAR ApcEnvironment; //0x46
    UCHAR AllocationFlags; //0x47
    union {
        struct _IO_STATUS_BLOCK* UserIosb; //0x48
        VOID* IoRingContext; //0x48
    };
    struct _KEVENT* UserEvent; //0x50
    union {
        struct {
            union {
                VOID (*UserApcRoutine)(VOID* arg1, struct _IO_STATUS_BLOCK* arg2, ULONG arg3); //0x58
                VOID* IssuingProcess; //0x58
            };
            union {
                VOID* UserApcContext; //0x60
                struct _IORING_OBJECT* IoRing; //0x60
            };
        } AsynchronousParameters; //0x58
        union _LARGE_INTEGER AllocationSize; //0x58
    } Overlay; //0x58
    VOID (*CancelRoutine)(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2); //0x68
    VOID* UserBuffer; //0x70
    union {
        struct {
            union {
                struct _KDEVICE_QUEUE_ENTRY DeviceQueueEntry; //0x78
                VOID* DriverContext[4]; //0x78
            };
            struct _ETHREAD* Thread; //0x98
            CHAR* AuxiliaryBuffer; //0xa0
            struct _LIST_ENTRY ListEntry; //0xa8
            union {
                struct _IO_STACK_LOCATION* CurrentStackLocation; //0xb8
                ULONG PacketType; //0xb8
            };
            struct _FILE_OBJECT* OriginalFileObject; //0xc0
            VOID* IrpExtension; //0xc8
        } Overlay; //0x78
        struct _KAPC Apc; //0x78
        VOID* CompletionKey; //0x78
    } Tail; //0x78
};

struct _KGATE {
    struct _DISPATCHER_HEADER Header; //0x0
};

struct _KGUARDED_MUTEX {
    volatile LONG Count; //0x0
    struct _KTHREAD* Owner; //0x8
    ULONG Contention; //0x10
    struct _KGATE Gate; //0x18
    union {
        struct {
            SHORT KernelApcDisable; //0x30
            SHORT SpecialApcDisable; //0x32
        };
        ULONG CombinedApcDisable; //0x30
    };
};
enum _KWAIT_REASON {
    Executive = 0,
    FreePage = 1,
    PageIn = 2,
    PoolAllocation = 3,
    DelayExecution = 4,
    Suspended = 5,
    UserRequest = 6,
    WrExecutive = 7,
    WrFreePage = 8,
    WrPageIn = 9,
    WrPoolAllocation = 10,
    WrDelayExecution = 11,
    WrSuspended = 12,
    WrUserRequest = 13,
    WrSpare0 = 14,
    WrQueue = 15,
    WrLpcReceive = 16,
    WrLpcReply = 17,
    WrVirtualMemory = 18,
    WrPageOut = 19,
    WrRendezvous = 20,
    WrKeyedEvent = 21,
    WrTerminated = 22,
    WrProcessInSwap = 23,
    WrCpuRateControl = 24,
    WrCalloutStack = 25,
    WrKernel = 26,
    WrResource = 27,
    WrPushLock = 28,
    WrMutex = 29,
    WrQuantumEnd = 30,
    WrDispatchInt = 31,
    WrPreempted = 32,
    WrYieldExecution = 33,
    WrFastMutex = 34,
    WrGuardedMutex = 35,
    WrRundown = 36,
    WrAlertByThreadId = 37,
    WrDeferredPreempt = 38,
    WrPhysicalFault = 39,
    MaximumWaitReason = 40
};

struct _OBJECT_TYPE_INITIALIZER {
    USHORT Length; //0x0
    union {
        USHORT ObjectTypeFlags; //0x2
        struct {
            UCHAR CaseInsensitive : 1; //0x2
            UCHAR UnnamedObjectsOnly : 1; //0x2
            UCHAR UseDefaultObject : 1; //0x2
            UCHAR SecurityRequired : 1; //0x2
            UCHAR MaintainHandleCount : 1; //0x2
            UCHAR MaintainTypeList : 1; //0x2
            UCHAR SupportsObjectCallbacks : 1; //0x2
            UCHAR CacheAligned : 1; //0x2
            UCHAR UseExtendedParameters : 1; //0x3
            UCHAR Reserved : 7; //0x3
        };
    };
    ULONG ObjectTypeCode; //0x4
    ULONG InvalidAttributes; //0x8
    struct _GENERIC_MAPPING GenericMapping; //0xc
    ULONG ValidAccessMask; //0x1c
    ULONG RetainAccess; //0x20
    enum _POOL_TYPE PoolType; //0x24
    ULONG DefaultPagedPoolCharge; //0x28
    ULONG DefaultNonPagedPoolCharge; //0x2c
    VOID (*DumpProcedure)(VOID* arg1, struct _OBJECT_DUMP_CONTROL* arg2); //0x30
    LONG (*OpenProcedure)(enum _OB_OPEN_REASON arg1, CHAR arg2, struct _EPROCESS* arg3, VOID* arg4, ULONG* arg5, ULONG arg6); //0x38
    VOID (*CloseProcedure)(struct _EPROCESS* arg1, VOID* arg2, ULONGLONG arg3, ULONGLONG arg4); //0x40
    VOID (*DeleteProcedure)(VOID* arg1); //0x48
    union {
        LONG (*ParseProcedure)
        (VOID* arg1, VOID* arg2, struct _ACCESS_STATE* arg3, CHAR arg4, ULONG arg5, struct _UNICODE_STRING* arg6, struct _UNICODE_STRING* arg7, VOID* arg8,
            struct _SECURITY_QUALITY_OF_SERVICE* arg9, VOID** arg10); //0x50
        LONG (*ParseProcedureEx)
        (VOID* arg1, VOID* arg2, struct _ACCESS_STATE* arg3, CHAR arg4, ULONG arg5, struct _UNICODE_STRING* arg6, struct _UNICODE_STRING* arg7, VOID* arg8,
            struct _SECURITY_QUALITY_OF_SERVICE* arg9, struct _OB_EXTENDED_PARSE_PARAMETERS* arg10, VOID** arg11); //0x50
    };
    LONG (*SecurityProcedure)
    (VOID* arg1, enum _SECURITY_OPERATION_CODE arg2, ULONG* arg3, VOID* arg4, ULONG* arg5, VOID** arg6, enum _POOL_TYPE arg7,
        struct _GENERIC_MAPPING* arg8, CHAR arg9); //0x58
    LONG (*QueryNameProcedure)(VOID* arg1, UCHAR arg2, struct _OBJECT_NAME_INFORMATION* arg3, ULONG arg4, ULONG* arg5, CHAR arg6); //0x60
    UCHAR (*OkayToCloseProcedure)(struct _EPROCESS* arg1, VOID* arg2, VOID* arg3, CHAR arg4); //0x68
    ULONG WaitObjectFlagMask; //0x70
    USHORT WaitObjectFlagOffset; //0x74
    USHORT WaitObjectPointerOffset; //0x76
};

struct _OBJECT_TYPE {
    struct _LIST_ENTRY TypeList; //0x0
    struct _UNICODE_STRING Name; //0x10
    VOID* DefaultObject; //0x20
    UCHAR Index; //0x28
    ULONG TotalNumberOfObjects; //0x2c
    ULONG TotalNumberOfHandles; //0x30
    ULONG HighWaterNumberOfObjects; //0x34
    ULONG HighWaterNumberOfHandles; //0x38
    struct _OBJECT_TYPE_INITIALIZER TypeInfo; //0x40
    struct _EX_PUSH_LOCK TypeLock; //0xb8
    ULONG Key; //0xc0
    struct _LIST_ENTRY CallbackList; //0xc8
};