#pragma once

#define PAGE_SHIFT              12
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE-1))
#define PAGE_ALIGN(addr)        (((addr)+PAGE_SIZE-1)&PAGE_MASK)

#define KB 1024
#define MB 1024 * KB
#define GB 1024 * MB
#define MEMORY_ALLOCATION 1 * MB


//Single Thread/Single Process environment right now, ideally we need a whole configurable fake environment




//Images have to be 4096bytes aligned, found out the hard way
//Use PTE to make those in kernel space

__declspec(align(4096)) static uint8_t Mapped_Driver[16 * MB] = { 0 };
//__declspec(align(4096)) static uint8_t AllocatedData[30 * MB] = { 0 }; 
__declspec(align(4096)) static uint8_t Kernel_Image[32 * MB] = { 0 };
__declspec(align(4096)) static uint8_t Flt_Image[4 * MB] = { 0 };
__declspec(align(4096)) static uint8_t Cng_Image[4 * MB] = { 0 };


//Lazy recast
uintptr_t db = (uintptr_t)Mapped_Driver;
uintptr_t kb = (uintptr_t)Kernel_Image;
uintptr_t fltb = (uintptr_t)Flt_Image;
uintptr_t cngb = (uintptr_t)Cng_Image;



enum TYPE_ARGUMENT {
    TINT8 = 0x0,
    TINT16 = 0x1,
    TINT32 = 0x2,
    TINT64 = 0x3,
    TBUFFER = 0x4,
    TCSTRING = 0x5,
    TWSTRING = 0x6,
    TUNICODESTRING = 0x7
};


struct ArgumentPrototype {
    const char* name;
    TYPE_ARGUMENT type; //Actually wasn't needed, will probably remove this
    uint64_t value;

};
struct FunctionPrototype {
    const char* name;
    uint8_t argumentCount; //Used for unicorn version
    void* hook;
    ArgumentPrototype args[15];
};

struct MemoryMapping { //For symbolic tracking, was used in the unicorn version, will redevelop it soon
    char* regionName;
    uintptr_t realMemory;
    uintptr_t guestBase;
    size_t allocSize;
    MemoryMapping* next;
} MemAccess = { 0 };

struct HandleManager { //For tracking of handle
    char* handleName;
    HANDLE realHandle;
    HANDLE guestHandle;
    size_t allocSize;
    HandleManager* next;
} HandleAccess = { 0 };



uint8_t* image_to_execute = nullptr;

std::unique_ptr<LIEF::PE::Binary> driver;
std::unique_ptr<LIEF::PE::Binary> ntoskrnl;
std::unique_ptr<LIEF::PE::Binary> cng_pe;
std::unique_ptr<LIEF::PE::Binary> fltmgr_pe;

LIEF::Binary::functions_t funcs;


#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

int fsize(FILE* fp) {
    int prev = ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz = ftell(fp);
    fseek(fp, prev, SEEK_SET); //go back to where we were
    return sz;
}


