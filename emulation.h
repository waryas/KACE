#include <windows.h>
#include <inttypes.h>
#include <intrin.h>
#include <Zydis/Register.h>
#include "memory_translation.h"

#define KUSD_MIN 0xFFFFF78000000000
#define KUSD_MAX 0xFFFFF78000001000
#define KUSD_USERMODE 0x7FFE0000

extern "C" uint64_t u_cmp_8(uint64_t eflags, uintptr_t ptr, uint8_t value);
extern "C" uint64_t u_cmp_16(uint64_t eflags, uintptr_t ptr, uint16_t value);
extern "C" uint64_t u_cmp_32(uint64_t eflags, uintptr_t ptr, uint32_t value);
extern "C" uint64_t u_cmp_64(uint64_t eflags, uintptr_t ptr, uint64_t value);

namespace VCPU {

	extern uint64_t CR0;
	extern uint64_t CR3;
	extern uint64_t CR4;
	extern uint64_t CR8;

	
	void Initialize();

	bool Decode(PCONTEXT context);


	namespace PrivilegedInstruction {
		bool Parse(PCONTEXT context);
	}

	namespace MemoryRead {
		bool Parse(uintptr_t addr, PCONTEXT context);
		bool EmulateRead(uintptr_t addr, PCONTEXT context);
	}

	namespace InstrEmu {

		bool EmulateCMP(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);

		namespace ReadPtr {
			bool EmulateMOV(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateXOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateAND(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateMOVZX(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, uint32_t size);
		}

		namespace WritePtr {
			bool EmulateMOV(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateXOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateAND(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateMOVZX(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, uint32_t size);
		}
	}
};