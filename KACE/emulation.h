#include <windows.h>
#include <inttypes.h>
#include <intrin.h>
#include <Zydis/Register.h>
#include <unordered_map>

#define KUSD_MIN 0xFFFFF78000000000
#define KUSD_MAX 0xFFFFF78000001000
#define KUSD_USERMODE 0x7FFE0000

extern "C" uint64_t u_cmp_8_sp(uint64_t eflags, uintptr_t ptr, uint8_t value);
extern "C" uint64_t u_cmp_16_sp(uint64_t eflags, uintptr_t ptr, uint16_t value);
extern "C" uint64_t u_cmp_32_sp(uint64_t eflags, uintptr_t ptr, uint32_t value);
extern "C" uint64_t u_cmp_64_sp(uint64_t eflags, uintptr_t ptr, uint64_t value);

extern "C" uint64_t u_test_8_sp(uint64_t eflags, uintptr_t ptr, uint8_t value);
extern "C" uint64_t u_test_16_sp(uint64_t eflags, uintptr_t ptr, uint16_t value);
extern "C" uint64_t u_test_32_sp(uint64_t eflags, uintptr_t ptr, uint32_t value);
extern "C" uint64_t u_test_64_sp(uint64_t eflags, uintptr_t ptr, uint64_t value);

extern "C" uint64_t u_cmp_8_dp(uint64_t eflags, uintptr_t ptr, uint8_t value);
extern "C" uint64_t u_cmp_16_dp(uint64_t eflags, uintptr_t ptr, uint16_t value);
extern "C" uint64_t u_cmp_32_dp(uint64_t eflags, uintptr_t ptr, uint32_t value);
extern "C" uint64_t u_cmp_64_dp(uint64_t eflags, uintptr_t ptr, uint64_t value);

extern "C" uint64_t u_test_8_dp(uint64_t eflags, uintptr_t ptr, uint8_t value);
extern "C" uint64_t u_test_16_dp(uint64_t eflags, uintptr_t ptr, uint16_t value);
extern "C" uint64_t u_test_32_dp(uint64_t eflags, uintptr_t ptr, uint32_t value);
extern "C" uint64_t u_test_64_dp(uint64_t eflags, uintptr_t ptr, uint64_t value);


namespace VCPU {

	extern uint64_t CR0;
	extern uint64_t CR3;
	extern uint64_t CR4;
	extern uint64_t CR8;

	namespace MSRContext {
		
		extern std::unordered_map<uint32_t, std::pair<uint64_t, std::string>> MSRData;
		bool Initialize();
	}
	
	void Initialize();

	bool Decode(PCONTEXT context);


	namespace PrivilegedInstruction {
		bool Parse(PCONTEXT context);
		bool ReadMSR(PCONTEXT context);
		bool WriteMSR(PCONTEXT context);
		bool EmulatePrivilegedMOV(PCONTEXT context);
	}

	namespace MemoryRead {
		bool Parse(uintptr_t addr, PCONTEXT context);
		bool EmulateRead(uintptr_t addr, PCONTEXT context);
	}

	namespace MemoryWrite {
		bool Parse(uintptr_t addr, PCONTEXT context);
		bool EmulateWrite(uintptr_t addr, PCONTEXT context);
	}

	namespace InstrEmu {

		bool EmulateCMPDestPtr(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
		bool EmulateCMPSourcePtr(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
		bool EmulateCMPImm(PCONTEXT ctx, int32_t imm, uint64_t ptr, size_t size);

		bool EmulateTestSourcePtr(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
		bool EmulateTestDestPtr(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
		bool EmulateTestImm(PCONTEXT ctx, int32_t imm, uint64_t ptr, size_t size);

		namespace ReadPtr {
			bool EmulateMOV(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateXOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateAND(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateSUB(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateADD(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr);
			bool EmulateMOVZX(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, uint32_t size);
			bool EmulateMOVSX(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, uint32_t size);
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