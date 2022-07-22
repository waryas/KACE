#include "emulation.h"
#include <Zydis/Zydis.h>
#include "libs/Logger/Logger.h"
#include <assert.h>

namespace VCPU {

	static ZydisDecoder decoder;
	static ZydisDecodedInstruction instr;

	uint64_t VCPU::CR0 = 0x80050033;
	uint64_t VCPU::CR3 = 0x1ad002;
	uint64_t VCPU::CR4 = 0x370678;
	uint64_t VCPU::CR8 = 0;


	void Initialize() {
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
		MemoryTranslation::AddMapping(KUSD_MIN, 0x1000, KUSD_USERMODE);
	}

	bool Decode(PCONTEXT context) {
		ZyanU64 runtime_address = context->Rip;
		auto status = ZydisDecoderDecodeBuffer(&decoder, (PVOID)context->Rip, ZYDIS_MAX_INSTRUCTION_LENGTH, &instr);
		return ZYAN_SUCCESS(status);
	}

	static uint32_t GRegIndex(ZydisRegister Reg) {

		PCONTEXT resolver = 0;

		if (Reg == ZYDIS_REGISTER_RIP)
			return (uint32_t)(&resolver->Rip) / 8;
		if (Reg == ZYDIS_REGISTER_EFLAGS)
			return (uint32_t)(&resolver->EFlags) / 8;

		auto lookup = (uint32_t)&resolver->Rax;
		auto zydis_rax = ZYDIS_REGISTER_RAX;
		auto zydis_gr64_lookup = ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, ZydisRegisterGetId(Reg));
		auto index = zydis_gr64_lookup - zydis_rax;

		if (index < 0 || index > 15)
			return 0;

		lookup += index * sizeof(uint64_t);

		return lookup / 8;
	}

	static uint64_t ReadRegisterValue(PCONTEXT ctx, ZydisRegister reg) {
		uint64_t* context_lookup = (uint64_t*)ctx;
		auto reg_class = ZydisRegisterGetClass(reg);
		auto ret = context_lookup[GRegIndex(reg)];

		if (reg_class == ZYDIS_REGCLASS_GPR64) { //Read the whole64bit register
			return ret;
		}
		else if (reg_class == ZYDIS_REGCLASS_GPR32) { //32 lower bytes
			return ret & 0xFFFFFFFF;
		}
		else if (reg_class == ZYDIS_REGCLASS_GPR16) { //16 llower bytes
			return ret & 0xFFFF;
		}
		else if (reg_class == ZYDIS_REGCLASS_GPR8) {
			if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) { //8 upper byte
				return (ret & 0xFF00) >> 8;
			}
			else { //8 lower bytes
				return ret & 0xFF;
			}
		}
		else {
			DebugBreak();
		}

		return 0;
	}

	static bool SkipToNext(PCONTEXT ctx) {
		ctx->Rip += instr.length;
		return true;
	}


	namespace PrivilegedInstruction {

		bool Parse(PCONTEXT context) {
			if (!Decode(context))
				return false;

			if (instr.mnemonic == ZYDIS_MNEMONIC_CLI) {
				Logger::Log("Clearing Interrupts\n");
				return SkipToNext(context);
			} 
			else if (instr.mnemonic == ZYDIS_MNEMONIC_STI) {
				Logger::Log("Restoring Interrupts\n");
				return SkipToNext(context);
			}
			else if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
				EmulatePrivilegedMOV(context);
				return SkipToNext(context);
			} else if (instr.mnemonic == ZYDIS_MNEMONIC_WRMSR) {
				WriteMSR(context);
				return SkipToNext(context);
			} else if (instr.mnemonic == ZYDIS_MNEMONIC_RDMSR) {
				ReadMSR(context);
				return SkipToNext(context);
			}
			else {
				DebugBreak();
			}

		}


		bool EmulatePrivilegedMOV(PCONTEXT context) {
			uint64_t* context_lookup = (uint64_t*)context;
			

			auto reg_to_write = GRegIndex(instr.operands[0].reg.value);
			auto reg_to_read = GRegIndex(instr.operands[1].reg.value);

			if (instr.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || instr.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
				DebugBreak();
			}

			if (!reg_to_read && !reg_to_write) {
				DebugBreak();
			}

			if (instr.operands[0].reg.value == ZYDIS_REGISTER_CR0) { //Write CR0
				VCPU::CR0 = context_lookup[reg_to_read];
			} 
			else if (instr.operands[1].reg.value == ZYDIS_REGISTER_CR0) { //Read CR0
				context_lookup[reg_to_write] = VCPU::CR0;
			} 
			else if (instr.operands[0].reg.value == ZYDIS_REGISTER_CR3) { //Write CR3
				VCPU::CR3 = context_lookup[reg_to_read];
			}
			else if (instr.operands[1].reg.value == ZYDIS_REGISTER_CR3) { //Read CR3
				context_lookup[reg_to_write] = VCPU::CR3;
			}
			else if (instr.operands[0].reg.value == ZYDIS_REGISTER_CR4) { //Read CR4
				VCPU::CR4 = context_lookup[reg_to_read];
			}
			else if (instr.operands[1].reg.value == ZYDIS_REGISTER_CR4) { //Read CR4
				context_lookup[reg_to_write] = VCPU::CR4;
			}
			else if (instr.operands[0].reg.value == ZYDIS_REGISTER_CR8) { //Write CR8
				VCPU::CR8 = context_lookup[reg_to_read];
			}
			else if (instr.operands[1].reg.value == ZYDIS_REGISTER_CR8) { //Read CR8
				context_lookup[reg_to_write] = VCPU::CR8;
			}
			else if (instr.operands[0].reg.value == ZYDIS_REGISTER_DR7) { //Read CR8
				context->Dr7 = context_lookup[reg_to_read];
			}
			else {
				DebugBreak();
			}
			
			return true;
		}

		bool ReadMSR(PCONTEXT context) {
			return true;
		}

		bool WriteMSR(PCONTEXT context) {
			return true;
		}
	}


	namespace MemoryRead {

		bool Parse(uintptr_t addr, PCONTEXT context) {
			if (!Decode(context))
				return false;

			if (auto HVA = MemoryTranslation::GetHVA(addr)) {
				return EmulateRead(HVA, context);
			}
			else {
				if (addr == 0xffffffffffffffff)
					return false;
				Logger::Log("Logging from a memory that has no usermode mapping : %llx\n", addr);
				fflush(stdout);
				fflush(stdout);
				MessageBoxA(NULL, "FLUSHED", "FLUSHED", MB_OK);
				DebugBreak();
				return false;
			}
		}

		bool EmulateRead(uintptr_t addr, PCONTEXT context) { //We return true if we emulated it

			if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
					InstrEmu::ReadPtr::EmulateMOV(context, instr.operands[0].reg.value, addr);
					return SkipToNext(context);
				}
				else {
					Logger::Log("This should never happen, please investigate\n");
					DebugBreak();
				}
			}
			else if (instr.mnemonic == ZYDIS_MNEMONIC_OR) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
					InstrEmu::ReadPtr::EmulateOR(context, instr.operands[0].reg.value, addr);
					return SkipToNext(context);
				}
				else {

					DebugBreak();
				}
			}
			else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
					InstrEmu::ReadPtr::EmulateXOR(context, instr.operands[0].reg.value, addr);
					return SkipToNext(context);
				}
				else {

					DebugBreak();
				}
			}
			else if (instr.mnemonic == ZYDIS_MNEMONIC_AND) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {

					InstrEmu::ReadPtr::EmulateAND(context, instr.operands[0].reg.value, addr);
					return SkipToNext(context);
				}
				else {

					DebugBreak();
				}
			}
			else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {

					InstrEmu::ReadPtr::EmulateSUB(context, instr.operands[0].reg.value, addr);
					return SkipToNext(context);
				}
				else {

					DebugBreak();
				}
			}
			else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {

					InstrEmu::ReadPtr::EmulateADD(context, instr.operands[0].reg.value, addr);
					return SkipToNext(context);
				}
				else {

					DebugBreak();
				}
			}
			else if (instr.mnemonic == ZYDIS_MNEMONIC_CMP) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) { //cmp [memory], reg
					InstrEmu::EmulateCMP(context, instr.operands[1].reg.value, addr);
					return SkipToNext(context);
				}
				else if (instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) { //cmp reg, [memory]
					InstrEmu::EmulateCMP(context, instr.operands[0].reg.value, addr);
					return SkipToNext(context);
				}
				else {
					DebugBreak();
				}
			}
			else if (instr.mnemonic == ZYDIS_MNEMONIC_MOVZX) {
				if (instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) { //cmp reg, [memory]
					InstrEmu::ReadPtr::EmulateMOVZX(context, instr.operands[0].reg.value, addr, instr.operands[1].size);
					return SkipToNext(context);
				}
				else {
					DebugBreak();
				}
			}

			else {
				Logger::Log("Unhandled Mnemonic for KUSER_SHARED_DATA manipulation.\n");
				DebugBreak();
				return false;
			}
			return false;
		}


	}


	namespace InstrEmu {
		bool EmulateCMP(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr) { //Emulates cmp [ptr], reg // cmp reg, [ptr]

			uint64_t* context_lookup = (uint64_t*)ctx;
			auto reg_class = ZydisRegisterGetClass(reg);
			auto reg_value = ReadRegisterValue(ctx, reg);

			if (reg_class == ZYDIS_REGCLASS_GPR64) {
				ctx->EFlags = u_cmp_64(ctx->EFlags, ptr, reg) | 0x10000;
			}
			else if (reg_class == ZYDIS_REGCLASS_GPR32) {
				ctx->EFlags = u_cmp_32(ctx->EFlags, ptr, reg) | 0x10000;
			}
			else if (reg_class == ZYDIS_REGCLASS_GPR16) {
				ctx->EFlags = u_cmp_16(ctx->EFlags, ptr, reg) | 0x10000;

			}
			else if (reg_class == ZYDIS_REGCLASS_GPR8) {
				ctx->EFlags = u_cmp_8(ctx->EFlags, ptr, reg) | 0x10000;
			}
			else {
				DebugBreak();
			}
			return true;
		}

		namespace ReadPtr {
			bool EmulateMOV(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr) { //X86-compliant MOV R64, [...] emulation

				uint64_t* context_lookup = (uint64_t*)ctx;
				auto reg_class = ZydisRegisterGetClass(reg);
				auto orig_value = context_lookup[GRegIndex(reg)];


				if (reg_class == ZYDIS_REGCLASS_GPR64) { //We replace the whole register
					context_lookup[GRegIndex(reg)] = *(uint64_t*)ptr;

				}
				else if (reg_class == ZYDIS_REGCLASS_GPR32) { //We replace the whole register
					context_lookup[GRegIndex(reg)] = *(uint32_t*)ptr;
				}
				else if (reg_class == ZYDIS_REGCLASS_GPR16) { // 16/8bits operation do not overwrite the rest of the register
					context_lookup[GRegIndex(reg)] = (orig_value & 0xFFFFFFFFFFFF0000) | (*(uint16_t*)ptr);

				}
				else if (reg_class == ZYDIS_REGCLASS_GPR8) {  // 16/8bits operation do not overwrite the rest of the register
					if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
						context_lookup[GRegIndex(reg)] = (orig_value & 0xFFFFFFFFFFFF00FF) | (*(uint8_t*)ptr) << 8;
					}
					else {  // 16/8bits operation do not overwrite the rest of the register
						context_lookup[GRegIndex(reg)] = (orig_value & 0xFFFFFFFFFFFFFF00) | (*(uint8_t*)ptr);
					}
				}
				else {
					DebugBreak();
				}
				return true;
			}


			bool EmulateSUB(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr) { //X86-compliant MOV R64, [...] emulation
				uint64_t* context_lookup = (uint64_t*)ctx;
				auto reg_class = ZydisRegisterGetClass(reg);


				if (reg_class == ZYDIS_REGCLASS_GPR64) {
					context_lookup[GRegIndex(reg)] -= *(uint64_t*)ptr;

				}
				else if (reg_class == ZYDIS_REGCLASS_GPR32) { //r32/m32 removes upper byte
					context_lookup[GRegIndex(reg)] = (context_lookup[GRegIndex(reg)] & 0xFFFFFFFF) - *(uint32_t*)ptr;
				}
				else if (reg_class == ZYDIS_REGCLASS_GPR16) {
					context_lookup[GRegIndex(reg)] -= (*(uint16_t*)ptr);

				}
				else if (reg_class == ZYDIS_REGCLASS_GPR8) {
					if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
						context_lookup[GRegIndex(reg)] -= (*(uint8_t*)ptr) << 8;
					}
					else {
						context_lookup[GRegIndex(reg)] -= (*(uint8_t*)ptr);
					}
				}
				else {
					DebugBreak();
				}
				return true;
			}

			bool EmulateADD(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr) { //X86-compliant MOV R64, [...] emulation
				uint64_t* context_lookup = (uint64_t*)ctx;
				auto reg_class = ZydisRegisterGetClass(reg);


				if (reg_class == ZYDIS_REGCLASS_GPR64) {
					context_lookup[GRegIndex(reg)] += *(uint64_t*)ptr;

				}
				else if (reg_class == ZYDIS_REGCLASS_GPR32) { //r32/m32 removes upper byte
					context_lookup[GRegIndex(reg)] = (context_lookup[GRegIndex(reg)] & 0xFFFFFFFF) + *(uint32_t*)ptr;
				}
				else if (reg_class == ZYDIS_REGCLASS_GPR16) {
					context_lookup[GRegIndex(reg)] += (*(uint16_t*)ptr);

				}
				else if (reg_class == ZYDIS_REGCLASS_GPR8) {
					if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
						context_lookup[GRegIndex(reg)] += (*(uint8_t*)ptr) << 8;
					}
					else {
						context_lookup[GRegIndex(reg)] += (*(uint8_t*)ptr);
					}
				}
				else {
					DebugBreak();
				}
				return true;
			}

			bool EmulateOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr) { //X86-compliant MOV R64, [...] emulation
				uint64_t* context_lookup = (uint64_t*)ctx;
				auto reg_class = ZydisRegisterGetClass(reg);


				if (reg_class == ZYDIS_REGCLASS_GPR64) {
					context_lookup[GRegIndex(reg)] |= *(uint64_t*)ptr;

				}
				else if (reg_class == ZYDIS_REGCLASS_GPR32) { //r32/m32 removes upper byte
					context_lookup[GRegIndex(reg)] = (context_lookup[GRegIndex(reg)] & 0xFFFFFFFF) | *(uint32_t*)ptr;
				}
				else if (reg_class == ZYDIS_REGCLASS_GPR16) {
					context_lookup[GRegIndex(reg)] |= (*(uint16_t*)ptr);

				}
				else if (reg_class == ZYDIS_REGCLASS_GPR8) {
					if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
						context_lookup[GRegIndex(reg)] |= (*(uint8_t*)ptr) << 8;
					}
					else {
						context_lookup[GRegIndex(reg)] |= (*(uint8_t*)ptr);
					}
				}
				else {
					DebugBreak();
				}
				return true;
			}

			bool EmulateXOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr) { //X86-compliant MOV R64, [...] emulation
				uint64_t* context_lookup = (uint64_t*)ctx;
				auto reg_class = ZydisRegisterGetClass(reg);


				if (reg_class == ZYDIS_REGCLASS_GPR64) {
					context_lookup[GRegIndex(reg)] ^= *(uint64_t*)ptr;

				}
				else if (reg_class == ZYDIS_REGCLASS_GPR32) { //r32/m32 removes upper byte
					context_lookup[GRegIndex(reg)] = (context_lookup[GRegIndex(reg)] & 0xFFFFFFFF) ^ *(uint32_t*)ptr;
				}
				else if (reg_class == ZYDIS_REGCLASS_GPR16) {
					context_lookup[GRegIndex(reg)] ^= (*(uint16_t*)ptr);

				}
				else if (reg_class == ZYDIS_REGCLASS_GPR8) {
					if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
						context_lookup[GRegIndex(reg)] ^= (*(uint8_t*)ptr) << 8;
					}
					else {
						context_lookup[GRegIndex(reg)] ^= (*(uint8_t*)ptr);
					}
				}
				else {
					DebugBreak();
				}
				return true;
			}

			bool EmulateAND(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr) { //X86-compliant MOV R64, [...] emulation
				uint64_t* context_lookup = (uint64_t*)ctx;
				auto reg_class = ZydisRegisterGetClass(reg);

				if (reg_class == ZYDIS_REGCLASS_GPR64) {
					context_lookup[GRegIndex(reg)] &= *(uint64_t*)ptr;
				}
				else if (reg_class == ZYDIS_REGCLASS_GPR32) { //r32/m32 removes upper byte
					context_lookup[GRegIndex(reg)] = (context_lookup[GRegIndex(reg)] & 0xFFFFFFFF) & *(uint32_t*)ptr;
				}
				else if (reg_class == ZYDIS_REGCLASS_GPR16) {
					context_lookup[GRegIndex(reg)] &= (*(uint16_t*)ptr);
				}
				else if (reg_class == ZYDIS_REGCLASS_GPR8) {
					if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
						context_lookup[GRegIndex(reg)] &= (*(uint8_t*)ptr) << 8;
					}
					else {
						context_lookup[GRegIndex(reg)] &= (*(uint8_t*)ptr);
					}
				}
				else {
					DebugBreak();
				}
				return true;
			}

			bool EmulateMOVZX(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, uint32_t size) { //X86-compliant MOVZX R32/16, 8/16[PTR] emulation

				uint64_t* context_lookup = (uint64_t*)ctx;
				auto reg_class = ZydisRegisterGetClass(reg);
				auto orig_value = context_lookup[GRegIndex(reg)];



				if (reg_class == ZYDIS_REGCLASS_GPR32) { //We replace the whole register
					if (size == 16) {
						context_lookup[GRegIndex(reg)] = *(uint16_t*)ptr;
					}
					else if (size == 8) {
						context_lookup[GRegIndex(reg)] = *(uint8_t*)ptr;
					}
					else {
						DebugBreak();
					}

				}
				else if (reg_class == ZYDIS_REGCLASS_GPR16) { // 16/8bits operation do not overwrite the rest of the register
					if (size == 8) {
						context_lookup[GRegIndex(reg)] = *(uint8_t*)ptr;
					}
					else {
						DebugBreak();
					}


				}
				else {
					DebugBreak();
				}
				return true;
			}
		}
	}
}
