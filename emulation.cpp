#include "emulation.h"
#include <Zydis/Zydis.h>
#include "libs/Logger/Logger.h"
#include <assert.h>

namespace VCPU {

	static ZydisDecoder decoder;
	static ZydisDecodedInstruction instr;

	uint64_t CR0 = 0;
	uint64_t CR3 = 0;
	uint64_t CR4 = 0;
	uint64_t CR8 = 0;


	void Initialize() {
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
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

		}
	}


	namespace MemoryRead {

		bool Parse(uintptr_t addr, PCONTEXT context) {



			if (!Decode(context))
				return false;

			if (KUSD_MIN <= addr && addr <= KUSD_MAX) {
				return KUSDInstrEmulate(addr, context);
			}
			else {

				return false;
			}

		}

		bool KUSDInstrEmulate(uintptr_t addr, PCONTEXT context) { //We return true if we emulated it

			if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
					InstrEmu::EmulateMOV(context, instr.operands[0].reg.value, KUSD_USERMODE + (addr - KUSD_MIN));
					return SkipToNext(context);
				}
				else {
					Logger::Log("This should never happen, please investigate\n");
					DebugBreak();
				}
			}
			else if (instr.mnemonic == ZYDIS_MNEMONIC_OR) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
					InstrEmu::EmulateOR(context, instr.operands[0].reg.value, KUSD_USERMODE + (addr - KUSD_MIN));
					return SkipToNext(context);
				}
				else {

					DebugBreak();
				}
			}

			else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
					InstrEmu::EmulateXOR(context, instr.operands[0].reg.value, KUSD_USERMODE + (addr - KUSD_MIN));
					return SkipToNext(context);
				}
				else {

					DebugBreak();
				}
			}

			else if (instr.mnemonic == ZYDIS_MNEMONIC_AND) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {

					InstrEmu::EmulateAND(context, instr.operands[0].reg.value, KUSD_USERMODE + (addr - KUSD_MIN));
					return SkipToNext(context);
				}
				else {

					DebugBreak();
				}
			}

			else if (instr.mnemonic == ZYDIS_MNEMONIC_CMP) {
				if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && instr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) { //cmp [memory], reg
					InstrEmu::EmulateCMP(context, instr.operands[1].reg.value, KUSD_USERMODE + (addr - KUSD_MIN));
					return SkipToNext(context);
				}
				else if (instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) { //cmp reg, [memory]
					InstrEmu::EmulateCMP(context, instr.operands[0].reg.value, KUSD_USERMODE + (addr - KUSD_MIN));
					return SkipToNext(context);
				}
				else {
					DebugBreak();
				}
			}
			else if (instr.mnemonic == ZYDIS_MNEMONIC_MOVZX) {
				if (instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) { //cmp reg, [memory]
					InstrEmu::EmulateMOVZX(context, instr.operands[0].reg.value, KUSD_USERMODE + (addr - KUSD_MIN), instr.operands[1].size);
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

		bool EmulateOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr) { //X86-compliant MOV R64, [...] emulation

			uint64_t* context_lookup = (uint64_t*)ctx;
			auto reg_class = ZydisRegisterGetClass(reg);
			auto orig_value = context_lookup[GRegIndex(reg)];


			if (reg_class == ZYDIS_REGCLASS_GPR64) { //We replace the whole register
				context_lookup[GRegIndex(reg)] |= *(uint64_t*)ptr;

			}
			else if (reg_class == ZYDIS_REGCLASS_GPR32) { //We replace the whole register
				context_lookup[GRegIndex(reg)] |= *(uint32_t*)ptr;
			}
			else if (reg_class == ZYDIS_REGCLASS_GPR16) { // 16/8bits operation do not overwrite the rest of the register
				context_lookup[GRegIndex(reg)] |= (orig_value & 0xFFFFFFFFFFFF0000) | (*(uint16_t*)ptr);

			}
			else if (reg_class == ZYDIS_REGCLASS_GPR8) {  // 16/8bits operation do not overwrite the rest of the register
				if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
					context_lookup[GRegIndex(reg)] |= (orig_value & 0xFFFFFFFFFFFF00FF) | (*(uint8_t*)ptr) << 8;
				}
				else {  // 16/8bits operation do not overwrite the rest of the register
					context_lookup[GRegIndex(reg)] |= (orig_value & 0xFFFFFFFFFFFFFF00) | (*(uint8_t*)ptr);
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
			auto orig_value = context_lookup[GRegIndex(reg)];


			if (reg_class == ZYDIS_REGCLASS_GPR64) { //We replace the whole register
				context_lookup[GRegIndex(reg)] ^= *(uint64_t*)ptr;

			}
			else if (reg_class == ZYDIS_REGCLASS_GPR32) { //We replace the whole register
				context_lookup[GRegIndex(reg)] ^= *(uint32_t*)ptr;
			}
			else if (reg_class == ZYDIS_REGCLASS_GPR16) { // 16/8bits operation do not overwrite the rest of the register
				context_lookup[GRegIndex(reg)] ^= (orig_value & 0xFFFFFFFFFFFF0000) | (*(uint16_t*)ptr);

			}
			else if (reg_class == ZYDIS_REGCLASS_GPR8) {  // 16/8bits operation do not overwrite the rest of the register
				if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
					context_lookup[GRegIndex(reg)] ^= (orig_value & 0xFFFFFFFFFFFF00FF) | (*(uint8_t*)ptr) << 8;
				}
				else {  // 16/8bits operation do not overwrite the rest of the register
					context_lookup[GRegIndex(reg)] ^= (orig_value & 0xFFFFFFFFFFFFFF00) | (*(uint8_t*)ptr);
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
			auto orig_value = context_lookup[GRegIndex(reg)];


			if (reg_class == ZYDIS_REGCLASS_GPR64) { //We replace the whole register
				context_lookup[GRegIndex(reg)] &= *(uint64_t*)ptr;

			}
			else if (reg_class == ZYDIS_REGCLASS_GPR32) { //We replace the whole register
				context_lookup[GRegIndex(reg)] &= *(uint32_t*)ptr;
			}
			else if (reg_class == ZYDIS_REGCLASS_GPR16) { // 16/8bits operation do not overwrite the rest of the register
				context_lookup[GRegIndex(reg)] &= (orig_value & 0xFFFFFFFFFFFF0000) | (*(uint16_t*)ptr);

			}
			else if (reg_class == ZYDIS_REGCLASS_GPR8) {  // 16/8bits operation do not overwrite the rest of the register
				if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
					context_lookup[GRegIndex(reg)] &= (orig_value & 0xFFFFFFFFFFFF00FF) | (*(uint8_t*)ptr) << 8;
				}
				else {  // 16/8bits operation do not overwrite the rest of the register
					context_lookup[GRegIndex(reg)] &= (orig_value & 0xFFFFFFFFFFFFFF00) | (*(uint8_t*)ptr);
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
