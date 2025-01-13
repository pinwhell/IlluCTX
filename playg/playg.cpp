#define NOMINMAX

#include <simplistic/proc.h>
#include <Illu/Context.h>
#include <CStone/CStone.h>
#include <iostream>

#include "CalledAtResolver.h" /*Old utility*/

using namespace Illu;

auto Uint32ToUint8 = [](const std::vector<uint32_t>& u32Arr) {
	std::vector<uint8_t> u8Arr;
	for (uint32_t u32 : u32Arr) {
		u8Arr.push_back(static_cast<uint8_t>(u32 & 0xFF));
		u8Arr.push_back(static_cast<uint8_t>((u32 >> 8) & 0xFF));
		u8Arr.push_back(static_cast<uint8_t>((u32 >> 16) & 0xFF));
		u8Arr.push_back(static_cast<uint8_t>((u32 >> 24) & 0xFF));
	}
	return u8Arr;
	};

int main()
{
	simplistic::proc::Self self{}; // This Process
	Context ctx(UC_ARCH_ARM, UC_MODE_ARM, self.Address(0), DEFAULT_STACK_SIZE, UC_PROT_ALL);
#ifdef HAS_CSTONE
	Capstone cston(CS_ARCH_ARM, CS_MODE_ARM);
	ctx.mUc.mHooks.AddHook(UC_HOOK_CODE, [&](const Uc::Hooks::Ev& ev, auto& next) {
		auto& code = ev.mCode;
		auto instBlob = ctx.mUc.mIo.Address(code.mAddress).ReadBlob(code.mSize);
		auto instDism = cston.DisassembleOne(instBlob.data(), code.mAddress);
		printf("Executed:%s\t %s %s\n",
			CalledAtResolver::Addr2Line(
				ctx.mUc.mRegs.Read<std::uint32_t>(
					UC_ARM_REG_PC)).c_str(),
			instDism.mInsn.mnemonic,
			instDism.mInsn.op_str
		);
		return next(ev);
		});
#endif
	auto res = ctx.mCaller(Caller::CallConv::ARM32_CDECL,
		*ctx.mStack.Push(Uint32ToUint8({ // RWX Stack Required
			0xE92D4800, //  push {r11, lr}
			0xE0810000, //  add  r0, r1, r0
			0xE59DE008, //  ldr  lr,[sp, #8]
			0xE0800002, //  add  r0, r0, r2
			0xE59DC00C, //  ldr  r12,[sp, #12]
			0xE0800003, //  add  r0, r0, r3
			0xE080000E, //  add  r0, r0, lr
			0xE080000C, //  add  r0, r0, r12
			0xE8BD8800, //  pop  {r11, pc}
			})), 1u, 2u, 3u, 4u, 5u, 6u); // 21u
	std::cout << "res=" << res << std::endl;
	return 0;
}