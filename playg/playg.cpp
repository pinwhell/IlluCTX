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

#define HAS_CODE_LOGGER

//std::unique_ptr<Capstone> CodeLoggerCapstone;
//const auto CodeLogger = [&](const Uc::Hooks::Ev& ev, auto& next) {
//	auto& code = ev.mCode;
//	auto instBlob = ctx.mUc.mIo.Address(code.mAddress).ReadBlob(code.mSize);
//	auto instDism = cston.DisassembleOne(instBlob.data(), code.mAddress);
//	printf("Executed:%s\t %s %s\n",
//		CalledAtResolver::Addr2Line(
//			ctx.mUc.mRegs.Read<std::uint32_t>(
//				UC_ARM_REG_PC)).c_str(),
//		instDism.mInsn.mnemonic,
//		instDism.mInsn.op_str
//	);
//	return next(ev);
//	};

void ARMFnInvokeShowcase1()
{
	simplistic::proc::Self self{}; // This Process
	Context ctx(
		UC_ARCH_ARM, UC_MODE_ARM,
		self.Address(0),
		DEFAULT_STACK_SIZE,
		UC_PROT_ALL);
	auto val = ctx.mCaller(Caller::CallConv::ARM32_CDECL,
		/** Compiled Sample
		int foo(int a, int b, int c, int d, int e, int f)
		{
			return a + b + c + d + e + f;
		}*/
		*ctx.mStack.Push(Uint32ToUint8({ // RWX Stack Required
			0xE3A00206, // mov r0, #0x60000000
			0xE5900000,	// ldr r0, [r0] ; 4 byte IO
			0xE12FFF1E	// bx lr
			})));
	assert(val == 0xC0FEEu);
}

int main()
{
#ifdef _WIN32
	if (void* ptr = VirtualAlloc((void*)0x60000000, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
		*(uint64_t*)ptr = 0xC0FEEu;
#endif
	ARMFnInvokeShowcase1();
	return 0;
}