#pragma once

#include <Uc/Engine.h>
#include <Illu/Stack.h>
#include <Illu/Caller.h>
#include <Illu/IoSyncer.h>
#include <Illu/Detours.h>

namespace Illu {
	constexpr auto DEFAULT_STACK_SIZE = 0x100000u;
	struct Context {
		Context(uc_arch arch, uc_mode mode, const simplistic::io::Object& targetAddrSpace, std::size_t stackSz = DEFAULT_STACK_SIZE, std::uint32_t stackProt = UC_PROT_READ | UC_PROT_WRITE);
		~Context();

		Uc::Engine mUc;
		Stack mStack;
		Caller mCaller;
		IoSyncer mIoSyncer;
		Detours mDetours;
	};
}