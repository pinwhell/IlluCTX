#pragma once

#include <Illu/RChain.h>
#include <Illu/Stack.h>
#include <Illu/IoSyncer.h>
#include <Illu/IntrDesc.h>
#include <Uc/Regs.h>
#include <Uc/Hooks.h>
#include <unordered_map>
#include <memory>
#include <cstdint>
#include <cstddef>

namespace Illu {
	struct Detours {
		using Args = std::function<std::uint64_t(std::uint64_t)>;
		using HandlerChain = RChain::HandlerChain<std::uint64_t(Args)>;
		using Handler = HandlerChain::_HandlerT;
		using Callback = HandlerChain::_Callback;

		enum class CallConv {
			X8632WINR3_CDECL,
			X8632WINR3_STDCALL,
			X8632LNX_REGPARAM3
		};

		struct Detour {
			Detour(CallConv callConv, std::size_t nrArg = 0);

			Args Params(Stack& stack, Uc::Regs& regs);
			Stack::AllocHandle MakeStackCleaner(Stack& stack);

			CallConv mCallConv;
			std::size_t mnrArgs = 0;
			HandlerChain mChain;
		};

		Detours(IoSyncer& ioSyncer, Uc::Hooks& hooks, Stack& stack, Uc::Regs& regs, std::uint32_t ipRegType, std::uint32_t retRegType, IntrDesc intrDesc);

		Detours& Declare(CallConv cconv, std::uint64_t entry, std::uint64_t nrArgs, Callback def = 0);
		Detours& Declare(CallConv cconv, std::uint64_t entry, Callback def = 0);
		bool Install(std::uint64_t entry, Callback cb = 0);

		IoSyncer& mIoSyncer;
		Stack& mStack;
		Uc::Regs& mRegs;
		std::uint32_t mIpRegType;
		std::uint32_t mRetRegType;
		IntrDesc mIntrDesc;
		std::unordered_map<std::uint64_t, std::unique_ptr<Detour>> mDetours;
	};
}