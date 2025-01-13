#pragma once

#include <Uc/Engine.h>
#include <Illu/Stack.h>
#include <Illu/IntrDesc.h>
#include <vector>
#include <cstdint>

namespace Illu {
	struct Caller {
		enum class CallConv {
			X8632WINR3_CDECL,
			X8632LNX_REGPARAM3,
			ARM32_AAPCS_GEN,
			ARM32_CDECL = ARM32_AAPCS_GEN,
			ARM32_THISCALL = ARM32_AAPCS_GEN
		};

		Caller(Uc::Engine& uc, Stack& stack, IntrDesc irupDesc);

		template<typename TCallConv, typename ...TArgs>
		std::uint32_t operator()(TCallConv callConv, std::uint64_t at, TArgs&&... args)
		{
			return Call((CallConv)callConv, at, { static_cast<std::uint64_t>(args)... });
		}

		Uc::Engine& mUc;
		Uc::Io& mIo;
		Uc::Regs& mRegs;
		Stack& mStack;
		IntrDesc mIrupDesc;
		std::uint64_t mRaiseAddr;

	private:

		Stack::AllocHandle::Ref InstallArgsReturn(CallConv callConv, const std::vector<std::uint32_t>& args);
		std::uint64_t ExtractReturn(CallConv callConv);
		std::uint64_t Call(CallConv callConv, std::uint64_t at, const std::vector<std::uint64_t>& _args = {});
	};
}