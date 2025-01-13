#define NOMINMAX

#include <Illu/Context.h>
#include <algorithm>
#include <iterator>

using namespace Illu;

Stack::Stack(Uc::Io& io, Uc::Regs& regs, std::uint32_t spType)
	: mIO(io)
	, mRegs(regs)
	, mSpType(spType)
{}

Stack::Stack(Uc::Io& io, Uc::Regs& regs, std::uint32_t spType, std::uint64_t stackTopEntry)
	: Stack(io, regs, spType)
{
	mRegs.Write<std::uint64_t>(mSpType, stackTopEntry);
}

Stack::Stack(Uc::Io& io, Uc::Regs& regs, std::uint32_t spType, std::uint64_t stackEntry, std::size_t stackSize)
	: Stack(io, regs, spType, stackEntry + stackSize)
{}

Stack::AllocHandle::Ref Stack::Alloc(std::size_t len)
{
	mRegs.Write<std::uint64_t>(mSpType, **this - len);
	auto res = std::make_shared<AllocHandle>(this, **this, len, mLastHandle.lock());
	mLastHandle = res;
	return { res };
}

Stack::AllocHandle::Ref Stack::Push4(std::uint32_t val, bool autoFree)
{
	auto handle = Alloc(sizeof(std::uint32_t));
	mIO.Write<std::uint32_t, std::uint64_t>(*handle, val);
	if (!autoFree) (*handle).mStack = 0;
	return handle;
}

Stack::AllocHandle::Ref Stack::Push8(std::uint64_t val, bool autoFree)
{
	auto handle = Alloc(sizeof(std::uint64_t));
	mIO.Write<std::uint64_t, std::uint64_t>(*handle, val);
	if (!autoFree) (*handle).mStack = 0;
	return handle;
}

Stack::AllocHandle::Ref Stack::Push(std::uint64_t val, bool autoFree)
{
	return mIO.mUc.mIs64 ?
		Push8(val, autoFree) :
		Push4(val, autoFree);
}

Stack::AllocHandle::Ref Stack::Push(std::string_view str, bool autoFree)
{
	size_t ALIGNMENT = (mIO.mUc.mIs64 ? 8u : 4u);
	size_t ALIGN_MASK = ALIGNMENT - 1u;
	size_t alignedAllocSz = ALIGNMENT + ((str.size() + ALIGN_MASK) & ~ALIGN_MASK);
	auto handle = Alloc(alignedAllocSz);
	mIO.WriteRawT((*handle).mPtr, str.data(), str.size());
	if (!autoFree) (*handle).mStack = 0;
	return handle;
}

Stack::AllocHandle::Ref Stack::Push(const std::vector<std::uint8_t>& arr, bool autoFree)
{
	size_t ALIGNMENT = (mIO.mUc.mIs64 ? 8u : 4u);
	size_t ALIGN_MASK = ALIGNMENT - 1u;
	size_t alignedAllocSz = ALIGNMENT + ((arr.size() + ALIGN_MASK) & ~ALIGN_MASK);
	auto handle = Alloc(alignedAllocSz);
	mIO.WriteRawT((*handle).mPtr, arr.data(), arr.size());
	if (!autoFree) (*handle).mStack = 0;
	return handle;
}

std::uint64_t Stack::Pop()
{
	auto oldSp = **this;
	Unwind(mIO.mUc.mIs64 ? 8u : 4u);
	return mIO.Address(oldSp).ReadPtr();
}

void Stack::Unwind(std::size_t nrBytes)
{
	if (!nrBytes) return; // Do Nothing
	mRegs.Write(mSpType, **this + nrBytes);
}

std::uint64_t Stack::Peek(std::size_t idx)
{
	std::uint64_t val{};
	const auto rowSz = mIO.mUc.mIs64 ? 8u : 4u;
	mIO.ReadRawT(**this + rowSz * idx, &val, rowSz);
	return val;
}

std::uint64_t Stack::PopUnwnd(std::size_t nrBytes)
{
	auto val = Pop();
	Unwind(nrBytes);
	return val;
}

std::uint64_t Stack::operator*()
{
	return mRegs.Read<std::uint64_t>(mSpType);
}

Stack::AllocHandle::AllocHandle(Stack* stack, std::uint64_t ptr, std::uint64_t allocedSz, std::shared_ptr<AllocHandle> prev)
	: mStack(stack)
	, mPtr(ptr)
	, mSize(allocedSz)
	, mPrev(prev)
{}

Stack::AllocHandle::AllocHandle(AllocHandle&& other) noexcept
{
	*this = std::move(other);
}

Stack::AllocHandle::~AllocHandle()
{
	if (!mStack || !mSize) return;
	mStack->mRegs.Write<std::uint64_t>(mStack->mSpType, **mStack + mSize);
	if (mStack->mLastHandle.lock().get() == this)
		mStack->mLastHandle = mPrev;
}

Stack::AllocHandle::operator std::uint64_t()
{
	return mPtr;
}

Stack::AllocHandle& Stack::AllocHandle::operator=(AllocHandle&& other) noexcept
{
	mSize = other.mSize;
	mStack = other.mStack;
	mPrev = other.mPrev;
	mPtr = other.mPtr;
	other.mSize = 0;
	other.mStack = 0;
	other.mPtr = 0;
	return *this;
}

Stack* Stack::AllocHandle::Ref::operator->()
{
	return mRef->mStack;
}

Stack::AllocHandle& Stack::AllocHandle::Ref::operator*()
{
	return *mRef;
}

Caller::Caller(Uc::Engine& uc, Stack& stack, IntrDesc irupDesc)
	: mUc(uc)
	, mIo(mUc.mIo)
	, mRegs(mUc.mRegs)
	, mStack(stack)
	, mIrupDesc(irupDesc)
{
	mRaiseAddr = mUc.mMem.Map(mIrupDesc.mInst.data(), mIrupDesc.mInst.size(), UC_PROT_ALL);
}

Stack::AllocHandle::Ref Caller::InstallArgsReturn(CallConv callConv, const std::vector<std::uint32_t>& args)
{
	switch (callConv)
	{
	case CallConv::X8632LNX_REGPARAM3:
	{
		switch (args.size())
		{
		default:
		case 3: mRegs.Write(UC_X86_REG_ECX, args[2]);
		case 2: mRegs.Write(UC_X86_REG_EDX, args[1]);
		case 1: mRegs.Write(UC_X86_REG_EAX, args[0]);
		case 0: break;
		};
		Stack::AllocHandle::Ref handle{};
		if (args.size() > 3)
		{
			auto argsRem = args.size() - 3u;
			handle = mStack.Alloc(argsRem * sizeof(std::uint32_t));
			mIo.WriteRawT<std::uint64_t>(*handle, args.data() + 3, argsRem * sizeof(std::uint32_t));
		}
		Stack::AllocHandle::Ref retAddr = mStack.Push(mRaiseAddr);
		(*retAddr).mSize -= sizeof(std::uint32_t); // Return Cosumed by ret...
		return retAddr;
	}

	case CallConv::ARM32_AAPCS_GEN:
	{
		switch (args.size())
		{
		default:
		case 4: mRegs.Write(UC_ARM_REG_R3, args[3]);
		case 3: mRegs.Write(UC_ARM_REG_R2, args[2]);
		case 2: mRegs.Write(UC_ARM_REG_R1, args[1]);
		case 1: mRegs.Write(UC_ARM_REG_R0, args[0]);
		case 0: break;
		};
		Stack::AllocHandle::Ref handle{};
		if (args.size() > 4)
		{
			auto argsRem = args.size() - 4u;
			handle = mStack.Alloc(argsRem * sizeof(std::uint32_t));
			mIo.WriteRawT<std::uint64_t>(*handle, args.data() + 4, argsRem * sizeof(std::uint32_t));
		}
		mRegs.Write(UC_ARM_REG_LR, mRaiseAddr);
		return handle;
	}

	};
	return {};
}

std::uint64_t Caller::ExtractReturn(CallConv callConv)
{
	switch (callConv)
	{
	case CallConv::X8632LNX_REGPARAM3:
	case CallConv::X8632WINR3_CDECL:
		return mRegs.Read<std::uint64_t>(UC_X86_REG_EAX);

	case CallConv::ARM32_AAPCS_GEN:
		return mRegs.Read<std::uint64_t>(UC_ARM_REG_R0);
	};
	return 0u;
}

std::uint64_t Caller::Call(CallConv callConv, std::uint64_t at, const std::vector<std::uint64_t>& _args)
{
	std::vector<std::uint32_t> args; args.reserve(_args.size() + 1);
	std::transform(_args.begin(), _args.end(), std::back_inserter(args), [](uint64_t value) {
		return static_cast<uint32_t>(value);
		});
	auto handle = InstallArgsReturn(callConv, args);
	mUc.Ignite(at);
	return ExtractReturn(callConv);
}

IoSyncer::IoSyncer(Uc::Hooks& hooks, Uc::Mem& mem, const simplistic::io::Object& ucAs, const simplistic::io::Object& targetAs, Uc::Regs& regs)
	: mUcAS(ucAs)
	, mTargetAS(targetAs)
	, mMem(mem)
	, mRegs(regs)
{
	hooks.AddHook(UC_HOOK_MEM_INVALID, [this](const auto& ev, auto& next)
		{
			const auto UC_MEM_X_UNMAPPED =
				1ull << UC_MEM_READ_UNMAPPED |
				1ull << UC_MEM_WRITE_UNMAPPED |
				1ull << UC_MEM_FETCH_UNMAPPED;
			if (!((1u << ev.mMem.mType) & UC_MEM_X_UNMAPPED))
				return next(ev);
			return Map(ev.mMem.mAddress >> 12);
		});

	hooks.AddHook(UC_HOOK_MEM_VALID, [this](const auto& ev, auto& next)
		{
			return Sync(ev.mMem.mAddress, ev.mMem.mSize) && next(ev);
		});
}

bool IoSyncer::Map(std::uint64_t pageId, bool isX, bool withContent)
{
	//if (!pageId) return false; // Dont try mapping nullptr =|
	const auto pageSize = 1u << 12;
	const auto pageBase = pageId << 12;
	const auto PROT = UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC;
	if (mMem.Alloc(pageSize, PROT, pageBase) == ~0ull) return false;
	if (withContent) return Sync(pageId);
	return true;
}


/*This sync family functions can
be optimized in the future... by removing the 2 step
update into a single one... in coordination with mapped
instead of allocated Mem
// Expects page existing already*/

bool IoSyncer::Sync(std::uint64_t entry, std::size_t nrBytes)
{
	if ((entry >> 12u) > (mMem.mVirtualLimit >> 12u)) return true; // Dont sync local virtual mem
	if (!entry) return true; // Dont try syncin nullptr =|
	try {
		auto blob = mTargetAS.ReadBlob(nrBytes, entry);
		if (mUcAS.mIO->WriteRawT(entry, blob.data(), blob.size()) != nrBytes)
			return false;
		return true;
	}
	catch (const std::exception& e)
	{
	}
	return false;
}

bool IoSyncer::Sync(std::uint64_t pageId)
{
	if (pageId > (mMem.mVirtualLimit >> 12u)) return true; // Dont sync local virtual mem
	if (!pageId) return true; // Dont try syncin nullptr =|
	const auto pageSize = 1u << 12;
	const auto pageBase = pageId << 12;
	try {
		auto pageBlob = mTargetAS.ReadBlob(pageSize, pageBase);
		if (mUcAS.mIO->WriteRawT(pageBase, pageBlob.data(), pageBlob.size()) != pageSize)
			return false;
		return true;
	}
	catch (const std::exception& e)
	{
	}
	return false;
}

Detours::Detour::Detour(CallConv callConv, std::size_t nrArg)
	: mCallConv(callConv)
	, mnrArgs(nrArg)
{}

Detours::Args Detours::Detour::Params(Stack& stack, Uc::Regs& regs)
{
	return [this, &stack, &regs](std::uint64_t paramId)
		{
			switch (mCallConv)
			{
			case CallConv::X8632LNX_REGPARAM3:
			{
				if (paramId < 3u) {
					switch (paramId)
					{
					case 2: return regs.Read<std::uint64_t>(UC_X86_REG_ECX);
					case 1: return regs.Read<std::uint64_t>(UC_X86_REG_EDX);
					case 0: return regs.Read<std::uint64_t>(UC_X86_REG_EAX);
					};
				}
				paramId -= 3u;
			}
			// Fallback to peekin
			case CallConv::X8632WINR3_CDECL:
			case CallConv::X8632WINR3_STDCALL:
				return stack.Peek(paramId + 1);

			};
			throw std::runtime_error("Unimpl");
		};
}

Stack::AllocHandle Detours::Detour::MakeStackCleaner(Stack& stack)
{
	switch (mCallConv)
	{
	case CallConv::X8632LNX_REGPARAM3:
		return { &stack, 1u, std::uint64_t(std::max(std::int64_t(mnrArgs) - 3ll, 0ll)) * (stack.mIO.mUc.mIs64 ? 8u : 4u), 0u };
	case CallConv::X8632WINR3_CDECL:
	case CallConv::X8632WINR3_STDCALL:
		return { &stack, 1u, mnrArgs * (stack.mIO.mUc.mIs64 ? 8u : 4u), 0u };
	};
	throw std::runtime_error("Unimpl");
}

Detours::Detours(IoSyncer& ioSyncer, Uc::Hooks& hooks, Stack& stack, Uc::Regs& regs, std::uint32_t ipRegType, std::uint32_t retRegType, IntrDesc intrDesc)
	: mIoSyncer(ioSyncer)
	, mStack(stack)
	, mRegs(regs)
	, mIpRegType(ipRegType)
	, mRetRegType(retRegType)
	, mIntrDesc(intrDesc)
{
	hooks.AddHook(UC_HOOK_INTR, [this](const auto& ev, auto& next) {
		if (ev.mIntr.mNr != mIntrDesc.mNr) return next(ev);
		auto ip = mRegs.Read<std::uint64_t>(mIpRegType) - mIntrDesc.mInst.size() /* We Already Exec BP */;
		auto detourIt = mDetours.find(ip);
		if (detourIt == mDetours.end()) return next(ev);

		Detour& desc = *detourIt->second;
		auto stackCleaner = desc.MakeStackCleaner(mStack);

		mRegs.Write(mRetRegType,	/*Ret Val	*/ desc.mChain(desc.Params(mStack, mRegs)));
		mRegs.Write(mIpRegType,		/*Ret Addr	*/ mStack.Pop());

		return true;
		});
}

Detours& Detours::Declare(CallConv cconv, std::uint64_t entry, std::uint64_t nrArgs, Callback def)
{
	if (mDetours.find(entry) != mDetours.end()) return *this;
	mDetours[entry] = std::make_unique<Detour>(cconv, nrArgs);
	if (def) mDetours[entry]->mChain += def;
	return *this;
}

Detours& Detours::Declare(CallConv cconv, std::uint64_t entry, Callback def)
{
	return Declare(cconv, entry, 0u, def);
}

bool Detours::Install(std::uint64_t entry, Callback cb)
{
	const auto tryInstallIrupt = [&] {
		auto& iruptIsnt = mIntrDesc.mInst;
		return mIoSyncer.mUcAS.mIO->WriteRawT(entry, iruptIsnt.data(), iruptIsnt.size()) == iruptIsnt.size();
		};

	if (cb) mDetours[entry]->mChain += cb;
	if (!tryInstallIrupt() && (!mIoSyncer.Map(entry >> 12, true) || !tryInstallIrupt())) {
		if (cb) mDetours[entry]->mChain.mHandlers.pop_back();
		return false;
	}
	return true;
}

std::uint32_t IPRegTypeFromArchMode(uc_arch arch, uc_mode mode)
{
	switch (arch)
	{
	case UC_ARCH_ARM:
	{
		if (mode & UC_MODE_64) return UC_ARM64_REG_PC;
		return UC_ARM_REG_PC; // SP
	};
	case UC_ARCH_X86:
	{
		if (mode & UC_MODE_64) return UC_X86_REG_EIP;
		return UC_X86_REG_RIP;
	};
	}
	throw std::logic_error("Unimpl");
}

std::uint32_t SPRegTypeFromArchMode(uc_arch arch, uc_mode mode)
{
	switch (arch)
	{
	case UC_ARCH_ARM:
	{
		if (mode & UC_MODE_64) return UC_ARM64_REG_SP;
		return UC_ARM_REG_SP; // SP
	};
	case UC_ARCH_X86:
	{
		if (mode & UC_MODE_64) return UC_X86_REG_ESP;
		return UC_X86_REG_RSP;
	};
	}
	throw std::logic_error("Unimpl");
}

IntrDesc CallRetIntrFromArchMode(uc_arch arch, uc_mode mode)
{
	switch (arch)
	{
	case UC_ARCH_ARM:
	{
		if (mode & UC_MODE_64) throw std::logic_error("Unimpl");
		return { { 0x01, 0x00, 0x00, 0xEF } };
	};
	case UC_ARCH_X86:
	{
		if (mode & UC_MODE_64) throw std::logic_error("Unimpl");
		return { { 0xF4u } };
	};
	}

	throw std::logic_error("Unimpl");
}

IntrDesc DetourIntrFromArchMode(uc_arch arch, uc_mode mode)
{
	switch (arch)
	{
	case UC_ARCH_ARM:
	{
		if (mode & UC_MODE_64) 	throw std::logic_error("Unimpl");
		return { { 0x03, 0x00, 0x00, 0xEF }, 3u };
	};
	case UC_ARCH_X86:
	{
		if (mode & UC_MODE_64) throw std::logic_error("Unimpl");
		return { { 0xCCu }, 3u };
	};
	}

	throw std::logic_error("Unimpl");
}

std::uint32_t RetRegTypeFromArchMode(uc_arch arch, uc_mode mode)
{
	switch (arch)
	{
	case UC_ARCH_ARM:
	{
		if (mode & UC_MODE_64) return UC_ARM64_REG_X0;
		return UC_ARM_REG_R0;
	};
	case UC_ARCH_X86:
	{
		if (mode & UC_MODE_64) return UC_X86_REG_EAX;
		return UC_X86_REG_RAX;
	};
	}
	throw std::logic_error("Unimpl");
}

Context::Context(uc_arch arch, uc_mode mode, const simplistic::io::Object& targetAs, std::size_t stackSz, std::uint32_t stackProt)
	: mUc(arch, mode)
	, mStack(
		mUc.mIo,
		mUc.mRegs,
		SPRegTypeFromArchMode(
			arch,
			mode),
		mUc.mMem.Alloc(
			stackSz,
			stackProt),
		stackSz)
	, mCaller(
		mUc,
		mStack,
		CallRetIntrFromArchMode(
			arch,
			mode))
	, mIoSyncer(
		mUc.mHooks,
		mUc.mMem,
		mUc.mIo.Address(0),
		targetAs,
		mUc.mRegs)
	, mDetours(
		mIoSyncer,
		mUc.mHooks,
		mStack,
		mUc.mRegs,
		IPRegTypeFromArchMode(
			arch,
			mode),
		RetRegTypeFromArchMode(
			arch,
			mode),
		DetourIntrFromArchMode(
			arch,
			mode))
{}

Context::~Context()
{}