#pragma once

#include <Uc/Io.h>
#include <Uc/Regs.h>
#include <string_view>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <memory>

namespace Illu {
	struct Stack {
		Stack(Uc::Io& io, Uc::Regs& regs, std::uint32_t spType);
		Stack(Uc::Io& io, Uc::Regs& regs, std::uint32_t spType, std::uint64_t stackTopEntry);
		Stack(Uc::Io& io, Uc::Regs& regs, std::uint32_t spType, std::uint64_t stackEntry, std::size_t stackSize);

		struct AllocHandle {
			AllocHandle(Stack* stack, std::uint64_t ptr, std::uint64_t allocedSz, std::shared_ptr<AllocHandle> prev = 0);
			AllocHandle(AllocHandle&& other) noexcept;
			~AllocHandle();

			operator std::uint64_t();
			AllocHandle& operator=(AllocHandle&& other) noexcept;

			struct Ref {
				Stack* operator->();
				AllocHandle& operator*();

				std::shared_ptr<AllocHandle> mRef;
			};

			Stack* mStack;
			std::uint64_t mPtr;
			std::uint64_t mSize;
			std::shared_ptr<AllocHandle> mPrev;
		};

		std::uint64_t Peek(std::size_t idx = 0ull);
		AllocHandle::Ref Alloc(std::size_t len);
		AllocHandle::Ref Push4(std::uint32_t val, bool autoFree = true);
		AllocHandle::Ref Push8(std::uint64_t val, bool autoFree = true);
		AllocHandle::Ref Push(std::uint64_t val, bool autoFree = true);
		AllocHandle::Ref Push(std::string_view str, bool autoFree = true);
		AllocHandle::Ref Push(const std::vector<std::uint8_t>& arr, bool autoFree = true);
		std::uint64_t PopUnwnd(std::size_t nrBytes);
		std::uint64_t Pop();
		std::uint64_t operator *();
		void Unwind(std::size_t nrBytes);

		Uc::Io& mIO;
		Uc::Regs& mRegs;
		std::uint32_t mSpType;
		std::weak_ptr<AllocHandle> mLastHandle;
	};
}