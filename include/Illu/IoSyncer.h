#pragma once

#include <Uc/Hooks.h>
#include <Uc/Mem.h>
#include <Uc/Regs.h>

namespace Illu {
	struct IoSyncer {
		IoSyncer(
			Uc::Hooks& hooks,
			Uc::Mem& mem,
			const simplistic::io::Object& ucAs,
			const simplistic::io::Object& targetAs,
			Uc::Regs& regs
		);

		bool Map(std::uint64_t pageId, bool isX = false, bool withContent = true);
		/*
		   This sync family function can be optimized in the future by consolidating the
		   two-step update process into a single operation. This can be achieved by
		   coordinating with the Memory component to use mapped pages, rather than
		   relying on privately allocated internal memory. allowing us to bypass emulator
		   read/writing apis and read/write memory directly
		*/

		/*
		* This Assumes the page exists already
		*/
		bool Sync(std::uint64_t entry, std::size_t nrBytes);
		bool Sync(std::uint64_t pageId);

		Uc::Mem& mMem;
		simplistic::io::Object mUcAS;
		simplistic::io::Object mTargetAS;
		Uc::Regs& mRegs;
	};
}