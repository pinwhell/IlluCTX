#pragma once

#include <cstdint>
#include <vector>

namespace Illu {
	struct IntrDesc {
		std::vector<std::uint8_t> mInst;
		std::uint32_t mNr;
	};
}