#pragma once

#include <unordered_map>
#include <string>

#define IN_RANGE(min, x, max) ((x) > (min) && (x) < (max))
#define ALWAYS_INLINE __attribute__((always_inline))

struct ObjectInfo {
    std::string name;
    std::uint64_t entry;
    size_t size;
};

class CalledAtResolver
{
public:

    static std::unordered_map<std::string, ObjectInfo>& getObjsRef()
    {
        static std::unordered_map<std::string, ObjectInfo> allObjects;

        return allObjects;
    }

    static void RegisterObject(const char* objName, std::uint64_t objEntry, size_t objSize)
    {
        std::unordered_map<std::string, ObjectInfo>& ois = getObjsRef();
        ObjectInfo oi;

        oi.name = objName;
        oi.entry = objEntry;
        oi.size = objSize;

        ois[oi.name] = oi;
    }

    static std::string Addr2Line(std::uint64_t addr, bool* bWasSolved = nullptr)
    {
        std::unordered_map<std::string, ObjectInfo>& ois = getObjsRef();
        char line[512];

        if(bWasSolved)
            *bWasSolved = false;

        for(auto& kv : ois) {
            std::uint64_t currObjStart = kv.second.entry;
            std::uint64_t currObjEnd = kv.second.entry + kv.second.size;

            if(IN_RANGE(currObjStart, (std::uint64_t)addr, currObjEnd)) {
                std::uint64_t offToSymbol =  addr - currObjStart;
                snprintf(line, 512, "%s+%llX", kv.first.c_str(), offToSymbol);

                if(bWasSolved)
                    *bWasSolved = true;

                return std::string(line);
            }
        }

        snprintf(line, 512, "0x%llX", addr);

        return std::string(line);
    }
};