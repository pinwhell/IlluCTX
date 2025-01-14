# IllusoryCTX

`IllusoryCTX` is a prototype library designed to enable `cross-address-space threading`, providing developers and researchers with a powerful abstraction layer for advanced low-level programming. Built on top of the `Unicorn Framework`, `IllusoryCTX` leverages dependencies like `SimplisticIO` and `UcPP (Unicorn Engine C++ Wrapper)` to deliver robust functionality.

This tool is ideal for anyone with a solid understanding of low-level systems who are exploring innovative ways to manipulate execution contexts. While it can be used as a standalone tool once dependencies are installed, its library nature allows seamless integration into custom applications.

Currently available as a prototype, `IllusoryCTX` supports flexible modifications to accommodate various architectures, empowering users to extend its capabilities to fit unique use cases.

# Example
Simple example reading demostrating `I/O` routing to its host address space. for the test  `0x60000000` must be preallocated holding a value of `0xC0FEE`. 

```cpp
simplistic::proc::Self self{}; // This Process
Context ctx(
    UC_ARCH_ARM, UC_MODE_ARM,
    self.Address(0) /*This process Address Space*/,
    DEFAULT_STACK_SIZE,
    UC_PROT_ALL);
auto val = ctx.mCaller(Caller::CallConv::ARM32_CDECL,
    /*Pushing code to the stack for simplicity ( Dont try at home =) )*/
    *ctx.mStack.Push(Uint32ToUint8({
        0xE3A00206, // mov r0, #0x60000000
        0xE5900000,	// ldr r0, [r0] ; 4 byte IO
        0xE12FFF1E	// bx lr
        })));
assert(val == 0xC0FEEu);
```
Leveraging `SimplisticProc` already implements `simplistic::io::IIO` for us. You can implement your own leveraging `SimplisticIO` too. `self.Address(0)` Would build that `simplistic::io::Object` that `IlluCTX` requires to route the entire `Address Space IO`
