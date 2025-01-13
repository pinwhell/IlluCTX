#pragma once

#include <functional>
#include <deque>

namespace Illu { namespace RChain {
    template<typename Siganture>
    class Handler;

    template<typename T>
    inline T DefaultConstruct() {
        return T{};
    }

    // Template specialization for void type
    template<>
    inline void DefaultConstruct<void>() {}

    // Handler class
    template<typename T, typename... Args>
    class Handler<T(Args...)> {
    public:
        using _HandlerT = Handler<T(Args...)>;
        using Callback = std::function<T(Args..., _HandlerT&)>;

        Handler(const Callback& callback) : Handler(callback, nullptr) {}
        Handler(const Callback& callback, _HandlerT* nextHandler) : callback(callback), nextHandler(nextHandler) {}
        Handler() : callback([](Args..., _HandlerT&) -> T {
            return DefaultConstruct<T>();
            }), nextHandler(nullptr) {}

            void setNextHandler(Handler& next) {
                nextHandler = &next;
            }

            T operator()(Args&&... args) {
                return callback(std::forward<Args&&>(args)..., *nextHandler);
            }

    private:
        Callback callback;
        _HandlerT* nextHandler;
    };

    template<typename Siganture>
    class HandlerChain;

    template<typename T, typename... Args>
    class HandlerChain<T(Args...)> {
    public:
        using _Callback = typename Handler<T(Args...)>::Callback;
        using _HandlerT = Handler<T(Args...)>;
        using _ReturnT = T;
        using _HandlerChain = HandlerChain<T(Args...)>;

        // Default constructor
        HandlerChain(_HandlerT def = {}) {
            mHandlers.emplace_back(def);
        }

        // Add handler to the chain
        _HandlerChain& operator+=(const _Callback& callback) {
            mHandlers.emplace_back(callback, &(mHandlers.back()));
            return *this;
        }

        // Functor operator
        _ReturnT operator()(Args&&... args) {
            return mHandlers.back()(std::forward<Args&&>(args)...);
        }

        std::deque<_HandlerT> mHandlers;
    };
}}