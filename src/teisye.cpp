/* Copyright (C) 2010 Daiqian Huang <daiqian.huang@outlook.com>
 *
 * teisye is free software; you can redistribute it and/or modify it 
 * under the terms of the MIT License.
 */
 
/**
 * @file teisye.cpp
 *
 * The implementation of teisye memory allocator.
 */
#if defined(_WIN32)

#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT    _WIN32_WINNT_WIN7
#endif

#define WIN32_LEAN_AND_MEAN     // Exclude rarely-used stuff from Windows headers
#define NOMINMAX                // Exclude macros min and max
#define _ENABLE_ATOMIC_ALIGNMENT_FIX
#include <windows.h>

BOOL APIENTRY
DllMain(HMODULE, DWORD, LPVOID)
{
    return true;
}
#endif

#include <cstdint>
#include <cstring>
#include <atomic>
#include <limits>
#include <cassert>
#include <algorithm>
#include "teisye.h"

namespace teisye
{
using namespace std;

inline size_t adjust_size(size_t size) noexcept
{
    return (size + alignof(void*)-1) & (~((alignof(void*)-1)));
}

template<typename T>
inline T adjust_pointer(const void* ptr, size_t delta = 0) noexcept
{
    return reinterpret_cast<T>(adjust_size(reinterpret_cast<size_t>(ptr) + delta));
}

inline size_t pointer_diff(const void *right, const void *left) noexcept
{
    return reinterpret_cast<size_t>(right) - reinterpret_cast<size_t>(left);
}

template<typename T>
class stack
{
    using node_t = T;
    node_t _head{};

public:
    inline node_t top() const noexcept
    {
        return _head;
    }

    inline void push(node_t node) noexcept
    {
        node->_next = _head;
        _head = node;
    }

    inline node_t pop() noexcept
    {
        node_t node = _head;
        if (node) _head = node->_next;
        return node;
    }
};

template<typename T>
class stack_sl
{
    using node_t = T;
    node_t _head{};
    atomic_flag  _spin_lock{};

public:
    inline node_t top() const noexcept
    {
        return _head;
    }

    inline void push(node_t node) noexcept
    {
        while (_spin_lock.test_and_set());
        node->_next = _head;
        _head = node;
        _spin_lock.clear();
    }

    inline void push(node_t head, node_t tail) noexcept
    {
        while (_spin_lock.test_and_set());
        tail->_next = _head;
        _head = head;
        _spin_lock.clear();
    }

    inline node_t pop() noexcept
    {
        while (_spin_lock.test_and_set());
        node_t node = _head;
        if (node) _head = node->_next;
        _spin_lock.clear();
        return node;
    }
};

template<typename T>
class atomic_stack
{
    using node_t = T;

    atomic<node_t>  _head{};

public:
    inline node_t top() noexcept
    {
        return _head;
    }

    inline void push(node_t node) noexcept
    {
        node_t old{ _head };

        do
        {
            node->_next = old;
        }
        while (!_head.compare_exchange_weak(old, node));
    }

    inline node_t pop() noexcept
    {
        node_t node{ _head };

        while (node)
        {
            node_t new_head = node->_next;
            if (_head.compare_exchange_weak(node, new_head)) break;
        }

        return node;
    }

    // pop node if it is the head
    inline bool pop(node_t node) noexcept
    {
        if (node != _head)  return false;

        return _head.compare_exchange_weak(node, node->_next);
    }
};

template<typename T>
class atomic_stack_v
{
    using node_t = T;

    struct head_version
    {
        node_t      _head;
        uintptr_t   _version;
    };

    atomic<head_version> _hv{};

public:
    inline node_t top() noexcept
    {
        return static_cast<head_version>(_hv)._head;
    }

    inline void push(node_t node) noexcept
    {
        head_version old_hv = _hv;
        head_version new_hv;

        new_hv._head = node;
        do
        {
            node->_next = old_hv._head;
            new_hv._version = old_hv._version + 1;
        }
        while (!_hv.compare_exchange_weak(old_hv, new_hv));
    }

    inline void push(node_t head, node_t tail) noexcept
    {
        head_version old_hv = _hv;
        head_version new_hv;

        new_hv._head = head;
        do
        {
            tail->_next = old_hv._head;
            new_hv._version = old_hv._version + 1;
        }
        while (!_hv.compare_exchange_weak(old_hv, new_hv));
    }

    inline node_t pop() noexcept
    {
        head_version old_hv = _hv;
        head_version new_hv;
        node_t head;

        do
        {
            head = old_hv._head;
            if (!head) break;
            new_hv._head = head->_next;
            new_hv._version = old_hv._version + 1;
        }
        while (!_hv.compare_exchange_weak(old_hv, new_hv));

        return head;
    }
};

enum : size_t
{
    max_small_size = 512, max_medium_size = 1024 * 8, max_large_size = 1024 * 128
};
using key_t = int8_t;

class size_book
{
    static constexpr const int _count = 50;

    size_t _book[_count]
    {
        16, 32, 48, 64, 80, 96, 112, 128,                       // increase by 16 bytes
        160, 192, 224, 256,                                     // increase by 32 bytes
        304, 352, 400, 448,                                     // increase by 48 bytes
        512, 576, 640, 704, 768, 832, 896, 960, 1024,           // increase by 64 bytes
        1152, 1280, 1408, 1536, 1664, 1792, 1920, 2048,         // increase by 128 bytes
        2304, 2560, 2816, 3072, 3328, 3584, 3840, 4096,         // increase by 256 bytes
        4608, 5120, 5632, 6144, 6656, 7168, 7680, 8192,         // increase by 512 bytes
        //9216, 10240, 11264, 12288, 13312, 14336, 15360, 16384,  // increase by 1024 bytes
        max_large_size
    };

    const key_t _key_max_small = key(max_small_size);
    const key_t _key_max_medium = key(max_medium_size);
    const key_t _key_max_large = key(max_large_size);

public:
    static constexpr int count() noexcept
    {
        return _count;
    }

    inline key_t key(size_t size) const noexcept
    {
        if (size <= 16) return 0;;

        key_t base = 0;
        size_t k;

        k = (size - 1) / 16;
        if (k < 8)
        {
            return static_cast<key_t>(k);
        }

        base += 8;
        k = (size - 1) / 32 - 4;
        if (k < 4)
        {
            return base + static_cast<key_t>(k);
        }

        base += 4;
        k = (size + 31) / 48 - 6;
        if (k < 4)
        {
            return base + static_cast<key_t>(k);
        }

        base += 4;
        k = (size - 1) / 64 - 7;
        if (k < 9)
        {
            return base + static_cast<key_t>(k);
        }

        base += 9;
        k = (size - 1) / 128 - 8;
        if (k < 8)
        {
            return base + static_cast<key_t>(k);
        }

        base += 8;
        k = (size - 1) / 256 - 8;
        if (k < 8)
        {
            return base + static_cast<key_t>(k);
        }

        base += 8;
        k = (size - 1) / 512 - 8;
        if (k < 8)
        {
            return base + static_cast<key_t>(k);
        }

        //base += 8;
        //k = (size - 1) / 1024 - 8;
        //if (k < 8)
        //{
        //    return base + static_cast<key_t>(k);
        //}

        base += 8;
        if (size > max_large_size)
        {
            ++base;
        }

        return base;
    }

    inline size_t value(key_t key) const noexcept
    {
        return key < _count ? _book[key] : numeric_limits<size_t>::max();
    }

    inline key_t key_max_small() const noexcept
    {
        return _key_max_small;
    }

    inline key_t key_max_medium() const noexcept
    {
        return _key_max_medium;
    }

    inline key_t key_max_large() const noexcept
    {
        return _key_max_large;
    }
};

struct memory_unit
{
    struct header
    {
        uint16_t _signature;
        key_t    _key;
        int8_t   _idle;
        uint32_t _size;
    };

    header _header;
    memory_unit* _next;
};

template<typename U, size_t Val>
struct slab_base
{
    enum : size_t { _slab_size = Val };
    using unit_t = U;
    unit_t* _first;
    unit_t* _last;

    inline slab_base() noexcept
    {
        _last = adjust_pointer<unit_t*>(this, _slab_size);
    }

    void* operator new(size_t)
    {
        return ::malloc(_slab_size);
    }

    void operator delete(void *ptr)
    {
        ::free(ptr);
    }
};

template<typename S, typename U>
class slabs
{
    using slab_t = S;
    using unit_t = U;
    atomic_stack <slab_t*>   _slabs;

public:
    inline unit_t* alloc(size_t size)  noexcept
    {
        assert(adjust_size(size) == size);

        unit_t *unit{};
        for (auto s = _slabs.top(); s; s = s->_next)
        {
            unit = s->alloc(size);
            if (unit) return unit;
        }

        // need a new slab
        auto s = new slab_t;
        if (s)
        {
            unit = s->alloc(size);
            _slabs.push(s);
        }

        return unit;
    }
};

template<typename T>
struct heap_small
{
    T _hashmap[size_book::count()] {};

    inline memory_unit* alloc(key_t key) noexcept
    {
        assert(key < size_book::count());
        return _hashmap[key].pop();
    }

    inline void free(memory_unit *unit) noexcept
    {
        _hashmap[unit->_header._key].push(unit);
    }
};

class heap_large
{
    struct large_slab;
    struct large_unit
    {
        large_unit *_right;
        large_slab *_owner;         // nullptr indicates free
        memory_unit::header _unit;
    };

    struct large_slab : slab_base<large_unit, 1024 * 1024 * 2>
    {
        large_slab*  _next{};
        atomic<size_t> _free_size;
        atomic_flag  _busy;

        inline large_slab() noexcept
        {
            _first = adjust_pointer<unit_t*>(this, sizeof(*this));
            _first->_owner = nullptr;
            _first->_right = _last;

            _free_size = pointer_diff(_last, _first);
            _busy.clear();
        }

        inline unit_t*  alloc(size_t size) noexcept
        {
            assert(adjust_size(size) == size);

            if (size > _free_size || _busy.test_and_set()) return nullptr;

            unit_t *chunk{};
            for (auto cur = _first; cur < _last; cur = cur->_right)
            {
                // the unit is not free
                if (cur->_owner) continue;

                // merge free units
                for (auto right = cur->_right; right < _last && !right->_owner; right = right->_right)
                {
                    cur->_right = right->_right;
                }
                assert(cur->_right > _first && cur->_right <= _last);

                auto free_size = pointer_diff(cur->_right, cur);
                if (size > free_size) continue;

                // if the remaining size is equal or greater 128 bytes, split it
                if (free_size - size >= 128)
                {
                    auto split = adjust_pointer<unit_t*>(cur, size);
                    split->_owner = nullptr;
                    split->_right = cur->_right;
                    cur->_right = split;
                }

                chunk = cur;
                chunk->_owner = this;

                _free_size.fetch_sub(pointer_diff(chunk->_right, chunk));
                break;
            }

            _busy.clear();

            return chunk;
        }

        inline void free(unit_t* chunk) noexcept
        {
            _free_size.fetch_add(pointer_diff(chunk->_right, chunk));
            assert(_free_size <= pointer_diff(_last, _first));
            chunk->_owner = nullptr;
        }
    };

    slabs<large_slab, large_unit> _slabs;

public:
    inline memory_unit* alloc(size_t size) noexcept
    {
        auto adjusted_size = adjust_size(size + sizeof(large_unit));
        large_unit* chunk = _slabs.alloc(adjusted_size);
        if (chunk)
        {
            return reinterpret_cast<memory_unit*>(&chunk->_unit);
        }

        return nullptr;
    }

    inline void free(memory_unit* unit) noexcept
    {
        auto chunk = adjust_pointer<large_unit*>(unit, sizeof(large_unit::_unit)) - 1;
        chunk->_owner->free(chunk);
    }
};

class heap
{
    struct slab : slab_base<memory_unit, 1024 * 1024>
    {
        slab* _next{};
        atomic<unit_t*> _current;

        inline slab() noexcept
        {
            _current = _first = adjust_pointer<unit_t*>(this, sizeof(*this));
        }

        inline unit_t* alloc(size_t size) noexcept
        {
            assert(adjust_size(size) == size);

            unit_t *ptr = _current;
            unit_t *next;
            do
            {
                next = adjust_pointer<unit_t*>(ptr, size);
                if (next >= _last) return nullptr;
            }
            while (!_current.compare_exchange_weak(ptr, next));

            return ptr;
        }
    };

    struct shared_cache : 
#if defined(__GNUC__) && defined(__x86_64__) 
        // gcc hasn't implemented atomic_compare_exchange_16 for x86-64 yet, use spin lock version instead
        heap_small<stack_sl<memory_unit*>>
#else
        heap_small<atomic_stack_v<memory_unit*>>
#endif
    {
        inline void merge(key_t key, memory_unit* head) noexcept
        {
            if (!head) return;
            auto tail = head;
            while (tail->_next) tail = tail->_next;
            _hashmap[key].push(head, tail);
        }
    };
    static shared_cache _shared_cache;

    struct thread_cache : heap_small<stack<memory_unit*>>
    {
        ~thread_cache() noexcept
        {
            for (key_t key = 0; key < size_book::count(); ++key)
            {
                _shared_cache.merge(key, _hashmap[key].top());
            }
        }
    };
    static thread_local thread_cache _thread_cache;

    enum : uint16_t { _unit_signature = 0x6871 };
    size_book _book;
    slabs<slab, memory_unit> _slabs;
    heap_large _large;

public:
    inline void* alloc(size_t size) noexcept
    {
        auto key = _book.key(size + sizeof(memory_unit::header));
        memory_unit* unit{};
        if (key <= _book.key_max_small())
        {
            unit = _thread_cache.alloc(key);
            if (unit)
            {
                unit->_header._idle = false;
                unit->_header._size = static_cast<uint32_t>(size);
                assert(validate(unit));
                return &unit->_next;
            }
        }

        if (key <= _book.key_max_medium())
        {
            unit = _shared_cache.alloc(key);
            if (unit)
            {
                unit->_header._idle = false;
                unit->_header._size = static_cast<uint32_t>(size);
                assert(validate(unit));
                return &unit->_next;
            }

            unit = _slabs.alloc(_book.value(key));
        }
        else if (key <= _book.key_max_large())
        {
            unit = _large.alloc(size);
        }
        else
        {
            size_t adjusted_size = adjust_size(size + sizeof(memory_unit::header));
            assert(adjusted_size >= size);
            unit = reinterpret_cast<memory_unit*>(::malloc(adjusted_size));
        }

        assert(unit);
        if (unit)
        {
            unit->_header._size = static_cast<uint32_t>(size);
            unit->_header._signature = _unit_signature;
            unit->_header._key = key;
            unit->_header._idle = false;
            assert(validate(unit));
            return &unit->_next;
        }

        return nullptr;
    }

    inline void free(void* ptr) noexcept
    {
        if (!ptr) return;

        auto unit = reinterpret_cast<memory_unit*>(reinterpret_cast<size_t>(ptr) - sizeof(memory_unit::header));
        if (!validate(unit)) return;

        if (unit->_header._idle) return;
        unit->_header._idle = true;

        auto key = unit->_header._key;
        if (key <= _book.key_max_small())
        {
            _thread_cache.free(unit);
        }
        else if (key <= _book.key_max_medium())
        {
            _shared_cache.free(unit);
        }
        else if (key <= _book.key_max_large())
        {
            _large.free(unit);
        }
        else
        {
            ::free(unit);
        }
    }

    inline void* realloc(void *ptr, size_t size) noexcept
    {
        if (!ptr) return alloc(size);

        auto unit = reinterpret_cast<memory_unit*>(reinterpret_cast<size_t>(ptr) - sizeof(memory_unit::header));
        if (!validate(unit)) return nullptr;

        auto key = _book.key(size + sizeof(memory_unit::header));
        if (key == unit->_header._key)
        {
            unit->_header._size = static_cast<uint32_t>(size);
            return ptr;
        }

        void *new_ptr = alloc(size);
        if (new_ptr)
        {
            memcpy(new_ptr, ptr, min(static_cast<size_t>(unit->_header._size), size));
            free(ptr);
        }

        return new_ptr;
    }

    inline bool validate(const memory_unit* unit) noexcept
    {
        if (unit->_header._signature != _unit_signature) return false;
        assert(unit->_header._key == _book.key(unit->_header._size + sizeof(unit->_header)));
        return true;
    }
};

heap::shared_cache heap::_shared_cache{};
thread_local heap::thread_cache heap::_thread_cache{};
}; // end of namespace teisye

teisye::heap _heap;

extern "C" void* tsalloc(size_t size)
{
    return _heap.alloc(size);
}

extern "C" void tsfree(void* ptr)
{
    _heap.free(ptr);
}

extern "C" void* tsrealloc(void* ptr, size_t size)
{
    return _heap.realloc(ptr, size);
}

extern "C" bool tsvalidate(const void* ptr)
{
    using namespace teisye;
    if (!ptr) return false;
    auto unit = reinterpret_cast<memory_unit*>(reinterpret_cast<size_t>(ptr) - sizeof(memory_unit::header));
    return _heap.validate(unit);
}

extern "C" size_t tssize(const void* ptr)
{
    using namespace teisye;
    if (!ptr) return static_cast<size_t>(-1);
    auto unit = reinterpret_cast<memory_unit*>(reinterpret_cast<size_t>(ptr) - sizeof(memory_unit::header));
    if (!_heap.validate(unit)) return static_cast<size_t>(-1);
    return unit->_header._size;
}
