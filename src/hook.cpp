/* Copyright (C) 2010 Daiqian Huang <daiqian.huang@outlook.com>
*
* teisye is free software; you can redistribute it and/or modify it
* under the terms of the MIT License.
*/
 
/**
 * @file hook.cpp
 *
 * Hook win32 Heap APIs.
 */
#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT    _WIN32_WINNT_WINXP
#endif

#define WIN32_LEAN_AND_MEAN     // Exclude rarely-used stuff from Windows headers
#define NOMINMAX                // Exclude macros min and max

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstdint>
#include <cassert>
#include <algorithm>
#include <atomic>
#include <limits>
#include "teisye.h"

extern "C" bool tsvalidate(const void* ptr);
extern "C" size_t tssize(const void* ptr); 

namespace hook
{
    using namespace std;

#if defined(_DEBUG) || !defined(NDEBUG)
    inline void debug_printf(const char* format, ...) noexcept
    {
        va_list ap;
        va_start(ap, format);

#if defined(_WIN32)
        char msg[512];
        msg[0] = 0;
        _vsnprintf_s(msg, _countof(msg), format, ap);
        OutputDebugStringA(msg);
#else
        vprintf(format, ap);
#endif
        va_end(ap);
    }
#else
    inline void debug_printf(const char*, ...) noexcept
    {
    }
#endif

    template<typename T>
    inline T pointer_cast(void* ptr, size_t delta = 0) noexcept
    {
        return reinterpret_cast<T>(reinterpret_cast<char*>(ptr) + delta);
    }

    template<typename T>
    inline void get_proc(HMODULE m, const char* name, T& proc) noexcept
    {
        void* address = GetProcAddress(m, name);
        if (address) proc = reinterpret_cast<T>(address);
    }

    typedef LPVOID  (WINAPI *HeapAlloc_t)(HANDLE win32_heap, DWORD flags, SIZE_T size);
    typedef BOOL    (WINAPI *HeapFree_t)(HANDLE win32_heap, DWORD flags, void* ptr);
    typedef LPVOID  (WINAPI *HeapReAlloc_t)(HANDLE win32_heap, DWORD flags, void* ptr, SIZE_T size);
    typedef SIZE_T  (WINAPI *HeapSize_t)(HANDLE win32_heap, DWORD flags, const void* ptr);
    typedef BOOL    (WINAPI *HeapValidate_t)(HANDLE win32_heap, DWORD flags, const void* ptr);

    typedef HMODULE (WINAPI *LoadLibraryExW_t)(LPCWSTR libname, HANDLE file, DWORD flags);
    typedef HMODULE (WINAPI *LoadLibraryExA_t)(LPCSTR libname, HANDLE file, DWORD flags);

    typedef BOOL    (WINAPI *EnumProcessModules_t)(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded);

    struct origin_proc
    {
        HeapAlloc_t      _HeapAlloc;
        HeapFree_t       _HeapFree;
        HeapReAlloc_t    _HeapReAlloc;
        HeapSize_t       _HeapSize;
        HeapValidate_t   _HeapValidate;
        LoadLibraryExW_t _LoadLibraryExW;
        LoadLibraryExA_t _LoadLibraryExA;
        EnumProcessModules_t _EnumProcessModules;
    } _origin;
        
    constexpr int _max_modules{ 512 };
    HMODULE _patched_modules[_max_modules]{};
    int _patched_modules_count{};

    class statistic
    {
        atomic<uint64_t> _num_of_allocations{};
        atomic<uint64_t> _num_of_deallocations{};
    public:
        inline void alloc() noexcept
        {
#if defined(_DEBUG) && !defined(NDEBUG)
            ++_num_of_allocations;
#endif
        }

        inline void free() noexcept
        {
#if defined(_DEBUG) && !defined(NDEBUG)
            ++_num_of_deallocations;
#endif
        }
    } _statistic;

    void* WINAPI HeapAlloc(HANDLE win32_heap, DWORD flags, size_t size) noexcept
    {
        if (flags & (~(HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY | HEAP_CREATE_ENABLE_EXECUTE)))
        {
            // there are some special flags, let the default to do the job
            return _origin._HeapAlloc(win32_heap, flags, size);
        } 

        void *ptr = tsalloc(size);
        if (ptr && (flags & HEAP_ZERO_MEMORY))
        {
            memset(ptr, 0, size);
        }

        _statistic.alloc();
        return ptr;
    }

    BOOL WINAPI HeapFree(HANDLE win32_heap, DWORD flags, void* ptr) noexcept
    {
        if (!tsvalidate(ptr)) return _origin._HeapFree(win32_heap, flags, ptr);

        tsfree(ptr);
        _statistic.free();
        return true;
    }

    void* WINAPI HeapReAlloc(HANDLE win32_heap, DWORD flags, void* ptr, size_t size) noexcept
    {
        if (!tsvalidate(ptr)) return _origin._HeapReAlloc(win32_heap, flags, ptr, size);

        // unsupported flags are specified, e.g:HEAP_REALLOC_IN_PLACE_ONLY, let the caller to deal with it
        if (flags & (~(HEAP_ZERO_MEMORY | HEAP_NO_SERIALIZE | HEAP_CREATE_ENABLE_EXECUTE))) return nullptr;

        size_t old_size = tssize(ptr);
        void *new_ptr = tsalloc(size);
        if (new_ptr)
        {
            if (flags & HEAP_ZERO_MEMORY)
            {
                memset(new_ptr, 0, size);
            }

            memcpy(new_ptr, ptr, std::min(old_size, size));
            tsfree(ptr);

            _statistic.alloc();
            _statistic.free();
        }

        return new_ptr;
    }

    size_t WINAPI HeapSize(HANDLE win32_heap, DWORD flags, const void* ptr) noexcept
    {
        return tsvalidate(ptr) ? tssize(ptr) : _origin._HeapSize(win32_heap, flags, ptr);
    }

    BOOL WINAPI HeapValidate(HANDLE win32_heap, DWORD flags, const void* ptr) noexcept
    {
        return tsvalidate(ptr) ? true : _origin._HeapValidate(win32_heap, flags, ptr);
    }

    void patch_all_modules() noexcept;

    HMODULE WINAPI LoadLibraryExW(LPCWSTR libname, HANDLE file, DWORD flags) noexcept
    {
        HMODULE m = _origin._LoadLibraryExW(libname, file, flags);
        patch_all_modules();
        return m;
    }

    HMODULE WINAPI LoadLibraryExA(LPCSTR libname, HANDLE file, DWORD flags) noexcept
    {
        HMODULE m = _origin._LoadLibraryExA(libname, file, flags);
        patch_all_modules();
        return m;
    }

    const void* find_hook_proc(const char* proc_name) noexcept
    {
        static const struct item
        {
            const char* _proc_name;
            const void* _hook_proc;
        }
        lookup_table[] =
        {
            // must be sorted by _proc_name
            { "HeapAlloc",          HeapAlloc },
            { "HeapFree",           HeapFree },
            { "HeapReAlloc",        HeapReAlloc },
            { "HeapSize",           HeapSize },
            { "HeapValidate",       HeapValidate },

            { "LoadLibraryExA",     LoadLibraryExA },
            { "LoadLibraryExW",     LoadLibraryExW },

            { "RtlAllocateHeap",    HeapAlloc },
            { "RtlFreeHeap",        HeapFree },
            { "RtlReAllocateHeap",  HeapReAlloc },
            { "RtlSizeHeap",        HeapSize },
            { "RtlValidateHeap",    HeapValidate },
        };

        item key{ proc_name };
        auto it = std::bsearch(&key, lookup_table, _countof(lookup_table), sizeof(lookup_table[0]),
            [](const void *a, const void* b) { return strcmp(reinterpret_cast<const item*>(a)->_proc_name, reinterpret_cast<const item*>(b)->_proc_name); });

        return (it) ? reinterpret_cast<item*>(it)->_hook_proc : nullptr;
    }

    void patch_module_iat(HMODULE module, bool hook_RtlAllocateHeap) noexcept
    {
        if (!module) return;

        auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
        auto nt_header = pointer_cast<PIMAGE_NT_HEADERS>(dos_header, dos_header->e_lfanew);
        if (IMAGE_NT_SIGNATURE != nt_header->Signature ||
            !nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        {
            return;
        }

        auto descriptor = pointer_cast<PIMAGE_IMPORT_DESCRIPTOR>(dos_header, nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; descriptor->Characteristics != 0; ++descriptor)
        {
            if (!descriptor->FirstThunk || !descriptor->OriginalFirstThunk) continue;

            auto module_name = pointer_cast<PCSTR>(dos_header, descriptor->Name);

            static const char *filter[] = { "ntdll.dll", "kernel32.dll", "api-ms-win-core-heap", "api-ms-win-core-libraryloader" };
            auto it = std::find_if(std::begin(filter), std::end(filter),
                                    [module_name](const auto& it) { return _strnicmp(module_name, it, strlen(it)) == 0; });
            if (it == std::end(filter)) continue;

            auto thunk = pointer_cast<PIMAGE_THUNK_DATA>(dos_header, descriptor->FirstThunk);
            auto origThunk = pointer_cast<PIMAGE_THUNK_DATA>(dos_header, descriptor->OriginalFirstThunk);

            for (; origThunk->u1.Function != NULL; origThunk++, thunk++)
            {
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)  continue;

                auto proc = pointer_cast<PIMAGE_IMPORT_BY_NAME>(dos_header, origThunk->u1.AddressOfData);
                auto proc_name = reinterpret_cast<PSTR>(proc->Name);
                if (!hook_RtlAllocateHeap && (_stricmp(proc_name, "RtlAllocateHeap") == 0)) continue;
                auto hook_proc = find_hook_proc(proc_name);
                if (!hook_proc)  continue;

                // already patched
                if (thunk->u1.Function == reinterpret_cast<DWORD_PTR>(hook_proc)) return;

                debug_printf("  [%s!%s] %p -> %p\n", module_name, proc_name, thunk->u1.Function, hook_proc);

                // Make page writable.
                MEMORY_BASIC_INFORMATION mbi;
                VirtualQuery(thunk, &mbi, sizeof(mbi));
                if (!(mbi.Protect & PAGE_EXECUTE_READWRITE))
                {
                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
                }

                thunk->u1.Function = reinterpret_cast<DWORD_PTR>(hook_proc);
            }
        }

#if defined(_DEBUG) || !defined(NDEBUG)
        char module_filename[256]{};
        if (GetModuleFileNameA(module, module_filename, _countof(module_filename)))
        {
            debug_printf("patched '%s'\n", module_filename);
        }
#endif
    }

    void patch_all_modules() noexcept
    {
        static atomic_flag patching{};  // prevent from patching in multi-threads

        if (patching.test_and_set()) return;

        HMODULE loaded_modules[_max_modules];
        DWORD cb = 0;
        if (_origin._EnumProcessModules(GetCurrentProcess(), loaded_modules, sizeof(loaded_modules), &cb))
        {
            int loaded_count = static_cast<int>(std::min(static_cast<size_t>(cb), sizeof(loaded_modules)) / sizeof(loaded_modules[0]));

            // remove unloaded modules from _patched_modules, and remove patched module from loaded_modules
            int unloaded_count = 0;
            for (int i = 0; i < _patched_modules_count; ++i)
            {
                bool unloaded{ true };
                for (int j = 0; j < loaded_count; ++j)
                {
                    if (loaded_modules[j] == _patched_modules[i])
                    {
                        // already patched
                        loaded_modules[j] = nullptr;
                        unloaded = false;
                    }
                }

                if (unloaded)
                {
                    _patched_modules[i] = nullptr;
                    unloaded_count++;
                }
            }

            if (unloaded_count)
            {
                // pack _patched_modules
                for (int i = 0, j = 1; j < _patched_modules_count; )
                {
                    if (_patched_modules[i])
                    {
                        ++i;
                        j = i + 1;
                    }
                    else if (!_patched_modules[j])
                    {
                        ++j;
                    }
                    else
                    {
                        _patched_modules[i++] = _patched_modules[j];
                        _patched_modules[j++] = nullptr;
                    }
                    assert(i < j);
                }
                _patched_modules_count -= unloaded_count;
            }

            for (int i = 0; i < loaded_count; ++i)
            {
                auto m = loaded_modules[i];
                if (m)
                {
                    patch_module_iat(m, true);

                    if (_patched_modules_count - 1 < _countof(_patched_modules))
                    {
                        _patched_modules[_patched_modules_count++] = m;
                    }
                }
            }
        }

        patching.clear();
    }

    // apply HEAP_CREATE_ENABLE_EXECUTE to the process heap, so apps like devenv.exe may execute code from memory allocated.
    bool process_heap_executable() noexcept
    {
        // partially copied from http://www.nirsoft.net/kernel_struct/vista/HEAP.html, with a little modifition. 
        // the layout of Flags member is same as ntdll!_HEAP on Windows 8.1
        struct PARTIAL_WIN32_HEAP
        {
            void* Entry[2];
            ULONG SegmentSignature;
            ULONG SegmentFlags;
            LIST_ENTRY SegmentListEntry;
            PARTIAL_WIN32_HEAP* Heap;
            PVOID BaseAddress;
            ULONG NumberOfPages;
            void* FirstEntry;
            void* LastValidEntry;
            ULONG NumberOfUnCommittedPages;
            ULONG NumberOfUnCommittedRanges;
            WORD SegmentAllocatorBackTraceIndex;
            WORD Reserved;
            LIST_ENTRY UCRSegmentList;
            ULONG Flags;
        };
        
        HANDLE process_heap = GetProcessHeap();
        if (!HeapLock(process_heap)) return false;

        auto heap = reinterpret_cast<PARTIAL_WIN32_HEAP*>(process_heap);
        heap->Flags |= HEAP_CREATE_ENABLE_EXECUTE;

        // change existing regions with PAGE_EXECUTE_READWRITE protection
        PROCESS_HEAP_ENTRY entry{};
        while (HeapWalk(process_heap, &entry))
        {
            if (entry.wFlags & PROCESS_HEAP_REGION)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                VirtualQuery(entry.lpData, &mbi, sizeof(mbi));
                VirtualProtect(entry.lpData, entry.cbData, PAGE_EXECUTE_READWRITE, &mbi.Protect);
            }
        }

        HeapUnlock(process_heap);
        return true;
    }

    bool start() noexcept
    {
        // already started
        if (_origin._EnumProcessModules) return true;

        if (!process_heap_executable()) return false;

        HMODULE psapi = LoadLibraryA("psapi.dll");
        if (!psapi) return false;
        get_proc(psapi, "EnumProcessModules", _origin._EnumProcessModules);

        // Heap APIs
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return false;
        get_proc(ntdll, "RtlAllocateHeap", _origin._HeapAlloc);
        get_proc(ntdll, "RtlFreeHeap", _origin._HeapFree);
        get_proc(ntdll, "RtlReAllocateHeap", _origin._HeapReAlloc);
        get_proc(ntdll, "RtlSizeHeap", _origin._HeapSize);
        get_proc(ntdll, "RtlValidateHeap", _origin._HeapValidate);

        // Locate LoadLibrary APIs of kernel32.dll
        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        if (!kernel32) return false;
        get_proc(kernel32, "LoadLibraryExW", _origin._LoadLibraryExW);
        get_proc(kernel32, "LoadLibraryExA", _origin._LoadLibraryExA);

        // Locate LoadLibrary APIs of kernelbase.dll if kernelbase.dll is loaded
        HMODULE kernelbase = GetModuleHandleA("kernelbase.dll");
        if (kernelbase)
        {
            get_proc(kernelbase, "LoadLibraryExW", _origin._LoadLibraryExW);
            get_proc(kernelbase, "LoadLibraryExA", _origin._LoadLibraryExA);
        }

        // if any procedure address is nullptr, return false
        const void** begin = reinterpret_cast<const void**>(&_origin);
        const void** end = begin + sizeof(_origin) / sizeof(_origin._HeapAlloc);
        for (auto it = begin; it != end; ++it)
        {
            if (!*it) return false;
        }
        
        // mark teisye.dll, ntdll.dll kernelbase.dll and kernel32.dll as already patched.
        HMODULE teisye = GetModuleHandleA("teisye.dll");
        if (!teisye) return false;
        _patched_modules[_patched_modules_count++] = teisye;
        _patched_modules[_patched_modules_count++] = ntdll;
        _patched_modules[_patched_modules_count++] = kernelbase;
        _patched_modules[_patched_modules_count++] = kernel32;

        // Patch kernelbase.dll and kernel32.dll without hooking RtlAllocateHeap
        patch_module_iat(kernelbase, false);
        patch_module_iat(kernel32, false);

        patch_all_modules();

        return true;
    }
} // namespace hook

extern "C" void tshook()
{
    hook::start();
}
