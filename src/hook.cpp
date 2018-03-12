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

    typedef LPVOID  (WINAPI *HeapAlloc_t)(HANDLE win32_heap, DWORD flags, SIZE_T size);
    typedef BOOL    (WINAPI *HeapFree_t)(HANDLE win32_heap, DWORD flags, void* ptr);
    typedef LPVOID  (WINAPI *HeapReAlloc_t)(HANDLE win32_heap, DWORD flags, void* ptr, SIZE_T size);
    typedef SIZE_T  (WINAPI *HeapSize_t)(HANDLE win32_heap, DWORD flags, const void* ptr);
    typedef BOOL    (WINAPI *HeapValidate_t)(HANDLE win32_heap, DWORD flags, const void* ptr);

    typedef HMODULE(WINAPI *LoadLibraryExW_t)(LPCWSTR libname, HANDLE file, DWORD flags);
    typedef HMODULE(WINAPI *LoadLibraryExA_t)(LPCSTR libname, HANDLE file, DWORD flags);

    typedef BOOL(WINAPI *EnumProcessModules_t)(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded);

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

    atomic<uint64_t> _num_of_allocations{};
    atomic<uint64_t> _num_of_deallocations{};

    void* WINAPI HeapAlloc(HANDLE win32_heap, DWORD flags, size_t size) noexcept
    {
        if (flags & (~(HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY | HEAP_CREATE_ENABLE_EXECUTE)))
        {
            // there are some special flags, let the default to do the job
            return _origin._HeapAlloc(win32_heap, flags, size);
        } 

        void *ptr = tsalloc(size);
        if (ptr)
        {
            if (flags & HEAP_ZERO_MEMORY)
            {
                memset(ptr, 0, size);
            }

            // assume heap was created with HEAP_CREATE_ENABLE_EXECUTE
            MEMORY_BASIC_INFORMATION mbi;
            VirtualQuery(ptr, &mbi, sizeof(mbi));
            if (!(mbi.Protect & PAGE_EXECUTE_READWRITE))
            {
                VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
            }

            _num_of_allocations.fetch_add(1);
        }

        return ptr;
    }

    BOOL WINAPI HeapFree(HANDLE win32_heap, DWORD flags, void* ptr) noexcept
    {
        if (!tsvalidate(ptr)) return _origin._HeapFree(win32_heap, flags, ptr);

        tsfree(ptr);
        _num_of_deallocations.fetch_add(1);
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

            // assume heap was created with HEAP_CREATE_ENABLE_EXECUTE
            MEMORY_BASIC_INFORMATION mbi;
            VirtualQuery(new_ptr, &mbi, sizeof(mbi));
            if (!(mbi.Protect & PAGE_EXECUTE_READWRITE))
            {
                VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
            }

            memcpy(new_ptr, ptr, std::min(old_size, size));
            tsfree(ptr);

           _num_of_allocations.fetch_add(1);
           _num_of_deallocations.fetch_add(1);
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
        static const struct
        {
            const char* _proc_name;
            const void* _hook_proc;
        }
        lookup_table[] =
        {
            { "HeapAlloc",          HeapAlloc },
            { "HeapFree",           HeapFree },
            { "HeapReAlloc",        HeapReAlloc },
            { "HeapSize",           HeapSize },
            { "HeapValidate",       HeapValidate },

            { "RtlAllocateHeap",    HeapAlloc },
            { "RtlFreeHeap",        HeapFree },
            { "RtlReAllocateHeap",  HeapReAlloc },
            { "RtlSizeHeap",        HeapSize },
            { "RtlValidateHeap",    HeapValidate },
            
            { "LoadLibraryExW",     LoadLibraryExW },
            { "LoadLibraryExA",     LoadLibraryExA },
        };

        for (const auto &it : lookup_table)
        {
            if (_stricmp(proc_name, it._proc_name) == 0) return it._hook_proc;
        }

        return nullptr;
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

    bool start() noexcept
    {
        HMODULE m = GetModuleHandleA("teisye.dll");
        if (!m) return false;
        // do not patch teisye.dll
        _patched_modules[_patched_modules_count++] = m;
        
        m = LoadLibraryA("psapi.dll");
        if (!m) return false;
        _origin._EnumProcessModules = reinterpret_cast<EnumProcessModules_t>(::GetProcAddress(m, "EnumProcessModules"));

        // Heap APIs
        m = GetModuleHandleA("ntdll.dll");
        if (!m) return false;
        _origin._HeapAlloc = reinterpret_cast<HeapAlloc_t>(GetProcAddress(m, "RtlAllocateHeap"));
        _origin._HeapFree = reinterpret_cast<HeapFree_t>(GetProcAddress(m, "RtlFreeHeap"));
        _origin._HeapReAlloc = reinterpret_cast<HeapReAlloc_t>(GetProcAddress(m, "RtlReAllocateHeap"));
        _origin._HeapSize = reinterpret_cast<HeapSize_t>(GetProcAddress(m, "RtlSizeHeap"));
        _origin._HeapValidate = reinterpret_cast<HeapValidate_t>(GetProcAddress(m, "RtlValidateHeap"));
        // do not patch ntdll.dll
        _patched_modules[_patched_modules_count++] = m;

        // Locate LoadLibrary APIs of kernel32.dll
        m = GetModuleHandleA("kernel32.dll");
        if (!m) return false;
        _origin._LoadLibraryExW = reinterpret_cast<LoadLibraryExW_t>(GetProcAddress(m, "LoadLibraryExW"));
        _origin._LoadLibraryExA = reinterpret_cast<LoadLibraryExA_t>(GetProcAddress(m, "LoadLibraryExA"));

        // Patch kernel32.dll without hooking RtlAllocateHeap
         patch_module_iat(m, false);
        _patched_modules[_patched_modules_count++] = m;

        // Locate LoadLibrary APIs of kernelbase.dll if kernelbase.dll is loaded
        m = GetModuleHandleA("kernelbase.dll");
        if (m)
        {
            _origin._LoadLibraryExW = reinterpret_cast<LoadLibraryExW_t>(GetProcAddress(m, "LoadLibraryExW"));
            _origin._LoadLibraryExA = reinterpret_cast<LoadLibraryExA_t>(GetProcAddress(m, "LoadLibraryExA"));

            // Patch kernelbase.dll without hooking RtlAllocateHeap
            patch_module_iat(m, false);
            _patched_modules[_patched_modules_count++] = m;
        }

        // if any procedure address is nullptr, return false
        const void** begin = reinterpret_cast<const void**>(&_origin);
        const void** end = begin + sizeof(_origin) / sizeof(_origin._HeapAlloc);
        for (auto it = begin; it != end; ++it)
        {
            if (!*it) return false;
        }
        
        patch_all_modules();

        return true;
    }
} // namespace hook

extern "C" void tshook()
{
    hook::start();
}
