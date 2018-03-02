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
#include "teisye.h"

extern "C" bool tsvalidate(const void* ptr);
extern "C" size_t tssize(const void* ptr); 

namespace hook
{
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

    typedef LPVOID  (WINAPI *HeapAlloc_t)(HANDLE win32Heap, DWORD flags, SIZE_T size);
    typedef BOOL    (WINAPI *HeapFree_t)(HANDLE win32Heap, DWORD flags, void* ptr);
    typedef LPVOID  (WINAPI *HeapReAlloc_t)(HANDLE win32Heap, DWORD flags, void* ptr, SIZE_T size);
    typedef SIZE_T  (WINAPI *HeapSize_t)(HANDLE win32Heap, DWORD flags, const void* ptr);
    typedef BOOL    (WINAPI *HeapValidate_t)(HANDLE win32Heap, DWORD flags, const void* ptr);

    typedef HMODULE(WINAPI *LoadLibraryExW_t)(LPCWSTR libname, HANDLE file, DWORD flags);
    typedef HMODULE(WINAPI *LoadLibraryExA_t)(LPCSTR libname, HANDLE file, DWORD flags);

    struct origin_proc
    {
        HeapAlloc_t      _HeapAlloc;
        HeapFree_t       _HeapFree;
        HeapReAlloc_t    _HeapReAlloc;
        HeapSize_t       _HeapSize;
        HeapValidate_t   _HeapValidate;
        LoadLibraryExW_t _LoadLibraryExW;
        LoadLibraryExA_t _LoadLibraryExA;
    } _origin;


    void* WINAPI HeapAlloc(HANDLE, DWORD flags, size_t size) noexcept
    {
        void *ptr = tsalloc(size);
        if (ptr && (flags & HEAP_ZERO_MEMORY))
        {
            memset(ptr, 0, size);
        }
        return ptr;
    }

    BOOL WINAPI HeapFree(HANDLE win32Heap, DWORD flags, void* ptr) noexcept
    {
        if (!tsvalidate(ptr)) return _origin._HeapFree(win32Heap, flags, ptr);
        tsfree(ptr);
        return true;
    }

    void* WINAPI HeapReAlloc(HANDLE win32Heap, DWORD flags, void* ptr, size_t size) noexcept
    {
        if (!tsvalidate(ptr)) return _origin._HeapReAlloc(win32Heap, flags, ptr, size);

        void *new_ptr = tsrealloc(ptr, size);
        if (new_ptr && (flags & HEAP_ZERO_MEMORY))
        {
            memset(new_ptr, 0, size);
        }
        return new_ptr;
    }

    size_t WINAPI HeapSize(HANDLE win32Heap, DWORD flags, const void* ptr) noexcept
    {
        if (!tsvalidate(ptr)) return _origin._HeapSize(win32Heap, flags, ptr);

        return tssize(ptr);
    }

    BOOL WINAPI HeapValidate(HANDLE win32Heap, DWORD flags, const void* ptr) noexcept
    {
        if (!tsvalidate(ptr)) return _origin._HeapValidate(win32Heap, flags, ptr);

        return true;
    }

    void patch_all_modules();

    HMODULE WINAPI LoadLibraryExW(LPCWSTR libname, HANDLE file, DWORD flags)
    {
        HMODULE m = _origin._LoadLibraryExW(libname, file, flags);
        patch_all_modules();
        return m;
    }

    HMODULE WINAPI LoadLibraryExA(LPCSTR libname, HANDLE file, DWORD flags)
    {
        HMODULE m = _origin._LoadLibraryExA(libname, file, flags);
        patch_all_modules();
        return m;
    }

    struct specification
    {
        const char* _proc_name;
        const void* _hook_proc;
    };

    inline const specification* find_specification(const char* proc_name) noexcept
    {
        static const specification heap_specifications[] =
        {
            { "HeapAlloc",    HeapAlloc },
            { "HeapFree",     HeapFree },
            { "HeapReAlloc",  HeapReAlloc },
            { "HeapSize",     HeapSize },
            { "HeapValidate", HeapValidate },

            //{ "RtlAllocateHeap",    HeapAlloc },
            { "RtlFreeHeap",        HeapFree },
            { "RtlReAllocateHeap",  HeapReAlloc },
            { "RtlSizeHeap",        HeapSize },
            { "RtlValidateHeap",    HeapValidate },
            
            { "LoadLibraryExW", LoadLibraryExW },
            { "LoadLibraryExA", LoadLibraryExA },
        };
        auto it = std::find_if(std::begin(heap_specifications), std::end(heap_specifications),
            [proc_name](const specification& it) { return _stricmp(proc_name, it._proc_name) == 0; });

        return it != std::end(heap_specifications) ? it : nullptr;
    }

    void patch_module_iat(HMODULE module)
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

            static const char *modules_to_hook[] = { "ntdll.dll", "kernel32.dll", "api-ms-win-core-heap", "api-ms-win-core-libraryloader" };
            auto it = std::find_if(std::begin(modules_to_hook), std::end(modules_to_hook),
                                    [module_name](const auto& it) { return _strnicmp(module_name, it, strlen(it)) == 0; });
            if (it == std::end(modules_to_hook))
            {
                continue;
            }

            auto thunk = pointer_cast<PIMAGE_THUNK_DATA>(dos_header, descriptor->FirstThunk);
            auto origThunk = pointer_cast<PIMAGE_THUNK_DATA>(dos_header, descriptor->OriginalFirstThunk);

            for (; origThunk->u1.Function != NULL; origThunk++, thunk++)
            {
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)  continue;

                auto proc = pointer_cast<PIMAGE_IMPORT_BY_NAME>(dos_header, origThunk->u1.AddressOfData);
                auto proc_name = reinterpret_cast<PSTR>(proc->Name);
                auto specification = find_specification(proc_name);
                if (!specification)  continue;

                if (thunk->u1.Function == reinterpret_cast<DWORD_PTR>(specification->_hook_proc))
                {
                    // already patched
                    return;
                }

                debug_printf("  [%s!%s] %p -> %p\n", module_name, proc_name, thunk->u1.Function, specification->_hook_proc);

                // Make page writable.
                MEMORY_BASIC_INFORMATION mbi;
                VirtualQuery(thunk, &mbi, sizeof(mbi));
                if (!(mbi.Protect & PAGE_EXECUTE_READWRITE))
                {
                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
                }

                thunk->u1.Function = reinterpret_cast<DWORD_PTR>(specification->_hook_proc);
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

    typedef BOOL(WINAPI *EnumProcessModules_t)(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded);

    HMODULE _psapi{};
    EnumProcessModules_t _EnumProcessModules{};
    std::atomic_flag  _patching{};  // prevent patching in multi-threads
    
    void patch_all_modules()
    {
        if (_patching.test_and_set()) return; 

        static const char* exclude_dlls[]{"teisye.dll", "ntdll.dll", "psapi.dll", "COMCTL32.dll"};
        HMODULE exclude_modules[_countof(exclude_dlls)];

        for (int i = 0; i < _countof(exclude_dlls); ++i)
        {
            exclude_modules[i] = GetModuleHandleA(exclude_dlls[i]);
        }

        HMODULE modules[256];
        DWORD cb = 0;
        if (_EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &cb))
        {
            for (int i = 0; i < static_cast<int>(cb / sizeof(modules[0])); ++i)
            {
                auto m = modules[i];
				auto it = std::find_if(std::begin(exclude_modules), std::end(exclude_modules),
										[m](const auto& it) { return it == m; });
				if (it == std::end(exclude_modules))
				{
                    patch_module_iat(m);
                }
            }
        }

        _patching.clear();
    }

    bool start() noexcept
    {
        _psapi = LoadLibraryA("psapi.dll");
        if (!_psapi)
        {
            assert(!"failed to load psapi.dll");
            return false;
        }

        _EnumProcessModules = reinterpret_cast<EnumProcessModules_t>(::GetProcAddress(_psapi, "EnumProcessModules"));
        if (!_EnumProcessModules)
        {
            assert(!"failed to get the address of EnumProcessModules");
            return false;
        }
        
         // Heap APIs
        HMODULE m = GetModuleHandleA("ntdll.dll");
        if (!m) return false;
        _origin._HeapAlloc = reinterpret_cast<HeapAlloc_t>(GetProcAddress(m, "RtlAllocateHeap"));
        _origin._HeapFree = reinterpret_cast<HeapFree_t>(GetProcAddress(m, "RtlFreeHeap"));
        _origin._HeapReAlloc = reinterpret_cast<HeapReAlloc_t>(GetProcAddress(m, "RtlReAllocateHeap"));
        _origin._HeapSize = reinterpret_cast<HeapSize_t>(GetProcAddress(m, "RtlSizeHeap"));
        _origin._HeapValidate = reinterpret_cast<HeapValidate_t>(GetProcAddress(m, "RtlValidateHeap"));

        // LoadLibrary APIs
        m = GetModuleHandleA("kernelbase.dll");
        if (!m) return false;
        _origin._LoadLibraryExW = reinterpret_cast<LoadLibraryExW_t>(GetProcAddress(m, "LoadLibraryExW"));
        _origin._LoadLibraryExA = reinterpret_cast<LoadLibraryExA_t>(GetProcAddress(m, "LoadLibraryExA"));

        // if a procedure address is nullptr, return false
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
