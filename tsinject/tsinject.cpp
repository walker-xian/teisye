/* Copyright (C) 2010 Daiqian Huang <daiqian.huang@outlook.com>
*
* The software is free, you can redistribute it and/or modify it under the terms of the MIT License.
*/
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501     // WinXP or above
#endif

#define WIN32_LEAN_AND_MEAN     // Exclude rarely-used stuff from Windows headers
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <intrin.h>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <strstream>
#include "../src/teisye.h"

TEISYE_NEW_OPERATORS

struct Params;

typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR lpFileName);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL    (WINAPI *tshook_t)();
typedef BOOL    (WINAPI *remoteProc_t)(Params *params);

struct Params
{
    uint8_t           _code[256];
    LoadLibraryA_t    _LoadLibraryA;
    GetProcAddress_t  _GetProcAddress;
    char              _tshook[32];
    char              _teisye_dll[MAX_PATH + 1];
};

BOOL WINAPI remote_proc(Params *params) noexcept
{
    //__debugbreak();

    HMODULE teisye = params->_LoadLibraryA(params->_teisye_dll);
    if (!teisye) return false;

    tshook_t tshook_proc = reinterpret_cast<tshook_t>(params->_GetProcAddress(teisye, params->_tshook));
    if (!tshook_proc) return false;

    tshook_proc();
    
    return true;
}

void WINAPI remote_proc_end() noexcept
{
}

using namespace std;

void inject(DWORD pid)
{
    Params  local_params{ {}, ::LoadLibraryA, ::GetProcAddress, "tshook" };
    const size_t code_size = reinterpret_cast<size_t>(remote_proc_end) - reinterpret_cast<size_t>(remote_proc);
    if (code_size > sizeof(local_params._code))
    {
        ostringstream err;
        err << "code buffer(" << code_size << ") is too small";
        throw runtime_error(err.str());    
    }

    memset(local_params._code, 0x90, sizeof(local_params._code));
    memcpy(local_params._code, remote_proc, code_size);

    HMODULE teisye = GetModuleHandleA("teisye.dll");
    if (!teisye)
    {
        ostringstream err;
        err << "Failed to load teisye.dll, gle = " << GetLastError();
        throw runtime_error(err.str());
    }

    if (!GetModuleFileNameA(teisye, local_params._teisye_dll, _countof(local_params._teisye_dll)))
    {
        ostringstream err;
        err << "Failed to retrieve the fully qualified path for teisye.dll, gle = " << GetLastError();
        throw runtime_error(err.str());
    }

    HANDLE remote_process = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ , FALSE, pid);
    if (!remote_process)
    {
        ostringstream err;
        err << "Failed to open the process " << pid << ", gle = " << GetLastError();
        throw runtime_error(err.str());
    }

    Params *remote_params = reinterpret_cast<Params*>(VirtualAllocEx(remote_process, 0, sizeof(Params), MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	if (!remote_params)
    {
        CloseHandle(remote_process);

        ostringstream err;
        err << "Failed to allocate a memory block in the target process, gle = " << GetLastError();
        throw runtime_error(err.str());
    }

    if (!WriteProcessMemory(remote_process, remote_params, &local_params, sizeof(local_params), NULL))
    {
        VirtualFreeEx(remote_process, remote_params, 0, MEM_RELEASE);
        CloseHandle(remote_process);

        ostringstream err;
        err << "Failed to write date to the memory block in the target process, gle = " << GetLastError();
        throw runtime_error(err.str());
    }

	// Start execution of remoteProc
	HANDLE remote_thread = CreateRemoteThread(remote_process, NULL, 0, (LPTHREAD_START_ROUTINE)remote_params, remote_params, 0 , NULL);
	if (!remote_thread)
    {
        VirtualFreeEx(remote_process, remote_params, 0, MEM_RELEASE);
        CloseHandle(remote_process);

        ostringstream err;
        err << "Failed to create a remote thread, gle = " << GetLastError();
        throw runtime_error(err.str());
    }

	WaitForSingleObject(remote_thread, INFINITE);

    CloseHandle(remote_thread);
	VirtualFreeEx(remote_process, remote_params, 0, MEM_RELEASE);
    CloseHandle(remote_process);
}

long int to_value(const string& str)
{
    char *end{};
    long int value = strtol(str.c_str(), &end, 0);
    if (end && *end == 0) return value;

    ostringstream err;
    err << "parameter '" << str << "' is invalid value";
    throw runtime_error(err.str());
}

int main(int argc, char **argv)
{
    tshook();

    try
    {
        static const char usage[] =
            "Inject teisye.dll into a process and invoke tshook(). debug mode should be enabled by 'bcdedit /debug on'\n"
            "Usage: tsinject pid \n"
            "  pid      The process ID to be injected into.\n";

        if (argc < 2) throw runtime_error("Missing parameters\n");

        DWORD pid{};
        for (int i = 1; i < argc; ++i)
        {
            string arg(argv[i]);

            if (arg == "-h")
            {
                throw runtime_error(usage);
            }
            else
            {
                pid = to_value(arg);
            }
        }

        inject(pid);

        cout << "Succeeded." << endl;
    }
    catch (const std::exception& e)
    {
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}

