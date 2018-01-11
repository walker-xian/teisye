/* Copyright (C) 2010 Daiqian Huang <daiqian.huang@outlook.com>
 *
 * heapperf is free software; you can redistribute it and/or modify it 
 * under the terms of the MIT License.
 */
 
 /** 
  * @file heapperf.cpp
  * 
  * heapperf measures heap performance.
*/
#if defined(_WIN32)
#define _WIN32_WINNT    _WIN32_WINNT_WIN7
#define WIN32_LEAN_AND_MEAN     // Exclude rarely-used stuff from Windows headers
#define NOMINMAX                // Exclude macros min and max
#define _ENABLE_ATOMIC_ALIGNMENT_FIX
#include <windows.h>
#include <psapi.h>
#else
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include <memory>
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>
#include <vector>
#include <map>
#include <regex>
#include <stdexcept>
#include <cassert>
#include <thread>
#include "../src/teisye.h"

static const char _wc_text[]
{
    "Function "
    "<cstdlib> "
    "malloc "
    "void* malloc (size_t size); "
    "Allocate memory block "
    "Allocates a block of size bytes of memory, returning a pointer to the beginning of the block. "
    " "
    "The content of the newly allocated block of memory is not initialized, remaining with indeterminate values. "
    " "
    "If size is zero, the return value depends on the particular library implementation (it may or may not be a null pointer), but the returned pointer shall not be dereferenced. "
    " "
    "Parameters "
    "size "
    "Size of the memory block, in bytes. "
    "size_t is an unsigned integral type. "
    " "
    "Return Value "
    "On success, a pointer to the memory block allocated by the function. "
    "The type of this pointer is always void*, which can be cast to the desired type of data pointer in order to be dereferenceable. "
    "If the function failed to allocate the requested block of memory, a null pointer is returned. "
};

static const char _usage[]
{
    "Usage: [-h] [-l loop_num] [-t thread_num] [allocator_id]\n"
    "  -h               Print the usage.\n"
    "  -c case_mask     Which test cases to run, default is 0x1f, which will ran all cases.\n"
    "  -l loop_num      The number of loops that tests will repeatedly run, default: 10.\n"
    "  thread_num       The number of threads the test will run within.\n"
    "  allocator_id     Specifies a allocator that will be tested, 0:malloc, 1:teisye, default is 0.\n"
};

using namespace std;
using namespace std::chrono;

struct statistic
{
    nanoseconds _allocations_cost{};
    nanoseconds _deallocations_cost{};
    int _num_of_allocations{};
    int _num_of_deallocations{};

    statistic operator+=(const statistic& rhs) noexcept
    {
        _allocations_cost += rhs._allocations_cost;
        _deallocations_cost += rhs._deallocations_cost;
        _num_of_allocations += rhs._num_of_allocations;
        _num_of_deallocations += rhs._num_of_deallocations;

        return *this;
    }

    int64_t average_allocation_cost() const noexcept
    {
        return _num_of_allocations ? (_allocations_cost / _num_of_allocations).count() : 0;
    }

    int64_t average_deallocation_cost() const noexcept
    {
        return  _num_of_deallocations ? (_deallocations_cost / _num_of_deallocations).count() : 0;
    }
};

typedef void* (*allocator_t)(size_t size);
typedef void  (*deallocator_t)(void*);

thread_local allocator_t _active_allocator = tsalloc;
thread_local deallocator_t _active_deallocator = tsfree;

static statistic _default_statistic{};
static thread_local statistic* _active_statistic{ &_default_statistic };

inline void* local_alloc(size_t size) noexcept
{
    auto start = high_resolution_clock::now();
    void* p = _active_allocator(size);
    auto end = high_resolution_clock::now();
    _active_statistic->_allocations_cost += end - start;
    _active_statistic->_num_of_allocations++;
    return p;
}

inline void local_dealloc(void* p) noexcept
{
    auto start = high_resolution_clock::now();
    _active_deallocator(p);
    auto end = high_resolution_clock::now();
    _active_statistic->_deallocations_cost += end - start;
    _active_statistic->_num_of_deallocations++;
}

void* operator new  (size_t size)
{
    return local_alloc(size);
}

void* operator new[](size_t size)
{
    return local_alloc(size);
}

void operator delete(void* ptr)
{
    local_dealloc(ptr);
}

void operator delete[](void* ptr)
{
    local_dealloc(ptr);
}

class application
{
    enum allocator_id : int { _malloc, _teisye };
    enum test_case : int { _wc, _small, _medium, _large, _extremely_large, _test_case_count }; // _huge is used by windows
    using case_statistics_t = statistic[_test_case_count];

    struct
    {
        const char*  _name;
        size_t _max_size;
        size_t _step;
    } _test_cases[_test_case_count]
    {
        { "wc",     0, 1 },
        { "512b",   512 - 8 + 1, 1 },
        { "8kb",    1024 * 8 - 8 + 1, 1 },
        { "128kb",  1024 * 128 - 8 - sizeof(void*) * 2 + 1, 21 },
        { "huge",   1024 * 130, 1 },
    };

    allocator_id _allocator_id{ _malloc };
    int _num_of_threads{ 1 };   // number of threads that tests run in
    int _num_of_loops{ 10 };    // number of loops that tests run
    int _case_mask{ 0x1f };     // run all cases by default

    void test(case_statistics_t& cs) noexcept
    {
        switch (_allocator_id)
        {
        case _malloc:
            _active_allocator = ::malloc;
            _active_deallocator = ::free;
            break;
        case _teisye:
            _active_allocator = tsalloc;
            _active_deallocator = tsfree;
            break;
        default:
            assert(0);
            break;
        }

        if (1 & _case_mask)
        {
            _active_statistic = &cs[_wc];
            test_wc();
        }

        unique_ptr<char> allocations[8] {};
        int pos{};

        for (int tc = 1; tc < _test_case_count; ++tc)
        {
            if (!((1 << tc) & _case_mask)) continue;

            _active_statistic = &cs[tc];
            for (size_t size = _test_cases[tc - 1]._max_size; size < _test_cases[tc]._max_size; size += _test_cases[tc]._step)
            {
                allocations[pos] = unique_ptr<char>(new char[size]);
                memset(allocations[pos].get(), 0xbd, size);

                // hold for a little while before deallocate it;
                pos = (pos + 1) % sizeof(allocations)/sizeof(allocations[0]);
                if (pos == 0)
                {
                    for (size_t i = 0; i < sizeof(allocations)/sizeof(allocations[0]); ++i)
                    {
                        allocations[i].reset();
                    }
                }
            }
        }

        for (size_t i = 0; i < sizeof(allocations)/sizeof(allocations[0]); ++i)
        {
            allocations[i].release();
        }

        _active_statistic = &_default_statistic;
        _active_allocator = tsalloc;
        _active_deallocator = tsfree;
    }

    void test_wc()
    {
        map<string, int> words;

        typedef regex_token_iterator<const char*> regex_it;
        regex_it::regex_type rx(R"([\s+[:punct:]+])"); // spaces and punctuations
        regex_it token(_wc_text, _wc_text + sizeof(_wc_text)/sizeof(_wc_text[0]), rx, -1);
        regex_it end;

        for (; token != end; token++)
        {
            string word{ *token };
            auto it = words.find(word);
            if (it == words.end()) words[word] = 0;
            ++words[word];
        }
    }

public:
    void parse_args(int argc, char *args[])
    {
        for (int i = 1; i < argc; i++)
        {
            string arg(args[i]);

            if (arg == "-h")
            {
                throw runtime_error(_usage);
            }
            else if (arg == "-c")
            {
                if (!args[++i]) throw runtime_error("-c missing a number");
                _case_mask = stoi(args[i]);
                if (_case_mask <= 0) throw runtime_error("-c invalid number");
            }
            else if (arg == "-l")
            {
                if (!args[++i]) throw runtime_error("-l missing a number");
                _num_of_loops = stoi(args[i]);
                if (_num_of_loops <= 0) throw runtime_error("-l invalid number");
            }
            else if (arg == "-t")
            {
                if (!args[++i]) throw runtime_error("-t missing a number");
                _num_of_threads = stoi(args[i]);
                if (_num_of_threads <= 0) throw runtime_error("-t invalid number");
            }
            else
            {
                _allocator_id = static_cast<allocator_id>(stoi(args[i]));
                if (_allocator_id != _malloc && _allocator_id != _teisye) throw runtime_error("invalid allocator id");
            }
        }
    }

    void run()
    {
        auto start_time{ high_resolution_clock::now() };

        vector<case_statistics_t> tcs(_num_of_threads);
        for (int l = 0; l < _num_of_loops; ++l)
        {
            vector<thread> threads(_num_of_threads);

            for (int i = 0; i < _num_of_threads; ++i)
            {
                thread t{ &application::test,  this, std::ref(tcs[i]) };
                threads[i] = move(t);
            }

            // wait for all threads have completed
            for (auto it = threads.begin(); it != threads.end(); ++it)
            {
                it->join();
            }
        }

        case_statistics_t final_results;
        for (auto it = tcs.begin(); it != tcs.end(); ++it)
        {
            for (int i = 0; i < _test_case_count; ++i)
                final_results[i] += (*it)[i];
        }

        auto run_duration = duration_cast<milliseconds>(high_resolution_clock::now() - start_time);

        string allocator_names[] { "malloc", "tsalloc"};
        cout << "allocator: " << allocator_names[_allocator_id] << endl;
        cout << "number of threads: " << _num_of_threads << endl;
        cout << "number of loops: " << _num_of_loops << endl;
        cout << "run duration(ms): " << run_duration.count() << endl;
        cout << "number of logic processors: " << thread::hardware_concurrency() << endl;

#if defined(_WIN32) 
#if defined(_MSC_VER)
        PROCESS_MEMORY_COUNTERS_EX pmcex = { 0 };
        GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmcex, sizeof(pmcex));
        cout << "peak working set(KB): " << pmcex.PeakWorkingSetSize / 1024 << endl;
        cout << "private usage(KB): " << pmcex.PrivateUsage / 1024 << endl;
#endif
#else
        rusage ru;
        getrusage(RUSAGE_SELF, &ru);
        cout << "maximum resident set size(KB): " << ru.ru_maxrss << endl;
#endif

        cout << left << setw(12) << "CASE"
             << right << setw(8)  << "AT"        // average allocation cost
             << right << setw(16) << "AC"
             << right << setw(16) << "DT"
             << right << setw(16) << "DC"
             << endl;

        for (int i = 0; i < _test_case_count; ++i)
        {
            cout << left << setw(12) << _test_cases[i]._name
                 << right << setw(8)  << final_results[i].average_allocation_cost()
                 << right << setw(16) << final_results[i]._num_of_allocations
                 << right << setw(16) << final_results[i].average_deallocation_cost()
                 << right << setw(16) << final_results[i]._num_of_deallocations
                 << endl;
        }
    }
};

int main(int argc, char **argv)
{
    try
    {
        application app;

        app.parse_args(argc, argv);
        app.run();
    }
    catch (const std::bad_alloc&)
    {
        cerr << "out of memory" << endl;
    }
    catch (const std::exception& e)
    {
        cerr << e.what() << endl;
    }

    return 0;
}
