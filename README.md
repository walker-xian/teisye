# teisye
teisye is a memory allocator, it provides tsalloc/tsfree/tsrealloc to replace malloc/free/realloc in C/C++ programs.

### Build on Windows
VC++ 2017 is required to build teisye on Windows, it can be built from Vistual Studio IDE, or use below command at a VC++ command line:

    msbuild /p:Configuration="Release" /p:Platfrom=x64 teisye.sln
### Build on Linux
GCC 6.3 or above is required to build teisye on Linux. Specifies DEBUG=1 to make command to build debug version, specifies SHARED=1 to make command to build heapperf that uses teisye.so. For examples:

    make clean all
    make DEBUG=1 clean all
    make SHARED=1 clean all

# heapperf
heapperf reports the performance of tsalloc/tsfree or malloc/free, below is an example of report:

	allocator: tsalloc
	number of threads: 1
	number of loops: 10
	run duration(ms): 530
	number of logic processors: 4
	peak working set(KB): 2304
	private usage(KB): 3556
	CASE              AT              AC              DT              DC
	wc                89           19372              80           19370
	512b              88            5050              78            5050
	8kb               99           76800              82           76800
	128kb            122           58510              89           58510
	huge             345           20710             356           20710
	
	AT: average allocation time in nanoseconds.
	AC: total allocation count. 
	DT: average deallocation time in nanoseconds.
	DC: total deallocation count.

