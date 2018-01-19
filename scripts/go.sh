heapperf=build/$(gcc -dumpmachine)/heapperf

for thread in 1 4 8 
do
    for heap in 0 1 
    do
        for ((i = 0; i < 3; ++i)) 
        do
            $heapperf -c 15 -l 3 -t $thread $heap
        done
    done
done
