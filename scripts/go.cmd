@echo off

for %%t in (1, 2, 4, 8) do (
    for %%h in (0, 1) do (
        @heapperf -c 15 -l 3 -t %%t %%h 
    )
)
