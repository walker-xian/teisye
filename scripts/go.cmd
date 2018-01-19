@echo off

for %%t in (1, 4, 8) do (
    for %%h in (0, 1) do (
        for /l %%i in (1, 1, 3) do (
            @build\release\x64\heapperf -l 3 -t %%t %%h 
        )
    )
)
