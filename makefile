TARGETDIR := ./build/$(shell $(CXX) -dumpmachine)

CXXFLAGS += -Wall -pthread
ifeq ($(DEBUG), 1)
	CXXFLAGS += -g -D_DEBUG
else
	CXXFLAGS += -Ofast -DNDEBUG
endif

all : $(TARGETDIR) $(addprefix $(TARGETDIR)/, heapperf)
    
clean:
	rm -f $(TARGETDIR)/*

$(TARGETDIR) :
	mkdir -p $(TARGETDIR)

ifeq ($(SHARED), 1)
$(TARGETDIR)/heapperf : $(TARGETDIR)/heapperf.o $(TARGETDIR)/teisye.so
else
$(TARGETDIR)/heapperf : $(TARGETDIR)/heapperf.o $(TARGETDIR)/teisye.o
endif
	$(CXX) $(CXXFLAGS) -o $@ $^ -lpthread 

$(TARGETDIR)/heapperf.o : heapperf/heapperf.cpp src/teisye.h 
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(TARGETDIR)/teisye.o : src/teisye.cpp src/teisye.h
	$(CXX) $(CXXFLAGS) -fno-exceptions -c -o $@ $<

$(TARGETDIR)/teisye.so : src/teisye.cpp src/teisye.h
	$(CXX) $(CXXFLAGS) -fno-exceptions -shared -fPIC -Wl,--version-script=src/teisye.map -o $@ $<
