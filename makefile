TARGETDIR := ./build/$(shell $(CXX) -dumpmachine)

CXXFLAGS += -Wall
ifeq ($(DEBUG), 1)
	CXXFLAGS += -g 
else
	CXXFLAGS += -Ofast
endif

all : $(TARGETDIR) $(addprefix $(TARGETDIR)/, teisye.so heapperf)
    
clean:
	rm -f $(TARGETDIR)/*

$(TARGETDIR) :
	mkdir -p $(TARGETDIR)

$(TARGETDIR)/heapperf : $(TARGETDIR)/heapperf.o $(TARGETDIR)/teisye.so
ifeq ($(SHARED), 1)
	$(CXX) $(CXXFLAGS) -lpthread -o $@ $^
else
	$(CXX) $(CXXFLAGS) -lpthread -o $@ $< src/teisye.cpp 
endif

$(TARGETDIR)/heapperf.o : heapperf/heapperf.cpp src/teisye.h 
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(TARGETDIR)/teisye.so : src/teisye.cpp src/teisye.h
	$(CXX) $(CXXFLAGS) -shared -fPIC -Wl,--version-script=src/teisye.map -o $@ $<
