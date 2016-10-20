CXXFLAGS := -O2 -fomit-frame-pointer -std=c++11 -I../common/
ALL := drk-probing

all: $(ALL)

drk-probing:

clean:
	rm -f *.o $(ALL) scan_* kernel_* module_* kallsyms kpt modules_* *.pyc

.PHONY: all clean
