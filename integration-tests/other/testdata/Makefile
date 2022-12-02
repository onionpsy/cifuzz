CXXFLAGS += -std=c++11

clean:
	rm -rf *.o *.a *.so.* *.so a.out

libexplore.so.4.2: src/explore/explore_me.cpp src/explore/explore_me.h
	${CXX} ${CXXFLAGS} -shared -fpic -o libexplore.so.4.2 $<

libexplore.so.4: libexplore.so.4.2
	ln -s libexplore.so.4.2 libexplore.so.4

libexplore.so: libexplore.so.4
	ln -s libexplore.so.4 libexplore.so

my_fuzz_test: libexplore.so
	@echo "Building $@"
	# The FUZZ_TEST_CXXFLAGS and FUZZ_TEST_LDFLAGS environment variables
	# are set by cifuzz when it executes the build command. Those must
	# be passed to the compiler and linker (compiling and linking is
	# done in a single invocation here, so we pass both to $CXX here).
	${CXX} ${CXXFLAGS} ${FUZZ_TEST_CXXFLAGS} ${FUZZ_TEST_LDFLAGS} -o $@ $@.cpp -Wl,-rpath '-Wl,$$ORIGIN' -L. -lexplore

crashing_fuzz_test.o: src/coverage/crashing_fuzz_test.c
	${CC} ${CFLAGS} ${FUZZ_TEST_CFLAGS} -c $<

crashing_fuzz_test: crashing_fuzz_test.o
	${CC} -o $@ crashing_fuzz_test.o ${LDFLAGS} ${FUZZ_TEST_LDFLAGS}
