include("${CMAKE_CURRENT_LIST_DIR}/cifuzz-functions.cmake")

set(CIFUZZ_TESTING false CACHE BOOL "Enable general compiler options for fuzzing and regression tests")
set(CIFUZZ_ENGINE "replayer" CACHE STRING "The fuzzing engine used to run fuzz tests")
set(CIFUZZ_SANITIZERS "" CACHE STRING "The sanitizers to instrument the code with")
set(CIFUZZ_USE_DEPRECATED_MACROS OFF CACHE BOOL "Whether to use the deprecated FUZZ(_INIT) macros instead of FUZZ_TEST(_SETUP)")

if(${CMAKE_VERSION} VERSION_LESS "3.19.0")
    get_filename_component(CIFUZZ_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}" REALPATH)
else()
    file(REAL_PATH "${CMAKE_CURRENT_LIST_DIR}" CIFUZZ_CMAKE_DIR)
endif()
set(CIFUZZ_INCLUDE_DIR "${CIFUZZ_CMAKE_DIR}/../../include" CACHE INTERNAL "The include directory for the cifuzz headers")
set(CIFUZZ_DUMPER_C_SRC "${CIFUZZ_CMAKE_DIR}/../../src/dumper.c" CACHE INTERNAL "The path of the dumper as a C source file.")
set(CIFUZZ_DUMPER_CXX_SRC "${CIFUZZ_CMAKE_DIR}/../../src/dumper.cpp" CACHE INTERNAL "The path of the dumper as a CXX source file.")
set(CIFUZZ_LAUNCHER_C_SRC "${CIFUZZ_CMAKE_DIR}/../../src/launcher.c" CACHE INTERNAL "The path of the launcher as a C source file.")
set(CIFUZZ_LAUNCHER_CXX_SRC "${CIFUZZ_CMAKE_DIR}/../../src/launcher.cpp" CACHE INTERNAL "The path of the launcher as a CXX source file.")
set(CIFUZZ_REPLAYER_C_SRC "${CIFUZZ_CMAKE_DIR}/../../src/replayer.c" CACHE INTERNAL "The path of the replayer as a C source file.")
set(CIFUZZ_REPLAYER_CXX_SRC "${CIFUZZ_CMAKE_DIR}/../../src/replayer.cpp" CACHE INTERNAL "The path of the replayer as a CXX source file.")