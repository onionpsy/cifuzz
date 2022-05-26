include("${CMAKE_CURRENT_LIST_DIR}/CIFuzzTargets.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/CIFuzzFunctions.cmake")

set(CIFUZZ_ENGINE "replayer" CACHE STRING "The fuzzing engine used to run fuzz tests")
set(CIFUZZ_SANITIZERS "" CACHE STRING "The sanitizers to instrument the code with")
set(CIFUZZ_USE_DEPRECATED_MACROS OFF CACHE BOOL "Whether to use the deprecated FUZZ(_INIT) macros instead of FUZZ_TEST(_SETUP)")

set(CIFUZZ_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/../../include/cifuzz" CACHE INTERNAL "The include directory for the cifuzz headers")
