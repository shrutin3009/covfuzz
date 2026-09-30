# Adds the covfuzz target to xpdf's build.
# Included from xpdf-4.06/xpdf/CMakeLists.txt by scripts/build.sh.
# FUZZER_SRC is passed in on the cmake command line.

if(NOT DEFINED FUZZER_SRC OR NOT EXISTS "${FUZZER_SRC}")
  message(FATAL_ERROR "covfuzz: FUZZER_SRC not set or missing (got '${FUZZER_SRC}')")
endif()

get_filename_component(FUZZER_SRC "${FUZZER_SRC}" ABSOLUTE)

# pdftotext's main() is renamed to targetMain() so the fuzzer can call it in-process.
add_executable(covfuzz pdftotext.cc TextOutputDev.cc "${FUZZER_SRC}")
set_source_files_properties(pdftotext.cc PROPERTIES COMPILE_DEFINITIONS "main=targetMain")
# The fuzzer itself is not instrumented, so its own code does not pollute the coverage map.
set_source_files_properties("${FUZZER_SRC}" PROPERTIES
  LANGUAGE CXX
  COMPILE_OPTIONS "-fno-sanitize-coverage=inline-8bit-counters"
)

set(_covfuzz_link_libs goo fofi)
set(_covfuzz_xpdf_target "")
foreach(_candidate xpdf_objs xpdf-objs xpdf)
  if(TARGET ${_candidate})
    set(_covfuzz_xpdf_target "${_candidate}")
    break()
  endif()
endforeach()

if(_covfuzz_xpdf_target STREQUAL "")
  message(FATAL_ERROR
    "covfuzz: could not find xpdf core target (expected one of: xpdf_objs, xpdf-objs, xpdf)")
endif()

get_target_property(_covfuzz_xpdf_type ${_covfuzz_xpdf_target} TYPE)
if(_covfuzz_xpdf_type STREQUAL "OBJECT_LIBRARY")
  list(APPEND _covfuzz_link_libs "$<TARGET_OBJECTS:${_covfuzz_xpdf_target}>")
else()
  list(APPEND _covfuzz_link_libs ${_covfuzz_xpdf_target})
endif()

if(DEFINED PDFTOTEXT_LINK_LIBS AND NOT "${PDFTOTEXT_LINK_LIBS}" STREQUAL "")
  separate_arguments(_covfuzz_extra_libs NATIVE_COMMAND "${PDFTOTEXT_LINK_LIBS}")
  list(APPEND _covfuzz_link_libs ${_covfuzz_extra_libs})
endif()

list(REMOVE_DUPLICATES _covfuzz_link_libs)
target_link_libraries(covfuzz PRIVATE ${_covfuzz_link_libs})
message(STATUS "covfuzz: linking with ${_covfuzz_link_libs}")

set_target_properties(covfuzz PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/xpdf"
)
