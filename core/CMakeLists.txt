cmake_minimum_required(VERSION 3.20)

project(aidecomp_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(aidecomp_core STATIC
  aidecomp_core/src/analyzer.cpp
  aidecomp_core/src/native_byte_image_decoder.cpp
  aidecomp_core/src/objdump_image_decoder.cpp
  aidecomp_core/src/pe_loader.cpp
  aidecomp_core/src/x86_byte_decoder.cpp
  aidecomp_core/src/x86_decoder.cpp
)
set_target_properties(aidecomp_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(aidecomp_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/aidecomp_core/include
)

enable_testing()

add_executable(aidecomp_core_tests
  tests/core_tests.cpp
)

target_link_libraries(aidecomp_core_tests PRIVATE aidecomp_core)

add_test(NAME aidecomp_core_tests COMMAND aidecomp_core_tests)

option(AIDECOMP_BUILD_PYBIND "Build Python bindings" ON)
if(AIDECOMP_BUILD_PYBIND)
  find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

  execute_process(
    COMMAND ${Python3_EXECUTABLE} -m pybind11 --cmakedir
    RESULT_VARIABLE _pybind_cmd_result
    OUTPUT_VARIABLE _pybind_cmake_dir
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )

  if(NOT _pybind_cmd_result EQUAL 0)
    message(FATAL_ERROR "pybind11 not found. Install pybind11 in the active Python environment.")
  endif()

  find_package(pybind11 CONFIG REQUIRED PATHS ${_pybind_cmake_dir} NO_DEFAULT_PATH)

  pybind11_add_module(aidecomp_cpp
    aidecomp_py/src/bindings.cpp
  )

  target_link_libraries(aidecomp_cpp PRIVATE aidecomp_core)
  target_include_directories(aidecomp_cpp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/aidecomp_core/include
  )

  set_target_properties(aidecomp_cpp PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/aidecomp_py/python/aidecomp_py
  )
endif()
