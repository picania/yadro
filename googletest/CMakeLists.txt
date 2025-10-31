# Where Google Test's .h files can be found.
set(gtest_build_include_dirs
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}")
include_directories(${gtest_build_include_dirs})

add_library(gtest STATIC src/gtest-all.cc)
add_library(gtest_main STATIC src/gtest_main.cc)

string(REPLACE ";" "$<SEMICOLON>" dirs "${gtest_build_include_dirs}")

set_property(TARGET gtest PROPERTY CXX_STANDARD 17)
set_property(TARGET gtest_main PROPERTY CXX_STANDARD 17)

target_include_directories(gtest SYSTEM INTERFACE
  "$<BUILD_INTERFACE:${dirs}>")
target_include_directories(gtest_main SYSTEM INTERFACE
  "$<BUILD_INTERFACE:${dirs}>")
target_link_libraries(gtest_main PUBLIC gtest)
