cmake_minimum_required(VERSION 3.14)
project(hexpress VERSION 6.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(HEXPRESS_BUILD_TOOLS  "Build hex-press / hex-tract CLIs" ON)
option(HEXPRESS_BUILD_TESTS  "Build unit tests (ctest)" ON)
option(HEXPRESS_BUILD_SHARED "Build shared library" ON)

add_library(hexpress_obj OBJECT libhexpress.cpp)
target_include_directories(hexpress_obj PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>)
set_target_properties(hexpress_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(hexpress_obj PRIVATE -Wall -Wextra)
endif()
find_package(Threads REQUIRED)
target_link_libraries(hexpress_obj PUBLIC Threads::Threads)

if(HEXPRESS_BUILD_SHARED)
  add_library(hexpress SHARED $<TARGET_OBJECTS:hexpress_obj>)
  target_include_directories(hexpress PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
      $<INSTALL_INTERFACE:include>)
  target_link_libraries(hexpress PUBLIC Threads::Threads)
  set_target_properties(hexpress PROPERTIES OUTPUT_NAME hexpress VERSION ${PROJECT_VERSION} SOVERSION 6)
endif()

add_library(hexpress_static STATIC $<TARGET_OBJECTS:hexpress_obj>)
target_include_directories(hexpress_static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(hexpress_static PUBLIC Threads::Threads)
set_target_properties(hexpress_static PROPERTIES OUTPUT_NAME hexpress)

if(HEXPRESS_BUILD_TOOLS)
  add_executable(hex-press hex-press.cpp)
  target_link_libraries(hex-press PRIVATE hexpress_static)
  add_executable(hex-tract hex-tract.cpp)
  target_link_libraries(hex-tract PRIVATE hexpress_static)
  install(TARGETS hex-press hex-tract RUNTIME DESTINATION bin)
endif()

if(HEXPRESS_BUILD_TESTS)
  enable_testing()
  add_executable(test_lib test_lib.cpp)
  target_link_libraries(test_lib PRIVATE hexpress_static)
  add_test(NAME unit_full COMMAND test_lib)
  add_test(NAME unit_multithread COMMAND test_lib mt)
  set_tests_properties(unit_full unit_multithread PROPERTIES TIMEOUT 900)
endif()

install(TARGETS hexpress_static ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)
if(HEXPRESS_BUILD_SHARED)
  install(TARGETS hexpress LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
endif()
install(FILES libhexpress.h DESTINATION include)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/hexpress.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/hexpress.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/hexpress.pc DESTINATION lib/pkgconfig)

install(FILES README.md LICENSE DESTINATION share/doc/hexpress)
