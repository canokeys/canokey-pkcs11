cmake_minimum_required(VERSION 3.10)
set(CNK_PKCS_TARGET "canokey_pkcs11")
set(CNK_PKCS_LIB_NAME "canokey-pkcs11")
project(${CNK_PKCS_TARGET} VERSION 0.1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_EXTENSIONS ON) # some macros need GNU extensions
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(WARNING "This project should be built with clang, now using ${CMAKE_C_COMPILER_ID}")
endif()

message(STATUS "C Compiler ID: ${CMAKE_C_COMPILER_ID}, Frontend: ${CMAKE_C_COMPILER_FRONTEND_VARIANT}")

if((CMAKE_C_COMPILER_ID MATCHES "GNU|Clang") AND (NOT CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"))
  set(USE_GNU_COMPILERS ON)
  message(STATUS "Using vanilla gcc or clang")
else()
  set(USE_GNU_COMPILERS OFF)
  message(STATUS "Using clang-cl")
endif()

if(USE_GNU_COMPILERS)
  add_compile_options("-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=")
  add_compile_options("-ffunction-sections" "-fdata-sections")
  if(LINUX)
    add_link_options("-Wl,--gc-sections")
  elseif(APPLE)
    add_link_options("-Wl,-dead_strip")
  elseif(WIN32)
    add_link_options("/LTCG")
  endif()
endif()

# Include project directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/private)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

# hide all symbols by default (clang-cl does not support this)
function(set_default_visibility)
  if(USE_GNU_COMPILERS)
    foreach(arg IN LISTS ARGN)
      target_compile_options(${arg} PRIVATE "-fvisibility=hidden")
    endforeach()
  endif()
endfunction()

# Configure nsync from submodule or system
option(USE_BUNDLED_NSYNC "Use bundled nsync" ON)
if(USE_BUNDLED_NSYNC)
  set(NSYNC_ENABLE_TESTS OFF CACHE BOOL "Enable for building tests" FORCE)
  add_subdirectory(external/nsync)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/nsync/public)
  set_default_visibility(nsync)
else()
  find_package(nsync REQUIRED)
endif()

# Configure mbedtls from submodule or system
option(USE_BUNDLED_MBEDTLS "Use bundled mbedtls" ON)
if(USE_BUNDLED_MBEDTLS)
  set(OLD_BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS})
  set(OLD_ENABLE_TESTING ${ENABLE_TESTING})
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE) # we must build mbedtls as static library
  set(ENABLE_TESTING OFF CACHE BOOL "" FORCE) # disable mbedtls tests
  set(ENABLE_PROGRAMS OFF CACHE BOOL "Build Mbed TLS programs." FORCE) # disable mbedtls programs
  set(MBEDTLS_USER_CONFIG_FILE "mbedtls_config_cnk.h" CACHE FILEPATH "" FORCE) # add user config

  add_subdirectory(external/mbedtls)

  set(BUILD_SHARED_LIBS ${OLD_BUILD_SHARED_LIBS} CACHE BOOL "" FORCE) # restore original value
  set(ENABLE_TESTING ${OLD_ENABLE_TESTING} CACHE BOOL "" FORCE) # restore original value

  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/mbedtls/include)
  set(MBEDTLS_LIBRARIES mbedcrypto)
  set_default_visibility(${MBEDTLS_LIBRARIES})
else()
  find_package(MbedTLS REQUIRED)
  set(MBEDTLS_LIBRARIES MBedTLS::mbedcrypto)
endif()

set(CNK_PKCS_LIBS nsync ${MBEDTLS_LIBRARIES})

file(GLOB CNK_PKCS_SRC src/*.c)

# these files will be installed (excluding include/private)
file(GLOB CNK_PKCS_PUBLIC_HEADERS include/*.h)

# all headers used (including private ones)
file(GLOB_RECURSE CNK_PKCS_HEADERS include/*.h)

add_library(${CNK_PKCS_TARGET} ${CNK_PKCS_SRC} ${CNK_PKCS_HEADERS})
set_default_visibility(${CNK_PKCS_TARGET})
if(USE_GNU_COMPILERS)
  target_compile_options(${CNK_PKCS_TARGET} PRIVATE "-Wextra" "-Wpedantic" "-Wall")
  if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_compile_options(${CNK_PKCS_TARGET} PRIVATE "-Wmost")
  endif()
elseif(MSVC)
  target_compile_options(${CNK_PKCS_TARGET} PRIVATE "/W4")
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

if(BUILD_SHARED_LIBS)
  target_compile_definitions(${CNK_PKCS_TARGET} PRIVATE "CNK_LIB_SHARED")
else()
  target_compile_definitions(${CNK_PKCS_TARGET} PRIVATE "CNK_LIB_STATIC")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(${CNK_PKCS_TARGET} PRIVATE "CNK_VERBOSE")
endif()

# find PC/SC library on different platforms
if(WIN32)
  # On Windows, use native PC/SC API
  set(CNK_PKCS_LIBS ${CNK_PKCS_LIBS} winscard.lib)
elseif(APPLE)
  # On macOS, PC/SC is provided by the PCSC framework
  find_library(PCSC_FRAMEWORK PCSC REQUIRED)
  set(CNK_PKCS_LIBS ${CNK_PKCS_LIBS} ${PCSC_FRAMEWORK})
elseif(UNIX)
  # For other UNIX-like platforms, use pkgconf to find libpcsclite
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(PCSC REQUIRED libpcsclite)
  include_directories(${PCSC_INCLUDE_DIRS})
  set(CNK_PKCS_LIBS ${CNK_PKCS_LIBS} ${PCSC_LIBRARIES})
else()
  message(FATAL_ERROR "Unsupported platform")
endif()

target_link_libraries(${CNK_PKCS_TARGET} PRIVATE ${CNK_PKCS_LIBS})

# Set library properties
set_target_properties(${CNK_PKCS_TARGET} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    OUTPUT_NAME ${CNK_PKCS_LIB_NAME}
    PUBLIC_HEADER "${CNK_PKCS_PUBLIC_HEADERS}"
)

# Install the library
install(TARGETS ${CNK_PKCS_TARGET}
    EXPORT "${CNK_PKCS_LIB_NAME}"
    RUNTIME
    LIBRARY
    ARCHIVE
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${CNK_PKCS_LIB_NAME}
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

option(BUILD_TESTING "Build test programs" OFF)
if(BUILD_TESTING)
  enable_testing()
  # for test only, expose all symbols
  add_library(${CNK_PKCS_TARGET}-test SHARED ${CNK_PKCS_SRC} ${CNK_PKCS_HEADERS})
  target_compile_definitions(${CNK_PKCS_TARGET} PRIVATE "CNK_LIB_STATIC" "CNK_VERBOSE")
  target_link_libraries(${CNK_PKCS_TARGET}-test PRIVATE ${CNK_PKCS_LIBS})
  add_subdirectory(test/unit)
  add_subdirectory(test/real)
endif()
