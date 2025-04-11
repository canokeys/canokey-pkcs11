cmake_minimum_required(VERSION 3.10)
set(CNK_PKCS_TARGET "canokey_pkcs11")
set(CNK_PKCS_LIB_NAME "canokey-pkcs11")
project(${CNK_PKCS_TARGET} VERSION 0.1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options("-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=")
endif()

# Include project directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/private)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

# hide all symbols by default (clang-cl does not support this)
function(set_default_visibility)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_C_SIMULATE_ID MATCHES "MSVC")
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
  set(MBEDTLS_LIBRARIES mbedcrypto mbedtls)
  set_default_visibility(mbedcrypto ${MBEDTLS_LIBRARIES})
else()
  find_package(MbedTLS REQUIRED)
  set(MBEDTLS_LIBRARIES MBedTLS::mbedcrypto MBedTLS::mbedtls)
endif()

set(CNK_PKCS_LIBS nsync ${MBEDTLS_LIBRARIES})

file(GLOB CNK_PKCS_SRC src/*.c)

# these files will be installed (excluding include/private)
file(GLOB CNK_PKCS_PUBLIC_HEADERS include/*.h)

# all headers used (including private ones)
file(GLOB_RECURSE CNK_PKCS_HEADERS include/*.h)

add_library(${CNK_PKCS_TARGET} ${CNK_PKCS_SRC} ${CNK_PKCS_HEADERS})
set_default_visibility(${CNK_PKCS_TARGET})

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

# Add a simple test executable if testing is enabled
option(BUILD_TESTING "Build test programs" OFF)
if(BUILD_TESTING)
    add_executable(test_pkcs11 test/test_pkcs11.c)
    target_link_libraries(test_pkcs11 ${CNK_PKCS_TARGET} ${CNK_PKCS_LIBS})
    
    add_executable(test_real test/test_real.c)
    if(APPLE OR UNIX)
        target_link_libraries(test_real dl)
    endif()
endif()
