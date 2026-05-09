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
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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

# Configure TF-PSA-Crypto from submodule or system
option(USE_BUNDLED_TF_PSA_CRYPTO "Use bundled TF-PSA-Crypto" ON)
if(USE_BUNDLED_TF_PSA_CRYPTO)
  set(OLD_ENABLE_TESTING ${ENABLE_TESTING})
  set(OLD_ENABLE_PROGRAMS ${ENABLE_PROGRAMS})
  set(USE_STATIC_TF_PSA_CRYPTO_LIBRARY ON CACHE BOOL "" FORCE)
  set(USE_SHARED_TF_PSA_CRYPTO_LIBRARY OFF CACHE BOOL "" FORCE)
  set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(ENABLE_PROGRAMS OFF CACHE BOOL "Build TF-PSA-Crypto programs." FORCE)
  set(TF_PSA_CRYPTO_FATAL_WARNINGS OFF CACHE BOOL "Compiler warnings treated as errors" FORCE)
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/tf-psa-crypto/core/psa_crypto_driver_wrappers_no_static.c")
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    execute_process(
      COMMAND "${Python3_EXECUTABLE}" -c "import jinja2, jsonschema"
      RESULT_VARIABLE CNK_TF_PSA_CRYPTO_PYTHON_DEPS_RESULT
      OUTPUT_QUIET
      ERROR_QUIET)
    if(NOT CNK_TF_PSA_CRYPTO_PYTHON_DEPS_RESULT EQUAL 0)
      message(FATAL_ERROR
        "TF-PSA-Crypto generated files are missing and GEN_FILES is required, "
        "but ${Python3_EXECUTABLE} cannot import jinja2 and jsonschema. "
        "Install cmake/tf-psa-crypto-generator-requirements.txt or pass "
        "-DPython3_EXECUTABLE to the Python environment that has them.")
    endif()
    set(GEN_FILES ON CACHE BOOL "Generate TF-PSA-Crypto files as needed" FORCE)
  else()
    set(GEN_FILES OFF CACHE BOOL "Generate TF-PSA-Crypto files as needed" FORCE)
  endif()

  set(CNK_TF_PSA_CRYPTO_USER_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/include/private/mbedtls_config_cnk.h")
  file(TO_CMAKE_PATH "${CNK_TF_PSA_CRYPTO_USER_CONFIG_FILE}" CNK_TF_PSA_CRYPTO_USER_CONFIG_FILE)
  set(TF_PSA_CRYPTO_USER_CONFIG_FILE "${CNK_TF_PSA_CRYPTO_USER_CONFIG_FILE}" CACHE FILEPATH "" FORCE)

  add_subdirectory(external/tf-psa-crypto)

  set(ENABLE_TESTING ${OLD_ENABLE_TESTING} CACHE BOOL "" FORCE)
  set(ENABLE_PROGRAMS ${OLD_ENABLE_PROGRAMS} CACHE BOOL "" FORCE)
  set(CMAKE_C_STANDARD 17)
  set(CMAKE_C_EXTENSIONS ON)
  set(CMAKE_C_STANDARD_REQUIRED ON)

  set(CNK_CRYPTO_LIBRARIES tfpsacrypto)
  set_default_visibility(${CNK_CRYPTO_LIBRARIES})
else()
  find_package(TF-PSA-Crypto REQUIRED)
  set(CNK_CRYPTO_LIBRARIES TF-PSA-Crypto::tfpsacrypto)
endif()

set(CNK_PKCS_LIBS nsync ${CNK_CRYPTO_LIBRARIES})

file(GLOB_RECURSE CNK_PKCS_SRC CONFIGURE_DEPENDS src/*.c)

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
  target_compile_definitions(${CNK_PKCS_TARGET} PRIVATE "CNK_LIB_SHARED" "CRYPTOKI_EXPORTS")
else()
  target_compile_definitions(${CNK_PKCS_TARGET} PRIVATE "CNK_LIB_STATIC")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(${CNK_PKCS_TARGET} PRIVATE "CNK_VERBOSE")
endif()

target_compile_definitions(${CNK_PKCS_TARGET} PRIVATE "MBEDTLS_ALLOW_PRIVATE_ACCESS")

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
option(BUILD_UNIT_TESTING "Build unit test programs" ${BUILD_TESTING})
option(BUILD_REAL_TESTING "Build real hardware test programs" ${BUILD_TESTING})
option(RUN_REAL_TESTING "Register real hardware tests with CTest" OFF)
if(BUILD_UNIT_TESTING OR BUILD_REAL_TESTING)
  enable_testing()
endif()

if(BUILD_UNIT_TESTING)
  # for test only, expose all symbols
  add_library(${CNK_PKCS_TARGET}-test SHARED ${CNK_PKCS_SRC} ${CNK_PKCS_HEADERS})
  target_compile_definitions(${CNK_PKCS_TARGET}-test PRIVATE "CNK_LIB_STATIC" "CNK_VERBOSE" "MBEDTLS_ALLOW_PRIVATE_ACCESS")
  target_link_libraries(${CNK_PKCS_TARGET}-test PRIVATE ${CNK_PKCS_LIBS})
  add_subdirectory(test/unit)
endif()

if(BUILD_REAL_TESTING)
  add_subdirectory(test/real)
endif()
