cmake_minimum_required(VERSION 3.10)
set(CNK_PKCS_TARGET "canokey_pkcs11")
set(CNK_PKCS_LIB_NAME "canokey-pkcs11")
project(${CNK_PKCS_TARGET} VERSION 0.1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include project directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/private)

# Configure nsync from submodule or system
option(USE_BUNDLED_NSYNC "Use bundled nsync" ON)
if(USE_BUNDLED_NSYNC)
  set(NSYNC_ENABLE_TESTS OFF CACHE BOOL "Enable for building tests" FORCE)
  add_subdirectory(external/nsync)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/nsync/public)
else()
  find_package(nsync REQUIRED)
endif()

file(GLOB CNK_PKCS_SRC src/*.c)

# these files will be installed
file(GLOB CNK_PKCS_PUBLIC_HEADERS include/*.h)

# all headers used (including private ones)
file(GLOB_RECURSE CNK_PKCS_HEADERS include/*.h)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)
add_library(${CNK_PKCS_TARGET} ${CNK_PKCS_SRC} ${CNK_PKCS_HEADERS})
set(CNK_PKCS_LIBS nsync)

# hide all symbols by default
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(${CNK_PKCS_TARGET} PRIVATE "-fvisibility=hidden")
  target_compile_options(nsync PRIVATE "-fvisibility=hidden")
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
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
    EXPORT "$CNK_PKCS_LIB_NAME"
    RUNTIME
    LIBRARY
    ARCHIVE
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${CNK_PKCS_LIB_NAME}
)

# Add a simple test executable if testing is enabled
option(BUILD_TESTING "Build test programs" OFF)
if(BUILD_TESTING)
    add_executable(test_pkcs11 tests/test_pkcs11.c)
    target_link_libraries(test_pkcs11 ${CNK_PKCS_TARGET} ${CNK_PKCS_LIBS})
endif()
