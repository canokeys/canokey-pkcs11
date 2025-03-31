cmake_minimum_required(VERSION 3.10)
project(canokey_pkcs11 VERSION 0.1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include project directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Configure nsync from submodule
add_subdirectory(external/nsync)

# Add nsync include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/nsync/public)

# On macOS, PC/SC is provided by the PCSC framework
if(APPLE)
  # Create shared library
  add_library(canokey_pkcs11 SHARED canokey.c pkcs11.c pkcs11_session.c)
  
  # Link against the PCSC framework on macOS
  find_library(PCSC_FRAMEWORK PCSC)
  if(NOT PCSC_FRAMEWORK)
    message(FATAL_ERROR "PCSC framework not found")
  endif()
  target_link_libraries(canokey_pkcs11 ${PCSC_FRAMEWORK} nsync)
else()
  # For non-macOS platforms, use pkg-config to find libpcsclite
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(PCSC REQUIRED libpcsclite)
  
  # Add include directories
  include_directories(${PCSC_INCLUDE_DIRS})
  
  # Create shared library
  add_library(canokey_pkcs11 SHARED canokey.c pkcs11.c pkcs11_session.c)
  
  # Link against PC/SC library
  target_link_libraries(canokey_pkcs11 ${PCSC_LIBRARIES} nsync)
endif()

# Set library properties
set_target_properties(canokey_pkcs11 PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    OUTPUT_NAME "canokey-pkcs11"
    PREFIX "lib"
)

# Install the library
install(TARGETS canokey_pkcs11
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

# Install header files
install(FILES pkcs11.h pkcs11_session.h canokey.h DESTINATION include/canokey-pkcs11)

# Add a simple test executable if testing is enabled
option(BUILD_TESTING "Build test programs" OFF)
if(BUILD_TESTING)
    add_executable(test_pkcs11 test_pkcs11.c)
    target_link_libraries(test_pkcs11 canokey_pkcs11 nsync)
endif()
