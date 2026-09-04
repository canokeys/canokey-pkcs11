find_package(Threads REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

if (WIN32)
  # Windows builds use a native CMake package (vcpkg or an installed CMocka
  # build). Do not require the Unix pkg-config discovery layer or MinGW CRT
  # libraries when compiling tests with MSVC/ClangCL.
  find_package(cmocka CONFIG REQUIRED)
  if (TARGET cmocka::cmocka)
    set(CMOCKA_LINK_LIBRARIES cmocka::cmocka)
    get_target_property(CMOCKA_INCLUDE_DIRS cmocka::cmocka INTERFACE_INCLUDE_DIRECTORIES)
  elseif (TARGET cmocka)
    set(CMOCKA_LINK_LIBRARIES cmocka)
    get_target_property(CMOCKA_INCLUDE_DIRS cmocka INTERFACE_INCLUDE_DIRECTORIES)
  else()
    message(FATAL_ERROR "CMocka package found without a cmocka target")
  endif()
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(CMOCKA REQUIRED cmocka)
endif()
message(STATUS "CMocka found: includedir ${CMOCKA_INCLUDE_DIRS}, lib ${CMOCKA_LINK_LIBRARIES}")

include(AddCMockaTest)
include(AddMockedTest)

add_mocked_test(rsa LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${CNK_CRYPTO_LIBRARIES})
target_compile_definitions(test_rsa PRIVATE "MBEDTLS_ALLOW_PRIVATE_ACCESS")
add_mocked_test(digest LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${CNK_CRYPTO_LIBRARIES})
add_mocked_test(policy LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${CNK_CRYPTO_LIBRARIES})
add_mocked_test(session LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${CNK_CRYPTO_LIBRARIES} Threads::Threads)
add_mocked_test(piv_object LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${CNK_CRYPTO_LIBRARIES})
add_mocked_test(mutex LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${CNK_CRYPTO_LIBRARIES})

add_test(
  NAME test_api_contracts
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/check-api-contracts.py")
