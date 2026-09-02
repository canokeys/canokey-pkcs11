find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
pkg_check_modules(CMOCKA REQUIRED cmocka)
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
