find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(CMOCKA REQUIRED cmocka)
message(STATUS "CMocka found: includedir ${CMOCKA_INCLUDE_DIRS}, lib ${CMOCKA_LINK_LIBRARIES}")

include(AddCMockaTest)
include(AddMockedTest)

add_mocked_test(rsa LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${CNK_CRYPTO_LIBRARIES})
target_compile_definitions(test_rsa PRIVATE "MBEDTLS_ALLOW_PRIVATE_ACCESS")
add_mocked_test(digest LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${CNK_CRYPTO_LIBRARIES})
add_mocked_test(policy LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${CNK_CRYPTO_LIBRARIES})
add_mocked_test(session LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${CNK_CRYPTO_LIBRARIES} Threads::Threads)
