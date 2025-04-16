find_package(PkgConfig REQUIRED)
pkg_check_modules(CMOCKA REQUIRED cmocka)
message(STATUS "CMocka found: includedir ${CMOCKA_INCLUDE_DIRS}, lib ${CMOCKA_LINK_LIBRARIES}")

include(AddCMockaTest)
include(AddMockedTest)

add_mocked_test(rsa_utils LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${MBEDTLS_LIBRARIES})
