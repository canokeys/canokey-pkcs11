include(AddCMockaTest)
include(AddMockedTest)
find_package(CMocka CONFIG REQUIRED)

add_executable(test_real test_real.c)
if (APPLE OR UNIX)
    target_link_libraries(test_real dl)
endif ()

add_mocked_test(rsa_utils LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${MBEDTLS_LIBRARIES})
target_link_libraries(test_rsa_utils PRIVATE cmocka::cmocka)