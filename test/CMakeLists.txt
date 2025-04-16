find_package(CMocka REQUIRED)
message(STATUS "CMocka found: includedir ${CMOCKA_INCLUDE_DIR}, lib ${CMOCKA_LIBRARY}")

include(AddCMockaTest)
include(AddMockedTest)

add_executable(test_real test_real.c)
if (APPLE OR UNIX)
    target_link_libraries(test_real dl)
endif ()

add_executable(test_rsa test_rsa.c)
target_link_libraries(test_rsa ${MBEDTLS_LIBRARIES})
if (APPLE OR UNIX)
    target_link_libraries(test_rsa dl)
endif ()

add_mocked_test(rsa_utils LINK_LIBRARIES ${CNK_PKCS_TARGET}-test ${MBEDTLS_LIBRARIES})
