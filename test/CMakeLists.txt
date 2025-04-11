add_mocked_test(rsa_utils LINK_LIBRARIES ${CNK_PKCS_TARGET} ${CNK_PKCS_LIBS} ${MBEDTLS_LIBRARIES})
target_include_directories(test_rsa_utils PRIVATE /opt/homebrew/include)
target_link_libraries(test_rsa_utils PRIVATE /opt/homebrew/lib/libcmocka.dylib)