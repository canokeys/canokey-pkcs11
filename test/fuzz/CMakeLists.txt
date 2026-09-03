set(CNK_FUZZ_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)

add_executable(cnk_fuzz_tlv fuzz_tlv.c ${CMAKE_CURRENT_SOURCE_DIR}/../../src/internal/util.c)
target_include_directories(cnk_fuzz_tlv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                                                  ${CMAKE_CURRENT_SOURCE_DIR}/../../include/private)
target_compile_options(cnk_fuzz_tlv PRIVATE ${CNK_FUZZ_FLAGS})
target_link_options(cnk_fuzz_tlv PRIVATE ${CNK_FUZZ_FLAGS})

add_executable(cnk_fuzz_api fuzz_api.c)
target_compile_definitions(cnk_fuzz_api PRIVATE CNK_LIB_SHARED)
target_link_libraries(cnk_fuzz_api PRIVATE ${CNK_PKCS_TARGET})
target_compile_options(cnk_fuzz_api PRIVATE ${CNK_FUZZ_FLAGS})
target_link_options(cnk_fuzz_api PRIVATE ${CNK_FUZZ_FLAGS})
set_target_properties(cnk_fuzz_api PROPERTIES BUILD_RPATH "$ORIGIN")

add_test(NAME fuzz_tlv_smoke COMMAND cnk_fuzz_tlv -runs=100)
add_test(NAME fuzz_api_smoke COMMAND cnk_fuzz_api -runs=100)
