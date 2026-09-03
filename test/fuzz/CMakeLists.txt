if (WIN32)
  # Visual Studio's ClangCL package does not ship clang_rt.fuzzer. Windows
  # therefore uses the bounded replay/mutation main below; Linux and macOS
  # use the native libFuzzer driver and sanitizer runtime.
  set(CNK_FUZZ_FLAGS)
  set(CNK_WINDOWS_FUZZ_MAIN fuzz_main_windows.c)
else()
  set(CNK_FUZZ_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
  set(CNK_WINDOWS_FUZZ_MAIN)
endif()

add_executable(cnk_fuzz_tlv fuzz_tlv.c ${CNK_WINDOWS_FUZZ_MAIN}
                                      ${CMAKE_CURRENT_SOURCE_DIR}/../../src/internal/util.c)
target_include_directories(cnk_fuzz_tlv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                                                  ${CMAKE_CURRENT_SOURCE_DIR}/../../include/private)
target_compile_options(cnk_fuzz_tlv PRIVATE ${CNK_FUZZ_FLAGS})
target_link_options(cnk_fuzz_tlv PRIVATE ${CNK_FUZZ_FLAGS})

add_executable(cnk_fuzz_api fuzz_api.c ${CNK_WINDOWS_FUZZ_MAIN})
target_compile_definitions(cnk_fuzz_api PRIVATE CNK_LIB_SHARED)
target_link_libraries(cnk_fuzz_api PRIVATE ${CNK_PKCS_TARGET})
target_compile_options(cnk_fuzz_api PRIVATE ${CNK_FUZZ_FLAGS})
target_link_options(cnk_fuzz_api PRIVATE ${CNK_FUZZ_FLAGS})
set_target_properties(cnk_fuzz_api PROPERTIES BUILD_RPATH "$ORIGIN")
if (WIN32)
  add_custom_command(TARGET cnk_fuzz_api POST_BUILD
                     COMMAND ${CMAKE_COMMAND} -E copy_if_different
                             "$<TARGET_FILE:${CNK_PKCS_TARGET}>"
                             "$<TARGET_FILE_DIR:cnk_fuzz_api>")
endif()

add_test(NAME fuzz_tlv_smoke COMMAND cnk_fuzz_tlv -runs=100)
add_test(NAME fuzz_api_smoke COMMAND cnk_fuzz_api -runs=100)
