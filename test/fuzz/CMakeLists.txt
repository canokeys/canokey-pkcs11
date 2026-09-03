if (WIN32 OR APPLE)
  # The Windows and Apple toolchains used by CI do not ship a usable
  # clang_rt.fuzzer runtime. Both use the bounded replay/mutation main below;
  # the Linux job provides native libFuzzer plus sanitizer diagnostics.
  set(CNK_FUZZ_FLAGS)
  set(CNK_REPLAY_MAIN fuzz_main_replay.c)
else()
  set(CNK_FUZZ_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
  set(CNK_REPLAY_MAIN)
endif()

add_executable(cnk_fuzz_tlv fuzz_tlv.c ${CNK_REPLAY_MAIN}
                                      ${CMAKE_CURRENT_SOURCE_DIR}/../../src/internal/util.c)
target_include_directories(cnk_fuzz_tlv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                                                  ${CMAKE_CURRENT_SOURCE_DIR}/../../include/private)
target_compile_options(cnk_fuzz_tlv PRIVATE ${CNK_FUZZ_FLAGS})
target_link_options(cnk_fuzz_tlv PRIVATE ${CNK_FUZZ_FLAGS})

add_executable(cnk_fuzz_api fuzz_api.c ${CNK_REPLAY_MAIN})
target_compile_definitions(cnk_fuzz_api PRIVATE CNK_LIB_SHARED)
target_link_libraries(cnk_fuzz_api PRIVATE ${CNK_PKCS_TARGET})
target_compile_options(cnk_fuzz_api PRIVATE ${CNK_FUZZ_FLAGS})
target_link_options(cnk_fuzz_api PRIVATE ${CNK_FUZZ_FLAGS})
set_target_properties(cnk_fuzz_api PROPERTIES BUILD_RPATH "$ORIGIN/../..")

find_package(Threads REQUIRED)
add_executable(cnk_fuzz_concurrency fuzz_concurrency.c ${CNK_REPLAY_MAIN})
target_compile_definitions(cnk_fuzz_concurrency PRIVATE CNK_LIB_SHARED)
target_link_libraries(cnk_fuzz_concurrency PRIVATE ${CNK_PKCS_TARGET} Threads::Threads)
target_compile_options(cnk_fuzz_concurrency PRIVATE ${CNK_FUZZ_FLAGS})
target_link_options(cnk_fuzz_concurrency PRIVATE ${CNK_FUZZ_FLAGS})
set_target_properties(cnk_fuzz_concurrency PROPERTIES BUILD_RPATH "$ORIGIN/../..")

add_executable(cnk_fuzz_pcsc fuzz_pcsc.c ${CNK_REPLAY_MAIN})
target_compile_definitions(cnk_fuzz_pcsc PRIVATE CNK_LIB_SHARED CNK_TEST_TRANSPORT CNK_REPLAY_HAS_INITIALIZER)
target_link_libraries(cnk_fuzz_pcsc PRIVATE ${CNK_PKCS_TARGET})
target_compile_options(cnk_fuzz_pcsc PRIVATE ${CNK_FUZZ_FLAGS})
target_link_options(cnk_fuzz_pcsc PRIVATE ${CNK_FUZZ_FLAGS})
set_target_properties(cnk_fuzz_pcsc PROPERTIES BUILD_RPATH "$ORIGIN/../..")
if (WIN32)
  add_custom_command(TARGET cnk_fuzz_api POST_BUILD
                     COMMAND ${CMAKE_COMMAND} -E copy_if_different
                             "$<TARGET_FILE:${CNK_PKCS_TARGET}>"
                             "$<TARGET_FILE_DIR:cnk_fuzz_api>")
  add_custom_command(TARGET cnk_fuzz_concurrency POST_BUILD
                     COMMAND ${CMAKE_COMMAND} -E copy_if_different
                             "$<TARGET_FILE:${CNK_PKCS_TARGET}>"
                             "$<TARGET_FILE_DIR:cnk_fuzz_concurrency>")
  add_custom_command(TARGET cnk_fuzz_pcsc POST_BUILD
                     COMMAND ${CMAKE_COMMAND} -E copy_if_different
                             "$<TARGET_FILE:${CNK_PKCS_TARGET}>"
                             "$<TARGET_FILE_DIR:cnk_fuzz_pcsc>")
endif()

add_test(NAME fuzz_tlv_smoke COMMAND cnk_fuzz_tlv -runs=100)
add_test(NAME fuzz_api_smoke COMMAND cnk_fuzz_api -runs=100)
add_test(NAME fuzz_concurrency_smoke COMMAND cnk_fuzz_concurrency -runs=20)
add_test(NAME fuzz_pcsc_smoke COMMAND cnk_fuzz_pcsc -runs=20)
