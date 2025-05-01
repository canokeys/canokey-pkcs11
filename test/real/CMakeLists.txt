function(add_dlopen_test NAME)
  add_executable(test_${NAME} test_${NAME}.c)
  target_link_libraries(test_${NAME} PRIVATE ${ARGN})
  if(APPLE OR UNIX)
    target_link_libraries(test_${NAME} PRIVATE dl)
  endif()
endfunction()

add_dlopen_test(real)
