add_executable(unit unit.c)
add_test(unit unit)
target_link_libraries(unit PRIVATE xor_singleheader)


# full warnings with sanitizers for tests. Include debug symbols and
# only -O2 to maintain some debugability. -Werror to
# prevent new warning creeping in Matches Makefile
if (MSVC)
  # limited support for MSVC, this is not tested
  list(APPEND TEST_COMPILE_OPTIONS /W4  /fsanitize=address)
else() # *nix
  list(APPEND TEST_COMPILE_OPTIONS -g -O2
  -fsanitize=address,leak,undefined
  -Wall -Wextra -Wshadow  -Wcast-qual -Wconversion -Wsign-conversion -Werror)

  if (NOT MINGW) # sanitizers are not supported under mingw
    list(APPEND TEST_COMPILE_OPTIONS -fsanitize=address,undefined,leak) 
    # sanitsizers need to be specified at link time as well
    target_link_options(unit PRIVATE -fsanitize=address,leak,undefined)
 endif()
endif()

target_compile_options(unit PRIVATE ${TEST_COMPILE_OPTIONS})

