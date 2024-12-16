add_executable(unit unit.c)
add_test(unit unit)
target_link_libraries(unit PRIVATE xor_singleheader)
# full warnings with sanitizers for tests. Include debug symbols and
# only -O2 to maintain some debugability. -Werror to
# prevent new warning creeping in Matches Makefile
target_compile_options(unit PRIVATE -g -O2
  -fsanitize=address,leak,undefined
  -Wall -Wextra -Wshadow  -Wcast-qual -Wconversion -Wsign-conversion -Werror
  -lm)
