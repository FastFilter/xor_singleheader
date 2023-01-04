add_executable(unit unit.c)
add_test(unit unit)
target_link_libraries(unit PUBLIC xor_singleheader)
