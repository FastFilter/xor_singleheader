add_executable(bench bench.c)
target_link_libraries(bench PUBLIC xor_singleheader)

add_executable(spaceusage spaceusage.c)
target_link_libraries(spaceusage PUBLIC xor_singleheader)

add_executable(query query.c)
target_link_libraries(query PUBLIC xor_singleheader)