cmake_minimum_required(VERSION 3.15)

project(test_install VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
find_package(xor_singleheader REQUIRED)



file(WRITE main.c "
#include <binaryfusefilter.h>
#include <xorfilter.h>
#include <stdlib.h>
 
int main() {
    uint64_t big_set[3] = {1,2,3};
    binary_fuse8_t filter;
    bool is_ok = binary_fuse8_allocate(3, &filter);
    if(! is_ok ) {
       // do something (you have run out of memory)
   }
   is_ok = binary_fuse8_populate(big_set, 3, &filter);
   if(! is_ok ) {
        // do something (you have run out of memory)
    }
    binary_fuse8_contain(big_set[0], &filter); // will be true
    binary_fuse8_contain(32132, &filter); // will be false with high probability
    binary_fuse8_free(&filter);

    return EXIT_SUCCESS;
}")



add_executable(repro main.c)
target_link_libraries(repro PUBLIC xor_singleheader::xor_singleheader)