cmake_minimum_required(VERSION 3.10)

project(xor_singleheader VERSION 1.1.0 LANGUAGES C)

include(CTest)

if (BUILD_TESTING)
  message(STATUS "The tests are enabled.")
  add_subdirectory(tests)
endif(BUILD_TESTING)
add_subdirectory(benchmarks)

if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, default to Release")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()


include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

add_library(xor_singleheader INTERFACE)
add_library(xor_singleheader::xor_singleheader ALIAS xor_singleheader)

find_library(MATH_LIBRARY m)
if(MATH_LIBRARY)
    target_link_libraries(xor_singleheader INTERFACE ${MATH_LIBRARY})
endif()

target_include_directories(
  xor_singleheader
  INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(xor_singleheader INTERFACE c_std_99)

include(CMakePackageConfigHelpers)

set(xor_singleheader_VERSION_CONFIG "${CMAKE_CURRENT_BINARY_DIR}/module/xor_singleheaderConfigVersion.cmake")
set(xor_singleheader_PROJECT_CONFIG "${CMAKE_CURRENT_BINARY_DIR}/module/xor_singleheaderConfig.cmake")
set(xor_singleheader_CONFIG_INSTALL_DIR "${CMAKE_INSTALL_DATAROOTDIR}/cmake/xor_singleheader")

if(${CMAKE_VERSION} VERSION_LESS "3.14")
    write_basic_package_version_file("${xor_singleheader_VERSION_CONFIG}" VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
else()
    write_basic_package_version_file("${xor_singleheader_VERSION_CONFIG}" VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion ARCH_INDEPENDENT)
endif()
configure_package_config_file("cmake/config.cmake.in"
                                "${xor_singleheader_PROJECT_CONFIG}"
                                INSTALL_DESTINATION "${xor_singleheader_CONFIG_INSTALL_DIR}")

#install(DIRECTORY "${PROJECT_SOURCE_DIR}/include" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(FILES "${xor_singleheader_PROJECT_CONFIG}" "${xor_singleheader_VERSION_CONFIG}" DESTINATION "${xor_singleheader_CONFIG_INSTALL_DIR}")
install(EXPORT ${PROJECT_NAME}-targets NAMESPACE xor_singleheader:: DESTINATION "${xor_singleheader_CONFIG_INSTALL_DIR}")

install(
    FILES include/binaryfusefilter.h include/xorfilter.h
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    COMPONENT xor_singleheader
)

#install(
#    DIRECTORY include/simdutf
#    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
#    COMPONENT xor_singleheader
#)

install(TARGETS xor_singleheader
          EXPORT ${PROJECT_NAME}-targets
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
