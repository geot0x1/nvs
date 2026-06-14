cmake_minimum_required(VERSION 4.2)

project(ctest LANGUAGES C)

# Use C11 standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    main.c
    tests/test_stress.c
    tests/test_edge_cases.c
    tests/test_nvs_robustness.c
    tests/test_vuln_toctou.c
)

# Add subdirectories
add_subdirectory(flash_mem)
add_subdirectory(crc32)
add_subdirectory(nvs)

# Executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE flash_mem crc32 nvs)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

# Basic compiler options for GCC
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -O2 -fstack-protector-all)
endif()
