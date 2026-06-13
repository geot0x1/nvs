cmake_minimum_required(VERSION 4.2)

project(ctest LANGUAGES C)

# Use C11 standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    main.c
)

# Add subdirectories
add_subdirectory(flash_mem)
add_subdirectory(crc32)
add_subdirectory(nvs)

# Executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE flash_mem crc32 nvs)

# Basic compiler options for GCC
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -O2)
endif()

#============================================================================
# Issue-verification test suite (additive; does not affect the ctest target)
#============================================================================

# Orchestrator: runs Issues B, C, D, E, G, H inline and launches A/F children.
add_executable(test_nvs_issues tests/test_nvs_issues.c)
target_include_directories(test_nvs_issues PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_libraries(test_nvs_issues PRIVATE flash_mem crc32 nvs)

# Crash-type Issue A: oversized data_len -> stack overflow in nvs_read.
add_executable(test_issue_A tests/test_issue_A.c)
target_link_libraries(test_issue_A PRIVATE flash_mem crc32 nvs)

# Crash-type Issue F: sector_count > 16 -> fixed-array stack overflow.
add_executable(test_issue_F tests/test_issue_F.c)
target_link_libraries(test_issue_F PRIVATE crc32 nvs)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(test_nvs_issues PRIVATE -Wall -Wextra -O2 -fstack-protector-all)
    target_compile_options(test_issue_A   PRIVATE -Wall -Wextra -O2 -fstack-protector-all)
    target_compile_options(test_issue_F   PRIVATE -Wall -Wextra -O2 -fstack-protector-all)
endif()
