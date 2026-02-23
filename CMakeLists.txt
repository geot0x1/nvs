cmake_minimum_required(VERSION 3.14)

project(nvs_lite_test LANGUAGES C)

# Enforce C11 across the whole build
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Common warning flags applied to every target in this project
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -O2
)

# Treat warnings as errors in CI / strict builds.
# Pass -DNVS_WERROR=ON to cmake to enable.
option(NVS_WERROR "Treat compiler warnings as errors" OFF)
if(NVS_WERROR)
    add_compile_options(-Werror)
endif()

# Enable verbose debug logging inside nvs_lite.
# Pass -DNVS_DEBUG_LOG=ON to cmake to enable.
option(NVS_DEBUG_LOG "Enable NVS verbose debug logging" OFF)
if(NVS_DEBUG_LOG)
    add_compile_definitions(NVS_DEBUG)
endif()

# Sub-libraries
add_subdirectory(flash_mem)
add_subdirectory(crc32)
add_subdirectory(nvs_lite)

# Test executable
add_executable(${PROJECT_NAME} main.c)
target_link_libraries(${PROJECT_NAME} PRIVATE flash_mem crc32 nvs_lite)

# CTest integration
enable_testing()
add_test(NAME smoke_test COMMAND ${PROJECT_NAME})
