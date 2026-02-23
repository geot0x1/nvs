add_library(crc32 STATIC crc32.c)

target_include_directories(crc32 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
