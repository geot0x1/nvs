add_library(nvs nvs.c)
target_include_directories(nvs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(nvs PRIVATE flash_mem crc32)
