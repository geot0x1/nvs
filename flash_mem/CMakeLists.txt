add_library(flash_mem STATIC flash_mem.c)

target_include_directories(flash_mem PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
