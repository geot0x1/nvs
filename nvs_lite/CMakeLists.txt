add_library(nvs_lite STATIC nvs_lite.c)

target_include_directories(nvs_lite PUBLIC .)

target_link_libraries(nvs_lite PRIVATE crc32)
