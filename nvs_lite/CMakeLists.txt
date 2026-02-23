add_library(nvs_lite STATIC nvs_lite.c)

target_include_directories(nvs_lite PUBLIC .)

# crc32 is a PRIVATE dependency: consumers of nvs_lite do not need to
# include crc32 headers directly.
target_link_libraries(nvs_lite PRIVATE crc32)
