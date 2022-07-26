include_directories (${PROJECT_SOURCE_DIR}/src/) 

add_executable(pac.out pac.c)
target_link_libraries(pac.out onion)