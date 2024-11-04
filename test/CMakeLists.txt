set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(pqot test-pqot.cpp)
target_link_libraries(pqot pq-ot)

find_package(OpenSSL REQUIRED) # newly added
include_directories(${OPENSSL_INCLUDE_DIR}) # newly added
target_link_libraries(pqot ${OPENSSL_LIBRARIES}) # newly added

macro (add_test _name)
	add_executable(${_name} "test-${_name}.cpp")
endmacro()
