cmake_minimum_required(VERSION 3.12)
project(mcuhttp_tests)

set(MCUHTTP_ENABLE_SSL 1)

add_subdirectory(src)
include_directories(src)

set(RESOURCES tests/Lenna.png tests/index.html)

set(SOURCES
	tests/test-certs.h
	tests/test-resources.h
	tests/tests.c)

foreach(RES ${RESOURCES})
	set(RESOURCES_ ${RESOURCES_} ${CMAKE_CURRENT_SOURCE_DIR}/${RES})
endforeach()

add_custom_command(
	OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/tests/test-resources.h
	COMMAND python2 ${CMAKE_CURRENT_SOURCE_DIR}/mcuhttp.py -g -r -o ${CMAKE_CURRENT_SOURCE_DIR}/tests/test-resources.h ${RESOURCES_}
	DEPENDS ${RESOURCES_})

if (APPLE)
	include_directories(/usr/local/opt/mbedtls/include)
	link_directories(/usr/local/opt/mbedtls/lib)
endif(APPLE)

add_executable(mcuhttp_tests ${SOURCES})
target_link_libraries(mcuhttp_tests mcuhttp mbedtls mbedx509 mbedcrypto)
