cmake_minimum_required(VERSION 3.12)
project(mcuhttp_tests)

set(SOURCES 
	mcuhttp.h
	mcuhttp.c
	mcusock.h
	mcusock.c)

if (MCUHTTP_ENABLE_SSL)
	set(SOURCES ${SOURCES} mcussl.h mcussl.c)

	if (APPLE)
		include_directories(/usr/local/opt/mbedtls/include)
		link_directories(/usr/local/opt/mbedtls/lib)
	endif(APPLE)
	add_definitions(-DMCUHTTP_ENABLE_SSL=1)
endif(MCUHTTP_ENABLE_SSL)

add_library(mcuhttp ${SOURCES})
