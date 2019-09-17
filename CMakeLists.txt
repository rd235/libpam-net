cmake_minimum_required(VERSION 2.6)
project("libpam-net"
			LANGUAGES C)

include(GNUInstallDirs)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(pam_newnet SHARED pam_newnet.c pam_net_checkgroup.c)

add_library(pam_usernet SHARED pam_usernet.c pam_net_checkgroup.c)

install(TARGETS pam_newnet pam_usernet
		DESTINATION lib/${CMAKE_LIBRARY_ARCHITECTURE}/security)

file(GLOB MAN8_PAGES ${CMAKE_CURRENT_SOURCE_DIR}/*.8)

install(FILES ${MAN8_PAGES}
	DESTINATION share/man/man8)
