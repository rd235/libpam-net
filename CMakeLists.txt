cmake_minimum_required(VERSION 2.6)
project("libpam-net")

include(GNUInstallDirs)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if(LIBSECURITYDIR)
	set(CMAKE_INSTALL_PAMDIR ${LIBSECURITYDIR})
else()
	set(CMAKE_INSTALL_PAMDIR ${CMAKE_INSTALL_LIBDIR}/security)
endif()

add_library(pam_newnet SHARED pam_newnet.c pam_net_checkgroup.c)
set_target_properties(pam_newnet PROPERTIES PREFIX "")

add_library(pam_usernet SHARED pam_usernet.c pam_net_checkgroup.c)
set_target_properties(pam_usernet PROPERTIES PREFIX "")

install(TARGETS pam_newnet pam_usernet
		DESTINATION ${CMAKE_INSTALL_PAMDIR})

file(GLOB MAN8_PAGES ${CMAKE_CURRENT_SOURCE_DIR}/*.8)

install(FILES ${MAN8_PAGES}
	DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)