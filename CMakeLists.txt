cmake_minimum_required(VERSION 3.0)
project("libpam-net"
		VERSION 0.1
		DESCRIPTION "create/join network namespaces at login"
		HOMEPAGE_URL "https://github.com/rd235/libpam-net"
    LANGUAGES C)

include(GNUInstallDirs)
include(CheckIncludeFile)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/nlinline)
set (CMAKE_REQUIRED_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/nlinline)

unset(NLINLINE_INCLUDE CACHE)
check_include_file(nlinline.h NLINLINE_INCLUDE)
if(NOT NLINLINE_INCLUDE)
  message(FATAL_ERROR "*** required nlinline.h include file not found.\nInstall nlinline: https://github.com/virtualsquare/nlinline")
endif()

if(LIBSECURITYDIR)
	set(CMAKE_INSTALL_PAMDIR ${LIBSECURITYDIR})
else()
	set(CMAKE_INSTALL_PAMDIR ${CMAKE_INSTALL_LIBDIR}/security)
endif()

add_library(pam_newnet SHARED pam_newnet.c pam_net_checkgroup.c)
set_target_properties(pam_newnet PROPERTIES PREFIX "")

add_library(pam_lonet SHARED pam_newnet.c pam_net_checkgroup.c)
set_target_properties(pam_lonet PROPERTIES PREFIX "")
target_compile_options(pam_lonet PRIVATE -DPAM_LONET)

add_library(pam_usernet SHARED pam_usernet.c pam_net_checkgroup.c)
set_target_properties(pam_usernet PROPERTIES PREFIX "")

install(TARGETS pam_newnet pam_lonet pam_usernet
		DESTINATION ${CMAKE_INSTALL_PAMDIR})

file(GLOB MAN8_PAGES ${CMAKE_CURRENT_SOURCE_DIR}/*.8)

install(FILES ${MAN8_PAGES}
	DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
