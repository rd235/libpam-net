#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libpam-net], [0.2], [info@v2.cs.unibo.it])
AM_INIT_AUTOMAKE([foreign dist-bzip2])
AC_CONFIG_SRCDIR([pam_newnet.c])
AC_CONFIG_HEADERS([config.h])
CFLAGS="$CFLAGS -Wall"
AC_ENABLE_SHARED(yes)
AC_ENABLE_STATIC(no)

AC_ARG_WITH([libsecuritydir],
		[AS_HELP_STRING([--with-libsecuritydir],
			[Directory for PAM modules, pass /lib/security for live install])],
		[], [with_libsecuritydir='$(libdir)/security'])
AC_SUBST([libsecuritydir], [$with_libsecuritydir])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

LT_INIT

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h syslog.h limits.h \
                  dirent.h sys/statvfs.h])
AC_CHECK_HEADERS([security/pam_modules.h security/pam_appl.h],
		[],
		[AC_MSG_ERROR([missing lbpam0g header])])


# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([strcmp])

AC_OUTPUT([Makefile])
