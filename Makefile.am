AM_LIBTOOLFLAGS = --quiet

libsecurity_LTLIBRARIES = pam_newnet.la pam_usernet.la

pam_newnet_la_SOURCES = pam_newnet.c pam_net_checkgroup.c
pam_newnet_la_LDFLAGS = -module -avoid-version

pam_usernet_la_SOURCES = pam_usernet.c pam_net_checkgroup.c
pam_usernet_la_LDFLAGS = -module -avoid-version $(libnl_route_3_0_LIBS)
pam_usernet_la_CFLAGS = $(libnl_route_3_0_CFLAGS)

man_MANS = pam_newnet.8 pam_usernet.8

install-data-hook:
	@(cd $(DESTDIR)$(libsecuritydir) && $(RM) $(libsecurity_LTLIBRARIES))

