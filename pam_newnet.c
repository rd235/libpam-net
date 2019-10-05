/* 
 * pam_newnet.
 * Copyright (C) 2016  Renzo Davoli, Eduard Caizer University of Bologna
 * 
 * pam_newnet module
 *   create a new network namespace at each login
 *   (for users belonging to the "newnet" group)
 *
 * Cado is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>. 
 *
 */

#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifdef PAM_LONET
#include <nlinline.h>
#define PAM_NET "lonet"
#else
#define PAM_NET "newnet"
#endif

#include <pam_net_checkgroup.h>

/**
 * init_log: log initialization with the given name
 */
void init_log(const char * log_name)
{
	setlogmask (LOG_UPTO (LOG_NOTICE));
	openlog (log_name, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
}

/**
 * end_log: closes the log previously initialized
 */
void end_log()
{
	closelog ();
}

/*
 * PAM entry point for session creation
 */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user;
	int rv;
	int isnewnet;

	init_log ("pam_" PAM_NET);
	if ((rv=pam_get_user(pamh, &user, NULL) != PAM_SUCCESS)) {
		syslog (LOG_ERR, "get user: %s", strerror(errno));
		goto close_log_and_exit;
	}

	isnewnet = checkgroup(user, PAM_NET);

	if (isnewnet > 0) {
		if (unshare(CLONE_NEWNET) < 0) {
			syslog (LOG_ERR, "Failed to create a new netns: %s", strerror(errno));
			goto close_log_and_abort;
		}
#ifdef PAM_LONET
		nlinline_linksetupdown(1, 1); // bring lo up
#endif
	} else
		rv=PAM_IGNORE;
close_log_and_exit:
	end_log();
	return rv;
close_log_and_abort:
	rv = PAM_ABORT;
	end_log();
	return rv;
}

/*
 * PAM entry point for session cleanup
 */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_IGNORE);
}

