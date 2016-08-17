/* 
 * pam_usernet.
 * Copyright (C) 2016  Renzo Davoli, Eduard Caizer University of Bologna
 * 
 * pam_usernet module
 *    provide each user with their own network
 *   (for users belonging to the "usernet" group)
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

#define _GNU_SOURCE
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <pam_net_checkgroup.h>

#define NSDIR "/var/run/netns/"

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
	int isusernet;

	init_log ("pam_usernet");
	if ((rv=pam_get_user(pamh, &user, NULL) != PAM_SUCCESS)) {
		syslog (LOG_ERR, "get user: %s", strerror(errno));
		goto close_log_and_exit;
	}

	isusernet = checkgroup(user, "usernet");

	if (isusernet > 0) {
		int nsfd;
		size_t ns_pathlen=sizeof(NSDIR)+strlen(user)+1;
		char ns_path[ns_pathlen];

		if (mkdir(NSDIR, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)) {
			if (errno != EEXIST) {
					syslog (LOG_ERR, "cannot create netns dir %s: %s",NSDIR, strerror(errno));
					goto close_log_and_abort;
			}
		}
		if (mount("", NSDIR, "none", MS_SHARED | MS_REC, NULL)) {
			if (errno != EINVAL) {
				syslog (LOG_ERR, "mount --make-shared %s: %s",NSDIR, strerror(errno));
				goto close_log_and_abort;
			}
			if (mount(NSDIR, NSDIR, "none", MS_BIND, NULL)) {
				syslog (LOG_ERR, "mount --bind %s: %s",NSDIR, strerror(errno));
				goto close_log_and_abort;
			}
			if (mount("", NSDIR, "none", MS_SHARED | MS_REC, NULL)) {
				syslog (LOG_ERR, "mount --make-shared after bind %s: %s",NSDIR, strerror(errno));
				goto close_log_and_abort;
			}
		}

		snprintf(ns_path,ns_pathlen,NSDIR "%s",user);
		if ((nsfd = open(ns_path, O_RDONLY)) < 0) {
			if (errno == ENOENT) {
				if ((nsfd = open(ns_path, O_RDONLY|O_CREAT|O_EXCL, 0)) < 0) {
					syslog (LOG_ERR, "cannot create netns %s: %s",ns_path, strerror(errno));
					goto close_log_and_abort;
				}
				close(nsfd);
				if (unshare(CLONE_NEWNET) < 0) {
					syslog (LOG_ERR, "Failed to create a new netns %s: %s",ns_path, strerror(errno));
					goto close_log_and_abort;
				}
				if (mount("/proc/self/ns/net", ns_path, "none", MS_BIND, NULL) < 0) {
					syslog (LOG_ERR, "mount /proc/self/ns/net -> %s failed: %s",ns_path, strerror(errno));
					goto close_log_and_abort;
				}
			} else {
				syslog (LOG_ERR, "netns open failed %s",ns_path);
				goto close_log_and_abort;
			}
		} else {
			if (setns(nsfd, CLONE_NEWNET) != 0) {
				syslog (LOG_ERR, "cannot join netns %s: %s",ns_path, strerror(errno));
				close(nsfd);
				goto close_log_and_abort;
			}
			close(nsfd);
			if (unshare(CLONE_NEWNS) < 0) {
				syslog (LOG_ERR, "unshare failed: %s", strerror(errno));
				goto close_log_and_abort;
			}
		}
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

