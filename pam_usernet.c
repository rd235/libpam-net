/* 
 * pam_usernet.
 * Copyright (C) 2016  Renzo Davoli, Eduard Caizer University of Bologna
 * Copyright (C) 2011-2017 The iproute2 Authors
 * Copyright (C) 2018  Daniel Gröber
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
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <pam_net_checkgroup.h>

#define NSDIR "/var/run/netns/"
#define NETNS_ETC_DIR "/etc/netns"

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

/**
 * bind_etc: Mount files from /etc/netns into current namespace
 */
void bind_etc(const char *name)
{
	char etc_netns_path[sizeof(NETNS_ETC_DIR) + NAME_MAX];
	char netns_name[PATH_MAX];
	char etc_name[PATH_MAX];
	struct dirent *entry;
	DIR *dir;

	if (strlen(name) >= NAME_MAX)
		return;

	snprintf(etc_netns_path, sizeof(etc_netns_path), "%s/%s", NETNS_ETC_DIR, name);
	dir = opendir(etc_netns_path);
	if (!dir)
		return;

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0)
			continue;
		if (strcmp(entry->d_name, "..") == 0)
			continue;
		snprintf(netns_name, sizeof(netns_name), "%s/%s", etc_netns_path, entry->d_name);
		snprintf(etc_name, sizeof(etc_name), "/etc/%s", entry->d_name);
		if (mount(netns_name, etc_name, "none", MS_BIND, NULL) < 0) {
			syslog (LOG_ERR, "Bind %s -> %s failed: %s\n",
				netns_name, etc_name, strerror(errno));
		}
	}
	closedir(dir);
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

		if (unshare(CLONE_NEWNS) < 0) {
			syslog (LOG_ERR, "unshare failed: %s\n", strerror(errno));
			goto close_log_and_abort;
		}
		/* Don't let any mounts propagate back to the parent */
		if (mount("", "/", "none", MS_SLAVE | MS_REC, NULL)) {
			fprintf(stderr, "\"mount --make-rslave /\" failed: %s\n",
				strerror(errno));
			goto close_log_and_abort;
		}

		/* Mount a version of /sys that describes the network namespace */
		unsigned long mountflags = 0;

		if (umount2("/sys", MNT_DETACH) < 0) {
			struct statvfs fsstat;

			/* If this fails, perhaps there wasn't a sysfs instance mounted. Good. */
			if (statvfs("/sys", &fsstat) == 0) {
				/* We couldn't umount the sysfs, we'll attempt to overlay it.
				 * A read-only instance can't be shadowed with a read-write one. */
				if (fsstat.f_flag & ST_RDONLY)
					mountflags = MS_RDONLY;
			}
		}
		if (mount(user, "/sys", "sysfs", mountflags, NULL) < 0) {
			syslog (LOG_ERR, "mount of /sys failed: %s\n", strerror(errno));
			goto close_log_and_abort;
		}

		/* Setup bind mounts for config files in /etc */
		bind_etc(user);
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

