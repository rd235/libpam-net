/*
 * pam_usernet.
 * Copyright (C) 2017-2019  Renzo Davoli University of Bologna
 * Copyright (C) 2018-2019  Daniel Gröber
 * Copyright (C) 2016  Renzo Davoli, Eduard Caizer University of Bologna
 * Copyright (C) 2011-2017 The iproute2 Authors
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

#include <stdio.h>
#include <stdlib.h>
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
#include <nlinline.h>

#define DEFAULT_GROUP "usernet"
#define NETNS_RUN_DIR "/var/run/netns/"
#define NETNS_ETC_DIR "/etc/netns"

/**
 * module args:
 * lodown, rootshared, group=....
 */
struct pam_net_args {
	const char *group;
	int flags;
};
#define LODOWN 0x1
#define ROOTSHARED 0x2

/**
 * parse_argv: parse module arguments
 */
static void parse_argv(struct pam_net_args *args, int argc, const char **argv) {
	for(; argc-- > 0; argv++) {
		if (strcmp(*argv, "lodown") == 0)
			args->flags |= LODOWN;
		else if (strcmp(*argv, "rootshared") == 0)
			args->flags |= ROOTSHARED;
		else if (strncmp(*argv, "group=", 6) == 0)
			args->group = (*argv) + 6;
		else
			syslog (LOG_ERR, "Unknown option: %s", *argv);
	}
}

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
 * bind_etc: Mount config files from /etc/netns/<name>/ into current namespace.
 */
int bind_etc(const char *name, int flags)
{
	int rv = 0;
	char etc_netns_path[sizeof(NETNS_ETC_DIR) + NAME_MAX];
	char netns_name[PATH_MAX];
	char etc_name[PATH_MAX];
	struct dirent *entry;
	DIR *dir;

	if (flags & ROOTSHARED) {
		/* ROOTSHARED */

		/* Make /etc a mount point, so we can apply a propagation policy to it
		 * below */
		rv = mount("/etc", "/etc", "none", MS_BIND, NULL);
		if (rv == -1) {
			syslog (LOG_ERR, "mount --bind %s %s: %s",
					etc_netns_path, etc_netns_path, strerror(errno));
			return -1;
		}

		/* Don't let bind mounts from /etc/netns/<name>/<file> -> /etc/<file>
		 * propagate back to the parent namespace */
		if (mount("", "/etc", "none", MS_PRIVATE, NULL)) {
			syslog (LOG_ERR, "\"mount --make-private /%s\" failed: %s\n",
					etc_netns_path, strerror(errno));
			return -1;
		}
	}

	snprintf(etc_netns_path, sizeof(etc_netns_path), "%s/%s", NETNS_ETC_DIR, name);
	dir = opendir(etc_netns_path);
	if (!dir)
		return errno == ENOENT ? 0 : -1;

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0)
			continue;
		if (strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(netns_name, sizeof(netns_name), "%s/%s", etc_netns_path, entry->d_name);
		snprintf(etc_name, sizeof(etc_name), "/etc/%s", entry->d_name);
		if (mount(netns_name, etc_name, "none", MS_BIND, NULL) < 0) {
			syslog (LOG_ERR, "Bind %s -> %s failed: %s",
					netns_name, etc_name, strerror(errno));
		}
	}

	closedir(dir);
	return 0;
}

/**
 * remount_sys: Mount a version of /sys that describes the new network namespace
 */
int remount_sys(const char *name, int flags)
{
	unsigned long mountflags = MS_NOSUID | MS_NOEXEC | MS_NODEV;

	if ((flags & ROOTSHARED) == 0) {
		/* DEFAULT behavior: NOT ROOTSHARED */
		/* Don't let any mounts propagate back to the parent */
		if (mount("", "/", "none", MS_SLAVE | MS_REC, NULL)) {
			fprintf(stderr, "\"mount --make-rslave /\" failed: %s\n",
					strerror(errno));
			return -1;
		}
	} else {
		/* ROOTSHARED */
		/* Make /sys private so the remounting below doesn't
                 * propagate to the parent namespace, since we're leaving
                 * the root directory shared */
		if (mount("", "/sys", "none", MS_PRIVATE | MS_REC, NULL)) {
			syslog (LOG_ERR, "\"mount --make-rprivate /sys\" failed: %s\n",
					strerror(errno));
			return -1;
		}
	}

	/* Mount a version of /sys that describes the network namespace */
	if (umount2("/sys", MNT_DETACH) < 0) {
		struct statvfs fsstat;

		/* If this fails, perhaps there wasn't a sysfs instance
		 * mounted. Good. */
		if (statvfs("/sys", &fsstat) == 0) {
			/* We couldn't umount the sysfs, we'll attempt to
			 * overlay it. A read-only instance can't be shadowed
			 * with a read-write one. */
			if (fsstat.f_flag & ST_RDONLY)
				mountflags |= MS_RDONLY;
		}
	}

	if (mount(name, "/sys", "sysfs", mountflags, NULL) < 0) {
		syslog (LOG_ERR, "mount of /sys failed: %s", strerror(errno));
		return -1;
	}

	if (mount("cgroup2", "/sys/fs/cgroup", "cgroup2", mountflags, NULL) < 0) {
		syslog (LOG_ERR, "mount of /sys/fs/cgroup failed: %s", strerror(errno));
		return -1;
	}

	return 0;
}

/**
 * create_netns_rundir: Create /var/run/netns mount if it doesn't exist yet.
 */
int create_netns_rundir(void)
{
	int rv = 0;

	rv = mkdir(NETNS_RUN_DIR, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	if (rv == -1 && errno != EEXIST) {
		syslog (LOG_ERR, "cannot create netns dir %s: %s",
				NETNS_RUN_DIR, strerror(errno));
		return -1;
	}

	rv = mount("", NETNS_RUN_DIR, "none", MS_SHARED | MS_REC, NULL);
	if (rv == 0) {
		return 0;
	}

	if (errno != EINVAL) {
		syslog (LOG_ERR, "mount --make-shared %s: %s",
				NETNS_RUN_DIR, strerror(errno));
		return -1;
	}

	rv = mount(NETNS_RUN_DIR, NETNS_RUN_DIR, "none", MS_BIND, NULL);
	if (rv == -1) {
		syslog (LOG_ERR, "mount --bind %s: %s",
				NETNS_RUN_DIR, strerror(errno));
		return -1;
	}

	rv = mount("", NETNS_RUN_DIR, "none", MS_SHARED | MS_REC, NULL);
	if (rv == -1) {
		syslog (LOG_ERR, "mount --make-shared after bind %s: %s",
				NETNS_RUN_DIR, strerror(errno));
		return -1;
	}

	return 0;
}

/**
 * unshare_netns: Create new netns, including mounting the handle to ns_path.
 */
int unshare_netns(char *ns_path, int flags)
{
	int rv;
	int nsfd;

	nsfd = open(ns_path, O_RDONLY|O_CREAT|O_EXCL, 0);
	if (nsfd < 0) {
		syslog (LOG_ERR, "cannot create netns %s: %s",
				ns_path, strerror(errno));
		return -1;
	}

	close(nsfd);

	rv = unshare(CLONE_NEWNET);
	if (rv < 0) {
		syslog (LOG_ERR, "Failed to create a new netns %s: %s",
				ns_path, strerror(errno));
		return -1;
	}

	rv = mount("/proc/self/ns/net", ns_path, "none", MS_BIND, NULL);
	if (rv == -1) {
		syslog (LOG_ERR, "mount /proc/self/ns/net -> %s failed: %s",
				ns_path, strerror(errno));
		return -1;
	}

	if ((flags & LODOWN) == 0)
		nlinline_linksetupdown(1, 1); // bring lo up

	return nsfd;
}

/**
 * enter_netns: Ensure we are in the netns referred to by ns_path, either by
 * creating it or entering it if it already exists.
 */
int enter_netns(char *ns_path, int flags)
{
	int nsfd;
	nsfd = open(ns_path, O_RDONLY);
	if (nsfd < 0) {
		if (errno == ENOENT) {
			unshare_netns(ns_path, flags);
		} else {
			syslog (LOG_ERR, "netns open failed %s", ns_path);
			return -1;
		}
	} else {
		if (setns(nsfd, CLONE_NEWNET) != 0) {
			syslog (LOG_ERR, "cannot join netns %s: %s",
					ns_path, strerror(errno));
			close(nsfd);
			return -1;
		}
		close(nsfd);
	}

	return 0;
}

/*
 * PAM entry point for session creation
 */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user;
	int rv;
	int isusernet;
	char ns_path[PATH_MAX];
	struct pam_net_args pam_args = {
		.group = DEFAULT_GROUP,
		.flags = 0};

	init_log ("pam_usernet");

	parse_argv(&pam_args, argc, argv);

	if ((rv=pam_get_user(pamh, &user, NULL) != PAM_SUCCESS)) {
		syslog (LOG_ERR, "get user: %s", strerror(errno));
		end_log();
		return PAM_SUCCESS;
	}

	isusernet = checkgroup(user, pam_args.group);
	if(isusernet <= 0) {
		end_log();
		return PAM_IGNORE;
	}

	if (create_netns_rundir() == -1)
		goto close_log_and_abort;

	snprintf(ns_path, sizeof(ns_path), "%s/%s", NETNS_RUN_DIR, user);

	rv = enter_netns(ns_path, pam_args.flags);
	if(rv == -1)
		goto close_log_and_abort;

	if (unshare(CLONE_NEWNS) < 0) {
		syslog (LOG_ERR, "unshare(mount) failed: %s", strerror(errno));
		goto close_log_and_abort;
	}

	if(remount_sys(user, pam_args.flags) == -1) {
		syslog (LOG_ERR, "remounting /sys failed");
		goto close_log_and_abort;
	}

	/* Setup bind mounts for config files in /etc */
	if(bind_etc(user, pam_args.flags) == -1) {
		syslog (LOG_ERR, "mounting /etc/netns/%s config files failed",
				user);
		goto close_log_and_abort;
	}

	end_log();
	return PAM_SUCCESS;

close_log_and_abort:
	end_log();
	return PAM_ABORT;
}

/*
 * PAM entry point for session cleanup
 */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_IGNORE);
}
