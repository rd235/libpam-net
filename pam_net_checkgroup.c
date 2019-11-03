/* 
 * pam_net_common.
 * Copyright (C) 2016, 2019 Renzo Davoli, Eduard Caizer University of Bologna
 * 
 * pam_net common code.
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
#include <string.h>
#include <grp.h>
#include <pwd.h>

/* check if "user" belongs to "group" */
int checkgroup(const char *user, const char *group) {
	struct passwd *pw = getpwnam(user);
	struct group *gr = getgrnam(group);
	int ngroups=0;
	if (pw == NULL) return -1;
	if (gr == NULL) return 0;
	if (getgrouplist(user, pw->pw_gid, NULL, &ngroups) < 0) {
		gid_t gids[ngroups];
		if (getgrouplist(user, pw->pw_gid, gids, &ngroups) == ngroups) {
			int i;
			for (i=0; i<ngroups; i++) {
				if (gr->gr_gid == gids[i]) 
					return 1;
			}
			return 0;
		}
	}
	return -1;
}
