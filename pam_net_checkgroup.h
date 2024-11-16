#ifndef PAM_NET_COMMON_H
#define PAM_NET_COMMON_H

/* check if "user" belongs to "group" */
/* 0=NO 1=YES -1=error */
int checkgroup(const char *user, const char *group);

/* get the name specified after a dash char '-' of "group" on a user.
 * if the user is part of multiple groups starting with "group", returns data from first matching group. */
/* NULL = not found/error. pointer must be freed. */
char *get_groupnet_netns(const char *user, const char *group);

#endif //PAM_NET_COMMON_H
