#ifndef PAM_NET_COMMON_H
#define PAM_NET_COMMON_H

/* check if "user" belongs to "group" */
/* 0=NO 1=YES -1=error */
int checkgroup(const char *user, const char *group);

#endif //PAM_NET_COMMON_H
