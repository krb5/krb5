#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <limits.h>

#ifdef _SC_OPEN_MAX
int getdtablesize() {
    return sysconf(_SC_OPEN_MAX);
}
#else
#include <sys/resource.h>
/* Placed in the Public Domain by Mark Eichin, Cygnus Support 1994 */

int getdtablesize() {
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    return rl.rlim_cur;
}
#endif
