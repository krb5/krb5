/* Placed in the Public Domain by Mark Eichin, Cygnus Support 1994 */

#include <sys/resource.h>
int getdtablesize() {
  struct rlimit rl;
  getrlimit(RLIMIT_NOFILE, &rl);
  return rl.rlim_cur;
}
