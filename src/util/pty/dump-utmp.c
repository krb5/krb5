#include <stdio.h>
#include <sys/file.h>
#include <fcntl.h>

#ifdef UTMPX
#include <utmpx.h>
#endif
#include <utmp.h>

char *ut_typename (t) {
  switch (t) {
#define S(N) case N : return #N
  S(EMPTY);
  S(RUN_LVL);
  S(BOOT_TIME);
  S(OLD_TIME);
  S(NEW_TIME);
  S(INIT_PROCESS);
  S(LOGIN_PROCESS);
  S(USER_PROCESS);
  S(DEAD_PROCESS);
  S(ACCOUNTING);
  default: return "??";
  }
}

int main (argc, argv) int argc; char *argv[]; {
  int f;
  char id[5], user[50];
  char *file = 0;
  int all = 0;

  while (*++argv)
    {
      char *arg = *argv;
      if (!arg)
	break;
      if (!strcmp ("-a", arg))
	all = 1;
      else if (file)
	{
	  fprintf (stderr, "already got a file\n");
	  return 1;
	}
      else
	file = arg;
    }
  f = open (file, O_RDONLY);
  if (f < 0) {
    perror (file);
    exit (1);
  }
  id[4] = 0;
#ifdef UTMPX
  if ('x' != file[strlen(file) - 1]) {
    struct utmpx u;
    while (read (f, &u, sizeof (u)) == sizeof (u)) {
      char c;
      if ((u.ut_type == DEAD_PROCESS
	   || u.ut_type == EMPTY)
	  && !all)
	continue;
      strncpy (id, u.ut_id, 4);
      printf ("%-8s:%-12s:%-4s:%6d %s",
	      u.ut_user, u.ut_line, id,
	      u.ut_pid, ut_typename (u.ut_type));
	      /* ctime (&u.ut_xtime) + 4 */
      if (u.ut_syslen && u.ut_host[0])
	printf (" %s", u.ut_host);
      printf ("\n");
      return 0;
    }
  }
  /* else */
#endif
  {
    struct utmp u;
    user[sizeof(u.ut_user)] = 0;
    while (read (f, &u, sizeof (u)) == sizeof (u)) {
      char c;
      if ((u.ut_type == DEAD_PROCESS
	   || u.ut_type == EMPTY)
	  && !all)
	continue;
      strncpy (id, u.ut_id, 4);
      strncpy (user, u.ut_user, sizeof (u.ut_user));
      printf ("%-8s:%-12s:%-4s:%6d %s", user, u.ut_line, id,
	      u.ut_pid, ut_typename (u.ut_type));
      printf ("\n");
#if 0
      printf ("user: %-32s  id: %s\n", user, id);
      printf ("    line: %-32s  pid:%-6d  type: %s\n",
	      u.ut_line, u.ut_pid, ut_typename (u.ut_type));
      printf ("    exit_status: %d,%d\n",
	      u.ut_exit.e_termination, u.ut_exit.e_exit);
      printf ("    time: %s\n", ctime (&u.ut_time) + 4);
#endif
    }
  }

  return 0;
}
