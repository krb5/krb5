#include <stdio.h>
#include <sys/file.h>
#include <fcntl.h>

#ifndef UTMPX
#ifdef HAVE_UTMPX_H
#define UTMPX
#endif
#endif

#ifdef UTMPX
#include <utmpx.h>
#endif
#include <utmp.h>

extern char *ctime ();

#if defined (HAVE_STRUCT_UTMP_UT_TYPE) || defined (UTMPX)
char *ut_typename (t) {
  switch (t) {
#define S(N) case N : return #N
#define S2(N,N2) case N : return #N2
  S(EMPTY);
  S(RUN_LVL);
  S(BOOT_TIME);
  S(OLD_TIME);
  S(NEW_TIME);
  S2(INIT_PROCESS,INIT);
  S2(LOGIN_PROCESS,LOGIN);
  S2(USER_PROCESS,USER);
  S2(DEAD_PROCESS,DEAD);
  S(ACCOUNTING);
  default: return "??";
  }
}
#endif

int main (argc, argv) int argc; char *argv[]; {
  int f;
  char id[5], user[50], host[100];
  char *file = 0;
  int all = 0;
  int is_utmpx = 0;

  while (*++argv)
    {
      char *arg = *argv;
      if (!arg)
	break;
      if (!strcmp ("-a", arg))
	all = 1;
      else if (!strcmp ("-x", arg))
	is_utmpx = 1;
      else if (arg[0] == '-')
	{
	  fprintf (stderr, "unknown arg `%s'\n", arg);
	  return 1;
	}
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
  if (is_utmpx) {
#ifdef UTMPX
    struct utmpx u;
    while (1) {
      int nread = read (f, &u, sizeof (u));
      if (nread == 0) {
	/* eof */
	return 0;
      } else if (nread == -1) {
	/* error */
	perror ("read");
	return 1;
      }
      if ((u.ut_type == DEAD_PROCESS
	   || u.ut_type == EMPTY)
	  && !all)
	continue;
      strncpy (id, u.ut_id, 4);
      printf ("%-8s:%-12s:%-4s", u.ut_user, u.ut_line, id);
      printf (":%5d", u.ut_pid);
      printf ("(%5d,%5d)", u.ut_exit.e_termination, u.ut_exit.e_exit);
      printf (" %-9s %s", ut_typename (u.ut_type), ctime (&u.ut_xtime) + 4);
      if (u.ut_syslen && u.ut_host[0])
	printf (" %s\n", u.ut_host);
    }
    abort ();
#else
    fprintf (stderr, "utmpx support not compiled in\n");
    return 1;
#endif
  }
  /* else */
  {
    struct utmp u;
    while (read (f, &u, sizeof (u)) == sizeof (u)) {
#ifdef EMPTY
      if ((u.ut_type == DEAD_PROCESS
	   || u.ut_type == EMPTY)
	  && !all)
	continue;
#endif
#ifdef HAVE_STRUCT_UTMP_UT_PID
      strncpy (id, u.ut_id, 4);
      strncpy (user, u.ut_user, sizeof (u.ut_user));
      user[sizeof(u.ut_user)] = 0;
      printf ("%-8s:%-12s:%-4s", user, u.ut_line, id);
      printf (":%5d", u.ut_pid);
#else
      strncpy (user, u.ut_name, sizeof (u.ut_name));
      user[sizeof(u.ut_name)] = 0;
      printf ("%-8s:%-12s", user, u.ut_line);
#endif
#ifdef HAVE_STRUCT_UTMP_UT_HOST
      {
	char host[sizeof (u.ut_host) + 1];
	strncpy (host, u.ut_host, sizeof(u.ut_host));
	host[sizeof (u.ut_host)] = 0;
	printf (":%-*s", sizeof (u.ut_host), host);
      }
#endif
#ifdef HAVE_STRUCT_UTMP_UT_EXIT
      printf ("(%5d,%5d)", u.ut_exit.e_termination, u.ut_exit.e_exit);
#endif
#ifdef HAVE_STRUCT_UTMP_UT_TYPE
      printf (" %-9s", ut_typename (u.ut_type));
#endif
      /* this ends with a newline */
      printf (" %s", ctime (&u.ut_time) + 4);
    }
  }

  return 0;
}
