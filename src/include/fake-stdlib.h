#ifndef FD_SETSIZE
#include <sys/types.h>
#endif

#if defined(vax) || defined(__vax__)

/* following functions removed:
   stdio
   directory reading
   DBM
   signal(3)
   alphasort(3), scandir(3)
   accept(2)
   bind(2)
   connect(2)
   getpeername(2)
   getpriority(2)
   getrlimit(2)
   getrusage(2)
   readv(2)
   recvfrom(2)
   recvmsg(2)
   sendto(2)
   sendmsg(2)
   setrlimit(2)
   sigvec(2)
   sigreturn(2)
   sigstack(2)
   wait(2)
   wait3(2)
   writev(2)
   ftime(2)
   gtty(3)
   inet_lnaof(3)
   inet_netof(3)
   in_addr(3)
   inet_ntoa(3)
   insque(3)
   longjmp(3)
   nlist(3)
   ns_ntoa(3)
   remque(3)
   setjmp(3)
   stty(3)
   times(3)
   vtimes(3)
   adjtime(2)
   fstat(2)
   getitimer(2)
   gettimeofday(2)
   lstat(2)
   select(2)
   setitimer(2)
   settimeofday(2)
   stat(2)
   utimes(2)
   asctime(2)
   monitor(3)
   monstartup(3)
   ctime(3)
   gmtime(3)
   localtime(3)
 */

/* /usr/lib/lint/llib-lc */
/* /usr/lib/lint/llib-lc */
int access (char *, int );
int acct (char *);
char *brk (char *);
int chdir (char *);
int chmod (char *, int );
int chown (char *, int , int );
int chroot (char *);
int close (int );
int dup (int );
int dup2 (int , int );
int execve (char *, char * [], char * []);
#ifndef __GNUC__
int _exit (int );
#endif
int fchmod (int , int );
int fchown (int , int , int );
int fcntl (int , int , int );
int flock (int , int );
int fork (void );
int fsync (int );
int ftruncate (int , off_t );
int getdtablesize (void );
gid_t getegid (void );
uid_t geteuid (void );
gid_t getgid (void );
int getgroups (int , int *);
long gethostid (void );
int gethostname (char *, int );
int getpagesize (void );
int getpgrp (int );
int getpid (void );
int getppid (void );
uid_t getuid (void );
int ioctl (int , u_long , char *);
int kill (int , int );
int killpg (int , int );
int listen (int , int );
int mount (int , char *, int , caddr_t *);
int pipe (int  [2 ]);
int profil (char *, int , int , int );
int ptrace (int , int , int *, int );
int quota (int , int , int , char *);
int read (int , char *, int );
int reboot (int );
int recv (int , char *, int , int );
char *sbrk (int );
int setgroups (int , int *);
int sethostid (long );
int sethostname (char *, int );
int setpgrp (int , int );
int setquota (const char *, const char *);
int setregid (int , int );
int setreuid (int , int );
int shutdown (int , int );
void srandom (int  );
int swapon (char *);
int sync (void );
int umask (int );
int umount (char *);
int vfork (void );
int vhangup (void );
int write (int , const char *, int );
int abs (int );
int alarm (unsigned );
double atof (const char *);
int atoi (char *);
long atol (char *);
int bcmp (char *, char *, int );
int bcopy (const char *, char *, int );
int bzero (char *, int );
void *calloc (unsigned long, unsigned long);
void closelog (void );
int creat (char *, int );
char *crypt (char *, char *);
char *ecvt (double , int , int *, int *);
int encrypt (char *, int );
int endfsent (void );
int endgrent (void );
int endhostent (void );
int endnetent (void );
int endprotoent (void );
int endpwent (void );
int endservent (void );
int endttyent (void );
int endusershell (void );
int execl (char *, char *, ...);
int execle (char *, char *);
int execlp (char *, char *, ...);
int execv (char *, char * []);
int execvp (char *, char * []);
int exect (char *, char * [], char * []);
#ifndef __GNUC__
int exit (int );
#endif
char *fcvt (double , int , int *, int *);
int ffs (int );
#ifdef __GNUC__
void free (void *);
#else
int free (char *);
#endif
double frexp (double , int *);
char *gcvt (double , int , char *);
struct disktab *getdiskbyname (char *);
char *getenv (char *);
struct fstab *getfsent (void );
struct fstab *getfsspec (char *);
struct fstab *getfsfile (char *);
struct fstab *getfstype (char *);
struct group *getgrent (void );
struct group *getgrgid (int );
struct group *getgrnam (const char *);
char *getlogin (void );
int getopt (int , char **, char *);
char *getpass (char *);
int getpw (int , char *);
struct passwd *getpwent (void );
struct passwd *getpwuid (int );
struct passwd *getpwnam (const char *);
struct ttyent *getttynam (const char *);
char *getusershell (void );
char *getwd (char *);
u_long htonl (u_long );
u_short htons (unsigned int );
u_long inet_addr (const char *);
u_long inet_network (const char *);
int initgroups (char *, int );
char *initstate (unsigned , char *, int );
int isatty (int );
double ldexp (double , int );
int longjmperror (void );
#if defined(__STDC__) || defined(_WINDOWS)
void *malloc (size_t );
#else
char *malloc (unsigned );
#endif
char *memccpy (char *, char *, int , int );
char *memchr (char *, int , int );
#ifndef __GNUC__
int memcmp (char *, char *, int );
char *memcpy (char *, const char *, int );
char *memset (char *, int , int );
#endif
char *mktemp (char *);
int mkstemp (char *);
double modf (double , double *);
int moncontrol (int );
int nice (int );
struct ns_addr ns_addr (char *);
u_long ntohl (u_long );
u_short ntohs (unsigned int );
void openlog (const char *, int , int );
int pause (void );
int perror (const char * );
int psignal (unsigned , const char *);
int qsort (char *, int , int , int (* )());
int rand (void );
long random (void );
int rcmd (char **, u_short , char *, char *, char *, int *);
char *re_comp (char *);
int re_exec (char *);
#ifdef __GNUC__
void *realloc (void *, size_t );
#else
char *realloc (char *, unsigned );
#endif
int rexec (char **, u_short , char *, char *, char *, int *);
int rresvport (int *);
int ruserok (char *, int , char *, char *);
int setegid (gid_t );
int seteuid (uid_t );
int setfsent (void );
int setgrent (void );
int setgid (gid_t );
int sethostent (int );
int setkey (char *);
int setlogmask (int );
int setnetent (int );
int setprotoent (int );
int setpwent (void );
int setpwfile (const char *);
int setrgid (gid_t );
int setruid (uid_t );
int setservent (int );
char *setstate (char *);
int setttyent (void );
int setuid (uid_t );
int setusershell (void );
int siginterrupt (int , int );
int sleep (unsigned );
int srand (int );
int swab (char *, char *, int );
void syslog (int , const char *, ...);
int system (char *);
long tell (int );
long time (long *);
char *timezone (int , int );
char *tmpnam (char *);
char *ttyname (int );
int ttyslot (void );
unsigned ualarm (unsigned , unsigned );
int usleep (unsigned );
int utime (char *, time_t *);
char *valloc (unsigned );
int vlimit (int , int );
#ifndef __GNUC__
void abort (void);
#endif

#endif /* VAX */

#if (defined(mips) && defined(ultrix)) || (defined(__mips__) && defined(__ultrix__)) || defined(__mips__) || defined(mips)

/* massaged from /usr/lib/lint/llib-lc, via watchbin/mkproto */
/* above functions removed, plus:
   old DBM
   sigset stuff
   semctl
   semget
   semop
   shmctl
   shmget
   uname
   ustat
   msg*
   to*
   is*
   hsearch
   ftok
   getmnt
   sprintf
 */

/* /usr/lib/lint/llib-lc */
int access (char * , int );
int acct (char * );
#ifndef SYSTEM_FIVE
caddr_t brk (caddr_t );
#endif
caddr_t sbrk (int  );
#ifdef mips
int cachectl (char * , int , int );
int cacheflush (char *, int , int );
#endif
int chdir (char * );
int chmod (char * , int  );
int fchmod (int  , int  );
int chown (char * , int  , int  );
int fchown (int  , int  , int );
int chroot (char * );
int close (int  );
int creat (char * , int  );
int dup (int  );
int dup2 (int , int  );
int execve (char * , char * [], char * []);
#ifndef SYSTEM_FIVE
int _exit (int  );
#endif
int exportfs (char * , int  , int  );
int fcntl (int  , int  , int );
int fork (void );
int getdirentries (int  , char * , int  , long * );
int getdomainname (char * , int  );
int setdomainname (char * , int );
#ifndef SYSTEM_FIVE
int getgid (void );
int getegid (void );
#endif
#ifndef SYSTEM_FIVE
int getpgrp (int );
#endif
int getpid (void );
int getppid (void );
#ifndef SYSTEM_FIVE
int getuid (void );
int geteuid (void );
#endif
#ifndef SYSTEM_FIVE
int ioctl (int  , int  , char * );
#endif
int kill (int  , int  );
int link (char * , char * );
off_t lseek (int  , long  , int );
#ifdef SYSTEM_FIVE
int madvise (char * , int , int );
int mmap (char * , int  , int , int , int , off_t );
int mincore (char * , int  , char * );
#endif
int mkdir (char *, int  );
int mknod (char * , int , int );
int mount (char * , char * , int );
int umount (char * );
#ifdef SYSTEM_FIVE
int mprotect (char * , int , int );
int mremap (char * , int , int , int , int );
int munmap (char * , int );
#endif
int nfs_svc (int );
void nfs_biod (void );
int open (char * , int  , int  );
int pipe (int [2]);
#ifndef SYSTEM_FIVE
int profil (char * , int , int , int );
#endif
int ptrace (int , int , int * , int  );
#ifndef SYSTEM_FIVE
int read (int , char * , int  );
#endif
#ifndef SYSTEM_FIVE
int setpgrp (int , int );
#endif
#ifdef SYSTEM_FIVE
char *stk (char * );
char *sstk (int  );
#endif
void sync (void );
int umask (int );
int unlink (char * );
pid_t waitpid (pid_t , int * , int );
#ifndef SYSTEM_FIVE
int write (int , char * , int  );
#endif

void abort (void );
int abs (int );
#ifndef SYSTEM_FIVE
int alarm (unsigned );
#endif
char *crypt (char * , char * );
#ifndef SYSTEM_FIVE
void encrypt (char * );
#endif
#ifndef SYSTEM_FIVE
char *timezone (int  , int  );
#endif
char *ecvt (double , int , int * , int * );
char *fcvt (double , int  , int * , int * );
char *gcvt (double , int , char * );
int execl (char * , char *, ...);
int execle (char * , char * );
int execv (char * , char **);
int exect (char *, char **, char ** );
/* void exit (int ); */
double frexp (double , int * );
double ldexp (double , int  );
double modf (double , double * );
struct disktab *getdiskbyname (char * );
char *getenv (char * );
struct fstab *getfsent (void );
struct fstab *getfsspec (char * );
struct fstab *getfsfile (char * );
struct fstab *getfstype (char * );
int endfsent (void );
int setfsent (void );
#ifndef SYSTEM_FIVE
struct group *getgrent (void );
struct group *getgrgid (int );
struct group *getgrnam (const char * );
int endgrent (void );
int setgrent (void );
#endif
char *getlogin (void );
struct hostent *gethostent (void );
struct hostent *gethostbyname (char * );
struct hostent *gethostbyaddr (char * , int  , int  );
void sethostent (int );
void endhostent (void );
struct netent *getnetent (void );
struct netent *getnetbyname (char * );
struct netent *getnetbyaddr (int  , int );
void setnetent (int );
void endnetent (void );
char *getpass (char * );
struct protoent *getprotoent (void );
struct protoent *getprotobyname (char * );
struct protoent *getprotobynumber (int  );
void setprotoent (int );
void endprotoent (void );
int getpw (int , char * );
#ifndef SYSTEM_FIVE
struct passwd *getpwent (void );
struct passwd *getpwuid (int );
struct passwd *getpwnam (const char * );
int endpwent (void );
int setpwent (void );
#endif
char *gets (char * );
struct servent *getservent (void );
struct servent *getservbyname (char * , char * );
struct servent *getservbyport (int , char * );
void setservent (int );
void endservent (void );
struct ttyent *getttyent (void );
struct ttyent *getttynam (const char * );
unsigned long inet_network (const char * );
int initgroups (char * , int  );
#if defined(__STDC__) || defined(_WINDOWS)
void *malloc (unsigned );
#else
char *malloc (unsigned );
#endif
char *calloc (unsigned , unsigned  );
char *realloc (char * , unsigned  );
void free (char * );
char *alloca (int  );
int mkfifo (char * , mode_t  );
char *mktemp (char * );
#ifndef SYSTEM_FIVE
void monitor (int (* )(), int (* )(), short * , int , int  );
#endif
void monstartup (int (* )(), int (* )());
void moncontrol (int );
#ifndef SYSTEM_FIVE
void nice (int );
#endif
long pathconf (char * , int  );
long fpathconf (int , int );
int pause (void );
void perror (char * );
int printf (const char *, ...);
int puts (const char * );
#ifndef SYSTEM_FIVE
int qsort (char * , int  , int , int (* )());
#endif
int rand (void );
void srand (int );
int rcmd (char ** , u_short , char * , char * , char * , int * );
int rresvport (int * );
int ruserok (char * , int  , char * , char * );
int rexec (char ** , u_short  , char * , char * , char * , int * );
int scanf (const char *, ... );
int sscanf (const char * , const char *, ... );
int setpgid (pid_t  , pid_t  );
int setuid (int  );
int seteuid (int  );
int setruid (int  );
int setgid (int  );
int setegid (int  );
int setrgid (int  );

int siginterrupt (int  , int  );
unsigned sleep (unsigned  );
int strcmp (const char * , const char * );
char *strcpy (char * , const char * );
#ifndef hpux
int strlen (const char * );
#endif
char *strncat (char * , const char * , int  );
int strncmp (const char * , const char * , int  );
char *strncpy (char * , const char * , int  );
void swab (char * , char * , int  );
long sysconf (int  );
int system (char * );
char *ttyname (int  );
int isatty (int  );
int ttyslot (void );
int utime (char * , time_t  []);

#ifndef SYSTEM_FIVE
int flock (int  , int  );
int fsync (int  );
int getdtablesize (void );
int getgroups (int  , int * );
int gethostid (void );
int sethostid (int  );
int gethostname (char * , int  );
int sethostname (char * , int  );
int getpagesize (void );
int getpriority (int  , int  );
int setpriority (int  , int  , int  );
int getsockname (int  , char * , int * );
int getsockopt (int  , int  , int  , char * , int * );
int setsockopt (int  , int  , int  , const char * , int  );
int killpg (int  , int  );
int listen (int  , int  );
int quota (int  , int  , int  , caddr_t );
int readlink (char * , char * , int  );
int reboot (int  );
int rename (char * , char * );
int rmdir (char * );
int send (int  , char * , int , int  );
int setgroups (int  , int * );
int setregid (int  , int  );
int setquota (char * , char * );
int setreuid (int  , int  );
pid_t setsid (void );
int shutdown (int  , int  );
int sigblock (int  );
int sigpause (int  );
int sigsetmask (int  );
int socket (int , int  , int  );
int socketpair (int , int  , int  , int  [2 ]);
int swapon (char * );
int symlink (char * , char * );
int truncate (char * , int  );
int ftruncate (int  , int  );
int vfork (void );
void vhangup (void );
double atof (char * );
int atoi (char * );
long atol (char * );
void bcopy (const char * , char * , int  );
int bcmp (char * , char * , int  );
void bzero (char * , int  );
int ffs (int  );
char *getwd (char * );
void psignal (unsigned  , char * );
void srandom (int  );
long random (void );
char *initstate (unsigned  , char * , int  );
char *setstate (char * );
char *re_comp (char * );
int re_exec (char * );
void openlog (const char * , int, int  ); /* our local version... */
void syslog (int  , const char *, ... );
void closelog (void );
char *valloc (unsigned  );
int vlimit (int  , int  );
#endif
int execlp (char * , char *, ... );
int execvp (char * , char * []);
int plock (int );
char *shmat (int  , char * , int  );
int shmdt (char * );
void sys3b (int  , int  , int  );
long ulimit (int  , long  );
long a64l (char * );
char *l64a (long  );
void _assert (char * , char * , int  );
char *bsearch (char * , char * , unsigned  , unsigned  , int (* )(char *, char *));
long clock (void );
char *ctermid (char * );
char *cuserid (char * );
double drand48 (void );
double erand48 (unsigned short  [3 ]);
long lrand48 (void );
long nrand48 (unsigned short  [3 ]);
long mrand48 (void );
long jrand48 (unsigned short  [3 ]);
void srand48 (long s );
unsigned short *seed48 (unsigned short  [3 ]);
void lcong48 (unsigned short  [7 ]);
char *getcwd (char * , int  );
int getopt (int  , char ** , char * );
int hcreate (unsigned  );
void hdestroy (void );
void l3tol (long * , char * , int  );
void ltol3 (char * , long * , int  );
char *lsearch (char * , char * , unsigned * , unsigned  , int (* )(char *, char *));
char *lfind (char * , char * , unsigned * , unsigned  , int (* )(char *, char *));
char *memccpy (char * , char * , int  , int  );
char *memchr (char * , int  , int  );
int memcmp (char * , char * , int  );
char *memcpy (char * , const char * , int  );
char *memset (char * , int  , int  );
int gsignal (int  );
double strtod (char * , char ** );
long strtol (char * , char ** , int  );
char *tmpnam (char * );
char *tempnam (char * , char * );
char *tsearch (char * , char ** , int (* )(char *, char *));
char *tfind (char * , char ** , int (* )(char *, char *));
char *tdelete (char * , char ** , int (* )(char *, char *));
void twalk (char * , void (* )(char *, int, int));
int syscall (int  , int  , int  , int  );
long tell (int  );

#ifdef SYSTEM_FIVE

unsigned alarm (unsigned );
int brk (char * );
void _exit (int  );
int getpgrp (void );
unsigned short getuid (void );
unsigned short geteuid (void );
unsigned short getgid (void );
unsigned short getegid (void );
int ioctl (int  , int  , int  );
int nice (int  );
void profil (char * , int  , int  , int  );
int read (int  , char * , unsigned  );
int setpgrp (void );
int write (int  , char * , unsigned  );
void setkey (char * );
void encrypt (char * , int  );
void tzset (void );
struct group *getgrent (void );
struct group *getgrgid (int  );
struct group *getgrnam (char * );
void setgrent (void );
void endgrent (void );
struct passwd *getpwent (void );
struct passwd *getpwuid (int  );
struct passwd *getpwnam (const char * );
void setpwent (void );
void endpwent (void );
void qsort (char * , unsigned  , unsigned  , int (* )());
#endif

#endif /* MIPS/Ultrix */

#ifdef ibm032
#ifndef memcpy
extern void *memcpy (void *, const void *, unsigned int);
#endif
#ifndef memset
extern void *memset (void *, int, unsigned int);
#endif
extern int bcmp (void *, void *, unsigned int);
extern void *calloc (unsigned int, unsigned int);
extern void *malloc (unsigned int);
extern void *realloc (void *, unsigned int);
extern void free (void *);
#ifndef abort
extern void abort (void);
#endif
extern char *getenv (const char *);

extern double atof (const char *);
extern int    atoi (const char *);

#ifndef abs
extern int abs(int);
#if 0 /* used to be __HIGHC__; that interferes with jfc's c89 stdlib.h */
#define	abs(x)	_abs(x)
#endif
#endif

#endif /* ibm032 */

/* Declarations valid for all machines. */
#if !defined(abs) && defined(__GNUC__)
#define	abs(x)	__builtin_abs(x)
#endif

#undef P
