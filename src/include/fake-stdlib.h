#if defined(__STDC__) || defined(_WINDOWS)
#else
# define P(s) ()
#endif

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
int access P((char *, int ));
int acct P((char *));
char *brk P((char *));
int chdir P((char *));
int chmod P((char *, int ));
int chown P((char *, int , int ));
int chroot P((char *));
int close P((int ));
int dup P((int ));
int dup2 P((int , int ));
int execve P((char *, char * [], char * []));
#ifndef __GNUC__
int _exit P((int ));
#endif
int fchmod P((int , int ));
int fchown P((int , int , int ));
int fcntl P((int , int , int ));
int flock P((int , int ));
int fork P((void ));
int fsync P((int ));
int ftruncate P((int , off_t ));
int getdtablesize P((void ));
gid_t getegid P((void ));
uid_t geteuid P((void ));
gid_t getgid P((void ));
int getgroups P((int , int *));
long gethostid P((void ));
int gethostname P((char *, int ));
int getpagesize P((void ));
int getpgrp P((int ));
int getpid P((void ));
int getppid P((void ));
uid_t getuid P((void ));
int ioctl P((int , u_long , char *));
int kill P((int , int ));
int killpg P((int , int ));
int listen P((int , int ));
int mount P((int , char *, int , caddr_t *));
int pipe P((int  [2 ]));
int profil P((char *, int , int , int ));
int ptrace P((int , int , int *, int ));
int quota P((int , int , int , char *));
int read P((int , char *, int ));
int reboot P((int ));
int recv P((int , char *, int , int ));
char *sbrk P((int ));
int setgroups P((int , int *));
int sethostid P((long ));
int sethostname P((char *, int ));
int setpgrp P((int , int ));
int setquota P((const char *, const char *));
int setregid P((int , int ));
int setreuid P((int , int ));
int shutdown P((int , int ));
void srandom P((int  ));
int swapon P((char *));
int sync P((void ));
int umask P((int ));
int umount P((char *));
int vfork P((void ));
int vhangup P((void ));
int write P((int , const char *, int ));
int abs P((int ));
int alarm P((unsigned ));
double atof P((const char *));
int atoi P((char *));
long atol P((char *));
int bcmp P((char *, char *, int ));
int bcopy P((const char *, char *, int ));
int bzero P((char *, int ));
void *calloc P((unsigned long, unsigned long));
void closelog P((void ));
int creat P((char *, int ));
char *crypt P((char *, char *));
char *ecvt P((double , int , int *, int *));
int encrypt P((char *, int ));
int endfsent P((void ));
int endgrent P((void ));
int endhostent P((void ));
int endnetent P((void ));
int endprotoent P((void ));
int endpwent P((void ));
int endservent P((void ));
int endttyent P((void ));
int endusershell P((void ));
int execl P((char *, char *, ...));
int execle P((char *, char *));
int execlp P((char *, char *, ...));
int execv P((char *, char * []));
int execvp P((char *, char * []));
int exect P((char *, char * [], char * []));
#ifndef __GNUC__
int exit P((int ));
#endif
char *fcvt P((double , int , int *, int *));
int ffs P((int ));
#ifdef __GNUC__
void free P((void *));
#else
int free P((char *));
#endif
double frexp P((double , int *));
char *gcvt P((double , int , char *));
struct disktab *getdiskbyname P((char *));
char *getenv P((char *));
struct fstab *getfsent P((void ));
struct fstab *getfsspec P((char *));
struct fstab *getfsfile P((char *));
struct fstab *getfstype P((char *));
struct group *getgrent P((void ));
struct group *getgrgid P((int ));
struct group *getgrnam P((const char *));
char *getlogin P((void ));
int getopt P((int , char **, char *));
char *getpass P((char *));
int getpw P((int , char *));
struct passwd *getpwent P((void ));
struct passwd *getpwuid P((int ));
struct passwd *getpwnam P((const char *));
struct ttyent *getttynam P((const char *));
char *getusershell P((void ));
char *getwd P((char *));
u_long htonl P((u_long ));
u_short htons P((unsigned int ));
u_long inet_addr P((const char *));
u_long inet_network P((const char *));
int initgroups P((char *, int ));
char *initstate P((unsigned , char *, int ));
int isatty P((int ));
double ldexp P((double , int ));
int longjmperror P((void ));
#if defined(__STDC__) || defined(_WINDOWS)
void *malloc P((size_t ));
#else
char *malloc P((unsigned ));
#endif
char *memccpy P((char *, char *, int , int ));
char *memchr P((char *, int , int ));
#ifndef __GNUC__
int memcmp P((char *, char *, int ));
char *memcpy P((char *, const char *, int ));
char *memset P((char *, int , int ));
#endif
char *mktemp P((char *));
int mkstemp P((char *));
double modf P((double , double *));
int moncontrol P((int ));
int nice P((int ));
struct ns_addr ns_addr P((char *));
u_long ntohl P((u_long ));
u_short ntohs P((unsigned int ));
void openlog P((const char *, int , int ));
int pause P((void ));
int perror P((const char * ));
int psignal P((unsigned , const char *));
int qsort P((char *, int , int , int (* )()));
int rand P((void ));
long random P((void ));
int rcmd P((char **, u_short , char *, char *, char *, int *));
char *re_comp P((char *));
int re_exec P((char *));
#ifdef __GNUC__
void *realloc P((void *, size_t ));
#else
char *realloc P((char *, unsigned ));
#endif
int rexec P((char **, u_short , char *, char *, char *, int *));
int rresvport P((int *));
int ruserok P((char *, int , char *, char *));
int setegid P((gid_t ));
int seteuid P((uid_t ));
int setfsent P((void ));
int setgrent P((void ));
int setgid P((gid_t ));
int sethostent P((int ));
int setkey P((char *));
int setlogmask P((int ));
int setnetent P((int ));
int setprotoent P((int ));
int setpwent P((void ));
int setpwfile P((const char *));
int setrgid P((gid_t ));
int setruid P((uid_t ));
int setservent P((int ));
char *setstate P((char *));
int setttyent P((void ));
int setuid P((uid_t ));
int setusershell P((void ));
int siginterrupt P((int , int ));
int sleep P((unsigned ));
int srand P((int ));
int swab P((char *, char *, int ));
void syslog P((int , const char *, ...));
int system P((char *));
long tell P((int ));
long time P((long *));
char *timezone P((int , int ));
char *tmpnam P((char *));
char *ttyname P((int ));
int ttyslot P((void ));
unsigned ualarm P((unsigned , unsigned ));
int usleep P((unsigned ));
int utime P((char *, time_t *));
char *valloc P((unsigned ));
int vlimit P((int , int ));
#ifndef __GNUC__
void abort P((void));
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
int access P((char * , int ));
int acct P((char * ));
#ifndef SYSTEM_FIVE
caddr_t brk P((caddr_t ));
#endif
caddr_t sbrk P((int  ));
#ifdef mips
int cachectl P((char * , int , int ));
int cacheflush P((char *, int , int ));
#endif
int chdir P((char * ));
int chmod P((char * , int  ));
int fchmod P((int  , int  ));
int chown P((char * , int  , int  ));
int fchown P((int  , int  , int ));
int chroot P((char * ));
int close P((int  ));
int creat P((char * , int  ));
int dup P((int  ));
int dup2 P((int , int  ));
int execve P((char * , char * [], char * []));
#ifndef SYSTEM_FIVE
int _exit P((int  ));
#endif
int exportfs P((char * , int  , int  ));
int fcntl P((int  , int  , int ));
int fork P((void ));
int getdirentries P((int  , char * , int  , long * ));
int getdomainname P((char * , int  ));
int setdomainname P((char * , int ));
#ifndef SYSTEM_FIVE
int getgid P((void ));
int getegid P((void ));
#endif
#ifndef SYSTEM_FIVE
int getpgrp P((int ));
#endif
int getpid P((void ));
int getppid P((void ));
#ifndef SYSTEM_FIVE
int getuid P((void ));
int geteuid P((void ));
#endif
#ifndef SYSTEM_FIVE
int ioctl P((int  , int  , char * ));
#endif
int kill P((int  , int  ));
int link P((char * , char * ));
off_t lseek P((int  , long  , int ));
#ifdef SYSTEM_FIVE
int madvise P((char * , int , int ));
int mmap P((char * , int  , int , int , int , off_t ));
int mincore P((char * , int  , char * ));
#endif
int mkdir P((char *, int  ));
int mknod P((char * , int , int ));
int mount P((char * , char * , int ));
int umount P((char * ));
#ifdef SYSTEM_FIVE
int mprotect P((char * , int , int ));
int mremap P((char * , int , int , int , int ));
int munmap P((char * , int ));
#endif
int nfs_svc P((int ));
void nfs_biod P((void ));
int open P((char * , int  , int  ));
int pipe P((int [2]));
#ifndef SYSTEM_FIVE
int profil P((char * , int , int , int ));
#endif
int ptrace P((int , int , int * , int  ));
#ifndef SYSTEM_FIVE
int read P((int , char * , int  ));
#endif
#ifndef SYSTEM_FIVE
int setpgrp P((int , int ));
#endif
#ifdef SYSTEM_FIVE
char *stk P((char * ));
char *sstk P((int  ));
#endif
void sync P((void ));
int umask P((int ));
int unlink P((char * ));
pid_t waitpid P((pid_t , int * , int ));
#ifndef SYSTEM_FIVE
int write P((int , char * , int  ));
#endif

void abort P((void ));
int abs P((int ));
#ifndef SYSTEM_FIVE
int alarm P((unsigned ));
#endif
char *crypt P((char * , char * ));
#ifndef SYSTEM_FIVE
void encrypt P((char * ));
#endif
#ifndef SYSTEM_FIVE
char *timezone P((int  , int  ));
#endif
char *ecvt P((double , int , int * , int * ));
char *fcvt P((double , int  , int * , int * ));
char *gcvt P((double , int , char * ));
int execl P((char * , char *, ...));
int execle P((char * , char * ));
int execv P((char * , char **));
int exect P((char *, char **, char ** ));
/* void exit P((int )); */
double frexp P((double , int * ));
double ldexp P((double , int  ));
double modf P((double , double * ));
struct disktab *getdiskbyname P((char * ));
char *getenv P((char * ));
struct fstab *getfsent P((void ));
struct fstab *getfsspec P((char * ));
struct fstab *getfsfile P((char * ));
struct fstab *getfstype P((char * ));
int endfsent P((void ));
int setfsent P((void ));
#ifndef SYSTEM_FIVE
struct group *getgrent P((void ));
struct group *getgrgid P((int ));
struct group *getgrnam P((const char * ));
int endgrent P((void ));
int setgrent P((void ));
#endif
char *getlogin P((void ));
struct hostent *gethostent P((void ));
struct hostent *gethostbyname P((char * ));
struct hostent *gethostbyaddr P((char * , int  , int  ));
void sethostent P((int ));
void endhostent P((void ));
struct netent *getnetent P((void ));
struct netent *getnetbyname P((char * ));
struct netent *getnetbyaddr P((int  , int ));
void setnetent P((int ));
void endnetent P((void ));
char *getpass P((char * ));
struct protoent *getprotoent P((void ));
struct protoent *getprotobyname P((char * ));
struct protoent *getprotobynumber P((int  ));
void setprotoent P((int ));
void endprotoent P((void ));
int getpw P((int , char * ));
#ifndef SYSTEM_FIVE
struct passwd *getpwent P((void ));
struct passwd *getpwuid P((int ));
struct passwd *getpwnam P((const char * ));
int endpwent P((void ));
int setpwent P((void ));
#endif
char *gets P((char * ));
struct servent *getservent P((void ));
struct servent *getservbyname P((char * , char * ));
struct servent *getservbyport P((int , char * ));
void setservent P((int ));
void endservent P((void ));
struct ttyent *getttyent P((void ));
struct ttyent *getttynam P((const char * ));
unsigned long inet_network P((const char * ));
int initgroups P((char * , int  ));
#if defined(__STDC__) || defined(_WINDOWS)
void *malloc P((unsigned ));
#else
char *malloc P((unsigned ));
#endif
char *calloc P((unsigned , unsigned  ));
char *realloc P((char * , unsigned  ));
void free P((char * ));
char *alloca P((int  ));
int mkfifo P((char * , mode_t  ));
char *mktemp P((char * ));
#ifndef SYSTEM_FIVE
void monitor P((int (* )(), int (* )(), short * , int , int  ));
#endif
void monstartup P((int (* )(), int (* )()));
void moncontrol P((int ));
#ifndef SYSTEM_FIVE
void nice P((int ));
#endif
long pathconf P((char * , int  ));
long fpathconf P((int , int ));
int pause P((void ));
void perror P((char * ));
int printf P((const char *, ...));
int puts P((const char * ));
#ifndef SYSTEM_FIVE
int qsort P((char * , int  , int , int (* )()));
#endif
int rand P((void ));
void srand P((int ));
int rcmd P((char ** , u_short , char * , char * , char * , int * ));
int rresvport P((int * ));
int ruserok P((char * , int  , char * , char * ));
int rexec P((char ** , u_short  , char * , char * , char * , int * ));
int scanf P((const char *, ... ));
int sscanf P((const char * , const char *, ... ));
int setpgid P((pid_t  , pid_t  ));
int setuid P((int  ));
int seteuid P((int  ));
int setruid P((int  ));
int setgid P((int  ));
int setegid P((int  ));
int setrgid P((int  ));

int siginterrupt P((int  , int  ));
unsigned sleep P((unsigned  ));
int strcmp P((const char * , const char * ));
char *strcpy P((char * , const char * ));
#ifndef hpux
int strlen P((const char * ));
#endif
char *strncat P((char * , const char * , int  ));
int strncmp P((const char * , const char * , int  ));
char *strncpy P((char * , const char * , int  ));
void swab P((char * , char * , int  ));
long sysconf P((int  ));
int system P((char * ));
char *ttyname P((int  ));
int isatty P((int  ));
int ttyslot P((void ));
int utime P((char * , time_t  []));

#ifndef SYSTEM_FIVE
int flock P((int  , int  ));
int fsync P((int  ));
int getdtablesize P((void ));
int getgroups P((int  , int * ));
int gethostid P((void ));
int sethostid P((int  ));
int gethostname P((char * , int  ));
int sethostname P((char * , int  ));
int getpagesize P((void ));
int getpriority P((int  , int  ));
int setpriority P((int  , int  , int  ));
int getsockname P((int  , char * , int * ));
int getsockopt P((int  , int  , int  , char * , int * ));
int setsockopt P((int  , int  , int  , const char * , int  ));
int killpg P((int  , int  ));
int listen P((int  , int  ));
int quota P((int  , int  , int  , caddr_t ));
int readlink P((char * , char * , int  ));
int reboot P((int  ));
int rename P((char * , char * ));
int rmdir P((char * ));
int send P((int  , char * , int , int  ));
int setgroups P((int  , int * ));
int setregid P((int  , int  ));
int setquota P((char * , char * ));
int setreuid P((int  , int  ));
pid_t setsid P((void ));
int shutdown P((int  , int  ));
int sigblock P((int  ));
int sigpause P((int  ));
int sigsetmask P((int  ));
int socket P((int , int  , int  ));
int socketpair P((int , int  , int  , int  [2 ]));
int swapon P((char * ));
int symlink P((char * , char * ));
int truncate P((char * , int  ));
int ftruncate P((int  , int  ));
int vfork P((void ));
void vhangup P((void ));
double atof P((char * ));
int atoi P((char * ));
long atol P((char * ));
void bcopy P((const char * , char * , int  ));
int bcmp P((char * , char * , int  ));
void bzero P((char * , int  ));
int ffs P((int  ));
char *getwd P((char * ));
void psignal P((unsigned  , char * ));
void srandom P((int  ));
long random P((void ));
char *initstate P((unsigned  , char * , int  ));
char *setstate P((char * ));
char *re_comp P((char * ));
int re_exec P((char * ));
void openlog P((const char * , int, int  )); /* our local version... */
void syslog P((int  , const char *, ... ));
void closelog P((void ));
char *valloc P((unsigned  ));
int vlimit P((int  , int  ));
#endif
int execlp P((char * , char *, ... ));
int execvp P((char * , char * []));
int plock P((int ));
char *shmat P((int  , char * , int  ));
int shmdt P((char * ));
void sys3b P((int  , int  , int  ));
long ulimit P((int  , long  ));
long a64l P((char * ));
char *l64a P((long  ));
void _assert P((char * , char * , int  ));
char *bsearch P((char * , char * , unsigned  , unsigned  , int (* )(char *, char *)));
long clock P((void ));
char *ctermid P((char * ));
char *cuserid P((char * ));
double drand48 P((void ));
double erand48 P((unsigned short  [3 ]));
long lrand48 P((void ));
long nrand48 P((unsigned short  [3 ]));
long mrand48 P((void ));
long jrand48 P((unsigned short  [3 ]));
void srand48 P((long s ));
unsigned short *seed48 P((unsigned short  [3 ]));
void lcong48 P((unsigned short  [7 ]));
char *getcwd P((char * , int  ));
int getopt P((int  , char ** , char * ));
int hcreate P((unsigned  ));
void hdestroy P((void ));
void l3tol P((long * , char * , int  ));
void ltol3 P((char * , long * , int  ));
char *lsearch P((char * , char * , unsigned * , unsigned  , int (* )(char *, char *)));
char *lfind P((char * , char * , unsigned * , unsigned  , int (* )(char *, char *)));
char *memccpy P((char * , char * , int  , int  ));
char *memchr P((char * , int  , int  ));
int memcmp P((char * , char * , int  ));
char *memcpy P((char * , const char * , int  ));
char *memset P((char * , int  , int  ));
int gsignal P((int  ));
double strtod P((char * , char ** ));
long strtol P((char * , char ** , int  ));
char *tmpnam P((char * ));
char *tempnam P((char * , char * ));
char *tsearch P((char * , char ** , int (* )(char *, char *)));
char *tfind P((char * , char ** , int (* )(char *, char *)));
char *tdelete P((char * , char ** , int (* )(char *, char *)));
void twalk P((char * , void (* )(char *, int, int)));
int syscall P((int  , int  , int  , int  ));
long tell P((int  ));

#ifdef SYSTEM_FIVE

unsigned alarm P((unsigned ));
int brk P((char * ));
void _exit P((int  ));
int getpgrp P((void ));
unsigned short getuid P((void ));
unsigned short geteuid P((void ));
unsigned short getgid P((void ));
unsigned short getegid P((void ));
int ioctl P((int  , int  , int  ));
int nice P((int  ));
void profil P((char * , int  , int  , int  ));
int read P((int  , char * , unsigned  ));
int setpgrp P((void ));
int write P((int  , char * , unsigned  ));
void setkey P((char * ));
void encrypt P((char * , int  ));
void tzset P((void ));
struct group *getgrent P((void ));
struct group *getgrgid P((int  ));
struct group *getgrnam P((char * ));
void setgrent P((void ));
void endgrent P((void ));
struct passwd *getpwent P((void ));
struct passwd *getpwuid P((int  ));
struct passwd *getpwnam P((const char * ));
void setpwent P((void ));
void endpwent P((void ));
void qsort P((char * , unsigned  , unsigned  , int (* )()));
#endif

#endif /* MIPS/Ultrix */

#ifdef ibm032
#ifndef memcpy
extern void *memcpy P((void *, const void *, unsigned int));
#endif
#ifndef memset
extern void *memset P((void *, int, unsigned int));
#endif
extern int bcmp P((void *, void *, unsigned int));
extern void *calloc P((unsigned int, unsigned int));
extern void *malloc P((unsigned int));
extern void *realloc P((void *, unsigned int));
extern void free P((void *));
#ifndef abort
extern void abort P((void));
#endif
extern char *getenv P((const char *));

extern double atof P((const char *));
extern int    atoi P((const char *));

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
