#ifdef __STDC__
# define	P(s) s
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
 */

/* /usr/lib/lint/llib-lc */
int access P((char *p , int m ));
int acct P((char *f ));
char *brk P((char *a ));
int chdir P((char *s ));
int chmod P((char *s , int m ));
int chown P((char *s , int u , int g ));
int chroot P((char *d ));
int close P((int f ));
int dup P((int f ));
int dup2 P((int o , int n ));
int execve P((char *s , char *v [], char *e []));
int _exit P((int s ));
int fchmod P((int f , int m ));
int fchown P((int f , int u , int g ));
int fcntl P((int f , int c , int a ));
int flock P((int f , int o ));
int fork P((void ));
int fsync P((int f ));
int ftruncate P((int d , off_t l ));
int getdtablesize P((void ));
gid_t getegid P((void ));
uid_t geteuid P((void ));
gid_t getgid P((void ));
int getgroups P((int n , int *g ));
long gethostid P((void ));
int gethostname P((char *n , int l ));
int getpagesize P((void ));
int getpgrp P((int p ));
int getpid P((void ));
int getppid P((void ));
int getsockname P((int s , char *name , int *namelen ));
int getsockopt P((int s , int level , int opt , char *buf , int *len ));
uid_t getuid P((void ));
int ioctl P((int d , u_long r , char *p ));
int kill P((int p , int s ));
int killpg P((int pg , int s ));
int link P((char *a , char *b ));
int listen P((int s , int b ));
off_t lseek P((int f , off_t o , int d ));
int madvise P((char *a , int l , int b ));
int mmap P((char *a , int l , int p , int s , int f , off_t o ));
int mincore P((char *a , int l , char *v ));
int mkdir P((char *p , int m ));
int mknod P((char *n , int m , int a ));
int mount P((int t , char *d , int f , caddr_t *dt ));
int mprotect P((char *a , int l , int p ));
int mremap P((char *a , int l , int p , int s , int f ));
int munmap P((char *a , int l ));
int open P((char *f , int m , int stuff ));
int pipe P((int f [2 ]));
int profil P((char *b , int s , int o , int i ));
int ptrace P((int r , int p , int *a , int d ));
int quota P((int c , int u , int a , char *ad ));
int read P((int f , char *b , int l ));
int readlink P((char *p , char *b , int s ));
int reboot P((int h ));
int recv P((int s , char *b , int l , int f ));
int rename P((char *f , char *t ));
int rmdir P((char *p ));
char *sbrk P((int i ));
int send P((int s , char *m , int l , int f ));
int setgroups P((int n , int *g ));
int sethostid P((long h ));
int sethostname P((char *n , int l ));
int setpgrp P((int g , int pg ));
int setpriority P((int w , int who , int pri ));
int setquota P((char *s , char *f ));
int setregid P((int r , int e ));
int setreuid P((int r , int e ));
int setsockopt P((int s , int level , int opt , char *buf , int len ));
int shutdown P((int s , int h ));
int sigblock P((int m ));
int sigsetmask P((int m ));
int sigpause P((int m ));
int socket P((int a , int t , int p ));
int socketpair P((int d , int t , int p , int s [2 ]));
char *stk P((char *a ));
char *sstk P((int a ));
int swapon P((char *s ));
int symlink P((char *t , char *f ));
int sync P((void ));
int truncate P((char *p , off_t l ));
int umask P((int n ));
int umount P((char *s ));
int unlink P((char *s ));
int vfork P((void ));
int vhangup P((void ));
int write P((int f , char *b , int l ));
int abs P((int i ));
int alarm P((unsigned s ));
double atof P((char *s ));
int atoi P((char *s ));
long atol P((char *s ));
int bcmp P((char *b1 , char *b2 , int length ));
int bcopy P((char *src , char *dst , int length ));
int bzero P((char *b , int length ));
char *calloc P((unsigned n , unsigned s ));
int closelog P((void ));
int creat P((char *s , int m ));
char *crypt P((char *k , char *s ));
char *ctime P((long *c ));
char *ecvt P((double v , int n , int *d , int *s ));
int encrypt P((char *s , int i ));
int endfsent P((void ));
int endgrent P((void ));
int endhostent P((void ));
int endnetent P((void ));
int endprotoent P((void ));
int endpwent P((void ));
int endservent P((void ));
int endttyent P((void ));
int endusershell P((void ));
int execl P((char *f , char *a ));
int execle P((char *f , char *a ));
int execlp P((char *f , char *a ));
int execv P((char *s , char *v []));
int execvp P((char *s , char *v []));
int exect P((char *s , char *v [], char *e []));
int exit P((int s ));
char *fcvt P((double v , int n , int *d , int *s ));
int ffs P((int i ));
int free P((char *p ));
double frexp P((double v , int *e ));
char *gcvt P((double v , int n , char *b ));
struct disktab *getdiskbyname P((char *name ));
char *getenv P((char *n ));
struct fstab *getfsent P((void ));
struct fstab *getfsspec P((char *n ));
struct fstab *getfsfile P((char *n ));
struct fstab *getfstype P((char *t ));
struct group *getgrent P((void ));
struct group *getgrgid P((int n ));
struct group *getgrnam P((char *n ));
struct hostent *gethostbyaddr P((char *addr , int len , int type ));
struct hostent *gethostbyname P((char *name ));
struct hostent *gethostent P((void ));
char *getlogin P((void ));
struct netent *getnetbyaddr P((int net , int type ));
struct netent *getnetbyname P((char *name ));
struct netent *getnetent P((void ));
int getopt P((int argc , char **argv , char *optstr ));
char *getpass P((char *n ));
struct protoent *getprotobyname P((char *name ));
struct protoent *getprotobynumber P((int proto ));
struct protoent *getprotoent P((void ));
int getpw P((int u , char *b ));
struct passwd *getpwent P((void ));
struct passwd *getpwuid P((int n ));
struct passwd *getpwnam P((char *n ));
struct servent *getservbyname P((char *name , char *proto ));
struct servent *getservbyport P((int port , char *proto ));
struct servent *getservent P((void ));
struct ttyent *getttynam P((char *name ));
char *getusershell P((void ));
char *getwd P((char *pathname ));
struct tm *gmtime P((long *c ));
u_long htonl P((u_long hostlong ));
u_short htons P((int hostshort ));
char *index P((char *s , int c ));
u_long inet_addr P((char *cp ));
u_long inet_network P((char *cp ));
int initgroups P((char *uname , int agroup ));
char *initstate P((unsigned s , char *st , int n ));
int isatty P((int f ));
double ldexp P((double v , int e ));
int longjmperror P((void ));
struct tm *localtime P((long *c ));
char *malloc P((unsigned n ));
char *memccpy P((char *t , char *f , int c , int n ));
char *memchr P((char *s , int c , int n ));
int memcmp P((char *s1 , char *s2 , int n ));
char *memcpy P((char *t , char *f , int n ));
char *memset P((char *s , int c , int n ));
char *mktemp P((char *p ));
int mkstemp P((char *p ));
double modf P((double v , double *p ));
int moncontrol P((int mode ));
int monitor P((int (*l )(), int (*h )(), short *b , int s , int n ));
int monstartup P((int (*l )(), int (*h )()));
int nice P((int incr ));
struct ns_addr ns_addr P((char *name ));
u_long ntohl P((u_long netlong ));
u_short ntohs P((int netshort ));
int openlog P((char *s , int f , int l ));
int pause P((void ));
int perror P((char *s ));
int psignal P((unsigned sig , char *s ));
int qsort P((char *b , int n , int w , int (*c )()));
int rand P((void ));
long random P((void ));
int rcmd P((char **a , u_short rp , char *lu , char *ru , char *c , int *f ));
char *re_comp P((char *s ));
int re_exec P((char *s ));
char *realloc P((char *p , unsigned n ));
int rexec P((char **a , u_short rp , char *n , char *p , char *c , int *f ));
char *rindex P((char *s , int c ));
int rresvport P((int *p ));
int ruserok P((char *rh , int su , char *ru , char *lu ));
int setegid P((gid_t egid ));
int seteuid P((uid_t euid ));
int setfsent P((void ));
int setgrent P((void ));
int setgid P((gid_t g ));
int sethostent P((int stayopen ));
int sethostfile P((char *name ));
int setkey P((char *k ));
int setlogmask P((int m ));
int setnetent P((int stayopen ));
int setprotoent P((int stayopen ));
int setpwent P((void ));
int setpwfile P((char *file ));
int setrgid P((gid_t rgid ));
int setruid P((uid_t ruid ));
int setservent P((int stayopen ));
char *setstate P((char *st ));
int setttyent P((void ));
int setuid P((uid_t u ));
int setusershell P((void ));
int siginterrupt P((int sig , int flag ));
int sleep P((unsigned i ));
int srand P((int s ));
char *strcat P((char *a , char *b ));
char *strcatn P((char *a , char *b , int n ));
char *strchr P((char *s , int c ));
int strcmp P((const char *a , const char *b ));
int strcmpn P((char *a , char *b , int n ));
char *strcpy P((char *a , const char *b ));
char *strcpyn P((char *a , char *b , int n ));
int strcspn P((char *s , char *set ));
int strlen P((const char *s ));
char *strncat P((char *a , const char *b , int n ));
int strncmp P((char *a , const char *b , int n ));
char *strncpy P((char *a , const char *b , int n ));
char *strpbrk P((char *s , char *brk ));
char *strrchr P(( char *s , int c ));
int strspn P((char *s , char *set ));
char *strtok P((char *s , char *sep ));
int swab P((char *f , char *t , int n ));
int syslog P((int l , char *f ));
int system P((char *s ));
long tell P((int f ));
long time P((long *t ));
char *timezone P((int z , int d ));
char *tmpnam P((char *s ));
char *ttyname P((int f ));
int ttyslot P((void ));
unsigned ualarm P((unsigned value , unsigned interval ));
int usleep P((unsigned useconds ));
int utime P((char *name , time_t *timep ));
char *valloc P((unsigned s ));
int vlimit P((int limit , int value ));
int printf P((char *s, ... ));
int puts P((char *s ));

#undef jmp_buf
#undef DBM

#endif /* VAX */
#undef P
