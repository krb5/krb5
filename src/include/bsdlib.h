/*
 * generic #include file for BSD libc functions which have no other logical
 * home.
 */
#ifndef __BSDLIB__
#define __BSDLIB__
#if defined(__STDC__) || defined(_WINDOWS)
/* compat-4.3 */
extern char *ecvt  (double , int , int *, int *);
extern char *fcvt  (double , int , int *, int *);
extern char *gcvt  (double , int , char *);

/* compat-4.1 */
extern int getpw  (int , char []);
extern int nice  (int );
extern int pause  (void );
extern int srand  (unsigned );
extern int rand  (void );
extern long tell  (int );
extern int utime  (char *, const int []);
extern int vlimit  (int , int );


/* compat-sys5 */
extern int getopt  (int , const char * const *, const char *);
#ifdef FILE
/* XXX depends on stdio #define of FILE */
extern FILE *tmpfile (void);
#endif


extern char *tmpnam  (char *);
extern char *tempnam  (const char *, const char *);


/* other random stuff-- some goes into stdlib.h? */
int abort  (void );
int alarm  (int );
int atoi  (const char *);
long atol  (const char *);

int setkey  (const char *);
int encrypt  (char *, int );
char *crypt  (const char *, const char *);

int ffs  (long );

char *getenv  (const char *);
int setenv  (const char *, const char *, int );
void unsetenv  (const char *);

char *getlogin  (void );
char *getpass  (const char *);
char *getwd  (char *);

char *getusershell  (void );
int endusershell  (void );
int setusershell  (void );

int initgroups  (const char *, int );

struct qelem {
    struct qelem *q_forw;
    struct qelem *q_back;
    char q_data[1];
};

int insque  (struct qelem *, struct qelem *); 
int remque  (struct qelem *); 

int isatty  (int );

int mkstemp  (char *);
char *mktemp  (char *);

int qsort  (char *, int, int, int (*)(char *, char *));

int srandom  (unsigned );
char *initstate  (unsigned , char *, int );
char *setstate  (char *);
long random  (void );

char *re_comp  (const char *);
int re_exec  (const char *);
int backref  (int , const char *);
int cclass  (const char *, int , int );

int setegid  (int );
int seteuid  (int );
int setgid  (int );
int setrgid  (int );
int setruid  (int );
int setuid  (int );

int sleep  (unsigned );

int swab  (char *, char *, int );

int system  (const char *);

char *ttyname  (int );
int ttyslot  (void );

unsigned ualarm  (unsigned , unsigned );
int usleep  (unsigned );
#else /* STDC */
/* compat-4.3 */
extern char *ecvt  ();
extern char *fcvt  ();
extern char *gcvt  ();

/* compat-4.1 */
extern int getpw  ();
extern int nice  ();
extern int pause  ();
extern int srand  ();
extern int rand  ();
extern long tell  ();
extern int utime  ();
extern int vlimit  ();

/* compat-sys5 */
extern int getopt  ();
#ifdef FILE
/* XXX depends on stdio #define of FILE */
extern FILE *tmpfile ();
#endif
extern char *tmpnam  ();
extern char *tempnam  ();

/* other random stuff-- some goes into stdlib.h? */
int abort  ();
int alarm  ();
int atoi  ();
long atol  ();

int setkey  ();
int encrypt  ();
char *crypt  ();

int ffs  ();

char *getenv  ();
int setenv  ();
void unsetenv  ();

char *getlogin  ();
char *getpass  ();
char *getwd  ();

char *getusershell  ();
int endusershell  ();
int setusershell  ();

int initgroups  ();

int insque  (); 
int remque  (); 

int isatty  ();

int mkstemp  ();
char *mktemp  ();

int qsort  ();

int srandom  ();
char *initstate  ();
char *setstate  ();
long random  ();

char *re_comp  ();
int re_exec  ();
int backref  ();
int cclass  ();

int setegid  ();
int seteuid  ();
int setgid  ();
int setrgid  ();
int setruid  ();
int setuid  ();

int sleep  ();

int swab  ();

int system  ();

char *ttyname  ();
int ttyslot  ();

unsigned ualarm  ();
int usleep  ();
#endif /* STDC */

#endif /* __BSDLIB__ */
