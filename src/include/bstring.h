/*
 * #include file for bstring(3) & sys5 version functions
 * home.
 */
#ifndef __BSTRING__
#define __BSTRING__
#if defined(__STDC__) || defined(_WINDOWS)
/* compat-sys5 */
/* these are in <string.h> */
extern int bcmp  (const char *, const char *, int );
extern int bcopy  (const char *, char *, int );
extern int bzero  (char *, int );
#else /* STDC */
/* compat-sys5 */
extern char *memccpy  ();
extern char *memchr  ();
extern int memcmp  ();
extern char *memcpy  ();
extern char *memset  ();

extern int bcmp  ();
extern int bcopy  ();
extern int bzero  ();

#endif /* STDC */
#endif /* __BSTRING__ */
