#ifndef __ASSEMBLER__
#include <TargetConditionals.h>

/* Macros for crypto types so they don't conflict with KerberosDES */
#define make_key_sched 	mit_make_key_sched
#define des_FP_table 	mit_des_FP_table
#define des_IP_table  	mit_des_IP_table
#define des_SP_table  	mit_des_SP_table

#define SIZEOF_LONG		4
#define SIZEOF_INT		4
#define SIZEOF_SHORT	2

#define	KRB5_DLLIMP		
#define	GSS_DLLIMP		
#define KRB5_CALLCONV		
#define KRB5_CALLCONV_C		
#define	FAR			

#define	krb5_sigtype		void

/* Note: code only checks #ifdef <foo> */
#define USE_CCAPI			1
#define USE_LOGIN_LIBRARY	1
#define NO_PASSWORD			1

#define HAVE_SRAND			1
#define HAVE_LABS			1

#define HAVE_NETINET_IN_H	1
#define HAVE_ARPA_INET_H	1
#define HAVE_SYS_STAT_H		1
#define	HAVE_SYS_PARAM_H	1
#define	HAVE_UNISTD_H		1
#define	HAVE_STDLIB_H		1
#define	HAVE_STDARG_H		1
#define HAVE_SYS_TYPES_H	1
#define	HAVE_PATHS_H		1
#define	HAVE_REGEX_H		1
#define	HAVE_REGEXP_H		1
#define	HAVE_FCNTL_H		1
#define	HAVE_MEMORY_H		1
#define HAVE_PWD_H			1

#define HAVE_PTHREADS	1

#define	HAVE_STAT		1
#define	HAVE_ACCESS		1
#define	HAVE_FLOCK		1

#define	HAVE_FCHMOD		1
#define	HAVE_CHMOD		1

#define	HAVE_STRFTIME		1
#define	HAVE_GETEUID		1

#define	HAVE_SETENV		1
#define	HAVE_UNSETENV		1
#define	HAVE_GETENV		1

#define	HAVE_SETSID		1
#define	HAVE_GETHOSTBYNAME2	1

#define	HAVE_VFPRINTF		1
#define	HAVE_VSPRINTF		1

#define	HAVE_STRDUP		1
#define	HAVE_STRCASECMP		1
#define	HAVE_STRERROR		1
#define	HAVE_MEMMOVE		1
#define	HAVE_DAEMON		1
#define	HAVE_GETUID		1
#define	HAVE_SSCANF		1
#define	HAVE_SYSLOG		1
#define	HAVE_REGEXEC		1
#define	HAVE_REGCOMP		1
#define	HAVE_SA_LEN		1
#endif
