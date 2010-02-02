/* fallback pathnames */

#ifdef RPROGS_IN_USR_UCB
#define	UCB_RLOGIN	"/usr/ucb/rlogin"
#define	UCB_RCP	"/usr/ucb/rcp"
#define	UCB_RSH	"/usr/ucb/rsh"
/* all in /usr/ucb/, don't look for /bin/rcp */
#endif

#ifdef RPROGS_IN_USR_BIN
#define UCB_RLOGIN "/usr/bin/rlogin"
#define UCB_RCP "/usr/bin/rcp"
#define UCB_RSH "/usr/bin/rsh"
#endif

#ifdef RPROGS_IN_USR_BSD
#define UCB_RLOGIN "/usr/bsd/rlogin"
#define UCB_RCP "/usr/bsd/rcp"
#define UCB_RSH "/usr/bsd/rsh"
#endif

#ifdef RSH_IS_RCMD
#undef UCB_RSH
#define UCB_RSH "/usr/bin/rcmd"
#endif

#ifdef RSH_IS_REMSH
#undef UCB_RSH
#define UCB_RSH "/usr/bin/remsh"
#endif

