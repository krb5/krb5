#include <Kerberos/krb5.h>
#include <Kerberos/krb.h>

int
krb_create_ticket(
    KTEXT   tkt,                /* Gets filled in by the ticket */
    unsigned char flags,        /* Various Kerberos flags */
    char    *pname,             /* Principal's name */
    char    *pinstance,         /* Principal's instance */
    char    *prealm,            /* Principal's authentication domain */
    long    paddress,           /* Net address of requesting entity */
    char    *session,           /* Session key inserted in ticket */
    short   life,               /* Lifetime of the ticket */
    long    time_sec,           /* Issue time and date */
    char    *sname,             /* Service Name */
    char    *sinstance,         /* Instance Name */
    C_Block key);                /* Service's secret key */

extern int
krb_cr_tkt_krb5(
    KTEXT   tkt,                /* Gets filled in by the ticket */
    unsigned char flags,        /* Various Kerberos flags */
    char    *pname,             /* Principal's name */
    char    *pinstance,         /* Principal's instance */
    char    *prealm,            /* Principal's authentication domain */
    long    paddress,           /* Net address of requesting entity */
    char    *session,           /* Session key inserted in ticket */
    short   life,               /* Lifetime of the ticket */
    long    time_sec,           /* Issue time and date */
    char    *sname,             /* Service Name */
    char    *sinstance,         /* Instance Name */
    krb5_keyblock *k5key);	/* NULL if not present */
