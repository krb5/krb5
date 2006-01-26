/*
 * include/kerberosIV/kadm.h
 *
 * Copyright 1988, 1994, 2002 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * Definitions for Kerberos administration server & client.  These
 * should be considered private; among other reasons, it leaks all
 * over the namespace.
 */

#ifndef KADM_DEFS
#define KADM_DEFS

/*
 * kadm.h
 * Header file for the fourth attempt at an admin server
 * Doug Church, December 28, 1989, MIT Project Athena
 */

#include <sys/types.h>
#include "port-sockets.h"
#include <kerberosIV/krb.h>
#include <kerberosIV/des.h>

/* for those broken Unixes without this defined... should be in sys/param.h */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

/* The global structures for the client and server */
typedef struct {
    struct sockaddr_in admin_addr;
    struct sockaddr_in my_addr;
    int my_addr_len;
    int admin_fd;		/* file descriptor for link to admin server */
    char sname[ANAME_SZ];	/* the service name */
    char sinst[INST_SZ];	/* the services instance */
    char krbrlm[REALM_SZ];
    /* KfM additions... */
    int  default_port;
    CREDENTIALS creds; /* The client's credentials (from krb_get_pw_in_tkt_creds)*/
} Kadm_Client;

typedef struct {		/* status of the server, i.e the parameters */
    int inter;			/* Space for command line flags */
    char *sysfile;		/* filename of server */
} admin_params;			/* Well... it's the admin's parameters */

/* Largest password length to be supported */
#define MAX_KPW_LEN	128

/* Largest packet the admin server will ever allow itself to return */
#define KADM_RET_MAX 2048

/* That's right, versions are 8 byte strings */
#define KADM_VERSTR	"KADM0.0A"
#define KADM_ULOSE	"KYOULOSE"	/* sent back when server can't
					   decrypt client's msg */
#define KADM_VERSIZE strlen(KADM_VERSTR)

/* the lookups for the server instances */
#define PWSERV_NAME  "changepw"
#define KADM_SNAME   "kerberos_master"
#define KADM_SINST   "kerberos"

/* Attributes fields constants and macros */
#define ALLOC        2
#define RESERVED     3
#define DEALLOC      4
#define DEACTIVATED  5
#define ACTIVE       6

/* Kadm_vals structure for passing db fields into the server routines */
#define FLDSZ        4

typedef struct {
    u_char         fields[FLDSZ];     /* The active fields in this struct */
    char           name[ANAME_SZ];
    char           instance[INST_SZ];
    KRB_UINT32     key_low;
    KRB_UINT32     key_high;
    KRB_UINT32     exp_date;
    unsigned short attributes;
    unsigned char  max_life;
} Kadm_vals;                    /* The basic values structure in Kadm */

/* Kadm_vals structure for passing db fields into the server routines */
#define FLDSZ        4

/* Need to define fields types here */
#define KADM_NAME       31
#define KADM_INST       30
#define KADM_EXPDATE    29
#define KADM_ATTR       28
#define KADM_MAXLIFE    27
#define KADM_DESKEY     26

/* To set a field entry f in a fields structure d */
#define SET_FIELD(f,d)  (d[3-(f/8)]|=(1<<(f%8)))

/* To set a field entry f in a fields structure d */
#define CLEAR_FIELD(f,d)  (d[3-(f/8)]&=(~(1<<(f%8))))

/* Is field f in fields structure d */
#define IS_FIELD(f,d)   (d[3-(f/8)]&(1<<(f%8)))

/* Various return codes */
#define KADM_SUCCESS    0

#define WILDCARD_STR "*"

enum acl_types {
ADDACL,
GETACL,
MODACL,
STABACL,
DELACL
};

/* Various opcodes for the admin server's functions */
#define CHANGE_PW    2
#define ADD_ENT      3
#define MOD_ENT      4
#define GET_ENT      5
#define CHECK_PW     6
#define CHG_STAB     7
/* Cygnus principal-deletion support */
#define KADM_CYGNUS_EXT_BASE 64
#define DEL_ENT              (KADM_CYGNUS_EXT_BASE+1)

#ifdef POSIX
typedef void sigtype;
#else
typedef int sigtype;
#endif

/* Avoid stomping on namespace... */

#define vals_to_stream		kadm_vals_to_stream
#define build_field_header	kadm_build_field_header
#define vts_string		kadm_vts_string
#define vts_short		kadm_vts_short
#define vts_long		kadm_vts_long
#define vts_char		kadm_vts_char

#define stream_to_vals		kadm_stream_to_vals
#define check_field_header	kadm_check_field_header
#define stv_string		kadm_stv_string
#define stv_short		kadm_stv_short
#define stv_long		kadm_stv_long
#define stv_char		kadm_stv_char

int vals_to_stream(Kadm_vals *, u_char **);
int build_field_header(u_char *, u_char **);
int vts_string(char *, u_char **, int);
int vts_short(KRB_UINT32, u_char **, int);
int vts_long(KRB_UINT32, u_char **, int);
int vts_char(KRB_UINT32, u_char **, int);

int stream_to_vals(u_char *, Kadm_vals *, int);
int check_field_header(u_char *, u_char *, int);
int stv_string(u_char *, char *, int, int, int);
int stv_short(u_char *, u_short *, int, int);
int stv_long(u_char *, KRB_UINT32 *, int, int);
int stv_char(u_char *, u_char *, int, int);

int kadm_init_link(char *, char *, char *, Kadm_Client *, int);
int kadm_cli_send(Kadm_Client *, u_char *, size_t, u_char **, size_t *);
int kadm_cli_conn(Kadm_Client *);
void kadm_cli_disconn(Kadm_Client *);
int kadm_cli_out(Kadm_Client *, u_char *, int, u_char **, size_t *);
int kadm_cli_keyd(Kadm_Client *, des_cblock, des_key_schedule);

#endif /* KADM_DEFS */
