/*
 * appl/gssftp/ftpd/ftp_var.h
 *
 * Copyright 2001 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 *
 * Prototypes for various functions in the ftpd sources.
 */

#ifndef FTPD_VAR_H__
#define FTPD_VAR_H__

/* Prototypes */

#ifdef GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#endif

/* radix.c */
char *radix_error (int);
int radix_encode (unsigned char *, unsigned char *, int *, int);

/* ftpd.c */
void ack(char *);
int auth_data(char *);
void auth(char *);
void cwd(char *);
void delete_file(char *);
void dologout(int);
void fatal(char *);
void makedir(char *);
void nack(char *);
void pass(char *);
void passive(void);
void perror_reply(int, char *);
void pwd(void);
void removedir(char *);
void renamecmd(char *, char *);
char *renamefrom(char *);
void retrieve(char *, char *);
void send_file_list(char *);
void setdlevel(int);
void statcmd(void);
void statfilecmd(char *);
void store_file(char *, char *, int);
void user(char *);
void yyerror(char *);

#ifdef GSSAPI
void
reply_gss_error(int, OM_uint32, OM_uint32, char *);
#endif


#if defined(STDARG) || (defined(__STDC__) && ! defined(VARARGS)) || defined(HAVE_STDARG_H)
extern void reply(int, char *, ...)
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
     __attribute__ ((__format__ (__printf__, 2, 3)))
#endif
     ;
extern void lreply(int, char *, ...)
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
     __attribute__ ((__format__ (__printf__, 2, 3)))
#endif
     ;
#endif


/* ftpcmd.y */
void upper(char *);
char *getline(char *, int, FILE *);
#endif /* FTPD_VAR_H__ */

/* popen.c */
FILE * ftpd_popen(char *, char *);
int ftpd_pclose(FILE *);
