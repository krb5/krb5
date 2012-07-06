/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* slave/kprop.c */
/*
 * Copyright 1990,1991,2008 by the Massachusetts Institute of Technology.
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
 */

#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/file.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <netdb.h>
#include <fcntl.h>

#include "k5-int.h"
#include "com_err.h"
#include "fake-addrinfo.h"
#include "kprop.h"

#ifndef GETSOCKNAME_ARG3_TYPE
#define GETSOCKNAME_ARG3_TYPE unsigned int
#endif

static char *kprop_version = KPROP_PROT_VERSION;

char    *progname = 0;
int     debug = 0;
char    *srvtab = 0;
char    *slave_host;
char    *realm = 0;
char    *file = KPROP_DEFAULT_FILE;

krb5_principal  my_principal;           /* The Kerberos principal we'll be */
/* running under, initialized in */
/* get_tickets() */
krb5_ccache     ccache;         /* Credentials cache which we'll be using */
krb5_creds      creds;
krb5_address    *sender_addr;
krb5_address    *receiver_addr;
const char      *port = KPROP_SERVICE;

void    PRS(int, char **);
void    get_tickets(krb5_context);
static void usage(void);
static void open_connection(krb5_context, char *, int *);
void    kerberos_authenticate(krb5_context, krb5_auth_context *,
                              int, krb5_principal, krb5_creds **);
int     open_database(krb5_context, char *, int *);
void    close_database(krb5_context, int);
void    xmit_database(krb5_context, krb5_auth_context, krb5_creds *,
                      int, int, int);
void    send_error(krb5_context, krb5_creds *, int, char *, krb5_error_code);
void    update_last_prop_file(char *, char *);

static void usage()
{
    fprintf(stderr, _("\nUsage: %s [-r realm] [-f file] [-d] [-P port] "
                      "[-s srvtab] slave_host\n\n"), progname);
    exit(1);
}

int
main(argc, argv)
    int     argc;
    char    **argv;
{
    int     fd, database_fd, database_size;
    krb5_error_code retval;
    krb5_context context;
    krb5_creds *my_creds;
    krb5_auth_context auth_context;

    setlocale(LC_ALL, "");
    retval = krb5_init_context(&context);
    if (retval) {
        com_err(argv[0], retval, _("while initializing krb5"));
        exit(1);
    }
    PRS(argc, argv);
    get_tickets(context);

    database_fd = open_database(context, file, &database_size);
    open_connection(context, slave_host, &fd);
    kerberos_authenticate(context, &auth_context, fd, my_principal,
                          &my_creds);
    xmit_database(context, auth_context, my_creds, fd, database_fd,
                  database_size);
    update_last_prop_file(slave_host, file);
    printf(_("Database propagation to %s: SUCCEEDED\n"), slave_host);
    krb5_free_cred_contents(context, my_creds);
    close_database(context, database_fd);
    exit(0);
}

void PRS(argc, argv)
    int     argc;
    char    **argv;
{
    register char   *word, ch;

    progname = *argv++;
    while (--argc && (word = *argv++)) {
        if (*word == '-') {
            word++;
            while (word && (ch = *word++)) {
                switch(ch){
                case 'r':
                    if (*word)
                        realm = word;
                    else
                        realm = *argv++;
                    if (!realm)
                        usage();
                    word = 0;
                    break;
                case 'f':
                    if (*word)
                        file = word;
                    else
                        file = *argv++;
                    if (!file)
                        usage();
                    word = 0;
                    break;
                case 'd':
                    debug++;
                    break;
                case 'P':
                    port = (*word != '\0') ? word : *argv++;
                    if (port == NULL)
                        usage();
                    word = 0;
                    break;
                case 's':
                    if (*word)
                        srvtab = word;
                    else
                        srvtab = *argv++;
                    if (!srvtab)
                        usage();
                    word = 0;
                    break;
                default:
                    usage();
                }

            }
        } else {
            if (slave_host)
                usage();
            else
                slave_host = word;
        }
    }
    if (!slave_host)
        usage();
}

void get_tickets(context)
    krb5_context context;
{
    char   buf[BUFSIZ], *def_realm;
    krb5_error_code retval;
    static char tkstring[] = "/tmp/kproptktXXXXXX";
    krb5_keytab keytab = NULL;

    /*
     * Figure out what tickets we'll be using to send stuff
     */
    retval = krb5_sname_to_principal(context, NULL, NULL,
                                     KRB5_NT_SRV_HST, &my_principal);
    if (retval) {
        com_err(progname, errno, _("while setting client principal name"));
        exit(1);
    }
    if (realm) {
        retval = krb5_set_principal_realm(context, my_principal, realm);
        if (retval) {
            com_err(progname, errno,
                    _("while setting client principal realm"));
            exit(1);
        }
    } else if (krb5_is_referral_realm(krb5_princ_realm(context,
                                                       my_principal))) {
        /* We're going to use this as a client principal, so it can't have the
         * referral realm.  Use the default realm instead. */
        retval = krb5_get_default_realm(context, &def_realm);
        if (retval) {
            com_err(progname, errno, _("while getting default realm"));
            exit(1);
        }
        retval = krb5_set_principal_realm(context, my_principal, def_realm);
        if (retval) {
            com_err(progname, errno,
                    _("while setting client principal realm"));
            exit(1);
        }
    }

#if 0
    krb5_princ_type(context, my_principal) = KRB5_NT_PRINCIPAL;
#endif

    /*
     * Initialize cache file which we're going to be using
     */
    (void) mktemp(tkstring);
    snprintf(buf, sizeof(buf), "FILE:%s", tkstring);

    retval = krb5_cc_resolve(context, buf, &ccache);
    if (retval) {
        com_err(progname, retval, _("while opening credential cache %s"), buf);
        exit(1);
    }

    retval = krb5_cc_initialize(context, ccache, my_principal);
    if (retval) {
        com_err(progname, retval, _("when initializing cache %s"), buf);
        exit(1);
    }

    /*
     * Get the tickets we'll need.
     *
     * Construct the principal name for the slave host.
     */
    memset(&creds, 0, sizeof(creds));
    retval = krb5_sname_to_principal(context,
                                     slave_host, KPROP_SERVICE_NAME,
                                     KRB5_NT_SRV_HST, &creds.server);
    if (retval) {
        com_err(progname, errno, _("while setting server principal name"));
        (void) krb5_cc_destroy(context, ccache);
        exit(1);
    }
    if (realm) {
        retval = krb5_set_principal_realm(context, creds.server, realm);
        if (retval) {
            com_err(progname, errno,
                    _("while setting server principal realm"));
            exit(1);
        }
    }

    /*
     * Now fill in the client....
     */
    retval = krb5_copy_principal(context, my_principal, &creds.client);
    if (retval) {
        com_err(progname, retval, _("while copying client principal"));
        (void) krb5_cc_destroy(context, ccache);
        exit(1);
    }
    if (srvtab) {
        retval = krb5_kt_resolve(context, srvtab, &keytab);
        if (retval) {
            com_err(progname, retval, _("while resolving keytab"));
            (void) krb5_cc_destroy(context, ccache);
            exit(1);
        }
    }

    retval = krb5_get_in_tkt_with_keytab(context, 0, 0, NULL,
                                         NULL, keytab, ccache, &creds, 0);
    if (retval) {
        com_err(progname, retval, _("while getting initial ticket\n"));
        (void) krb5_cc_destroy(context, ccache);
        exit(1);
    }

    if (keytab)
        (void) krb5_kt_close(context, keytab);

    /*
     * Now destroy the cache right away --- the credentials we
     * need will be in my_creds.
     */
    retval = krb5_cc_destroy(context, ccache);
    if (retval) {
        com_err(progname, retval, _("while destroying ticket cache"));
        exit(1);
    }
}

static void
open_connection(krb5_context context, char *host, int *fd_out)
{
    int     s;
    krb5_error_code retval;
    GETSOCKNAME_ARG3_TYPE socket_length;
    struct addrinfo hints, *res, *answers;
    struct sockaddr *sa;
    struct sockaddr_storage my_sin;
    int error;

    *fd_out = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    error = getaddrinfo(host, port, &hints, &answers);
    if (error != 0) {
        com_err(progname, 0, "%s: %s", host, gai_strerror(error));
        exit(1);
    }

    s = -1;
    retval = EINVAL;
    for (res = answers; res != NULL; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            com_err(progname, errno, _("while creating socket"));
            exit(1);
        }

        if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
            retval = errno;
            close(s);
            s = -1;
            continue;
        }

        /* We successfully connect()ed */
        *fd_out = s;
        retval = sockaddr2krbaddr(context, res->ai_family, res->ai_addr,
                                  &receiver_addr);
        if (retval != 0) {
            com_err(progname, retval, _("while converting server address"));
            exit(1);
        }

        break;
    }

    freeaddrinfo(answers);

    if (s == -1) {
        com_err(progname, retval, _("while connecting to server"));
        exit(1);
    }

    /* Set sender_addr. */
    socket_length = sizeof(my_sin);
    if (getsockname(s, (struct sockaddr *)&my_sin, &socket_length) < 0) {
        com_err(progname, errno, _("while getting local socket address"));
        exit(1);
    }
    sa = (struct sockaddr *) &my_sin;
    if (sockaddr2krbaddr(context, sa->sa_family, sa, &sender_addr) != 0) {
        com_err(progname, errno, _("while converting local address"));
        exit(1);
    }
}


void kerberos_authenticate(context, auth_context, fd, me, new_creds)
    krb5_context context;
    krb5_auth_context *auth_context;
    int fd;
    krb5_principal me;
    krb5_creds ** new_creds;
{
    krb5_error_code retval;
    krb5_error      *error = NULL;
    krb5_ap_rep_enc_part    *rep_result;

    retval = krb5_auth_con_init(context, auth_context);
    if (retval)
        exit(1);

    krb5_auth_con_setflags(context, *auth_context,
                           KRB5_AUTH_CONTEXT_DO_SEQUENCE);

    retval = krb5_auth_con_setaddrs(context, *auth_context, sender_addr,
                                    receiver_addr);
    if (retval) {
        com_err(progname, retval, _("in krb5_auth_con_setaddrs"));
        exit(1);
    }

    retval = krb5_sendauth(context, auth_context, (void *)&fd,
                           kprop_version, me, creds.server,
                           AP_OPTS_MUTUAL_REQUIRED, NULL, &creds, NULL,
                           &error, &rep_result, new_creds);
    if (retval) {
        com_err(progname, retval, _("while authenticating to server"));
        if (error) {
            if (error->error == KRB_ERR_GENERIC) {
                if (error->text.data) {
                    fprintf(stderr, _("Generic remote error: %s\n"),
                            error->text.data);
                }
            } else if (error->error) {
                com_err(progname,
                        (krb5_error_code) error->error + ERROR_TABLE_BASE_krb5,
                        _("signalled from server"));
                if (error->text.data) {
                    fprintf(stderr, _("Error text from server: %s\n"),
                            error->text.data);
                }
            }
            krb5_free_error(context, error);
        }
        exit(1);
    }
    krb5_free_ap_rep_enc_part(context, rep_result);
}

char * dbpathname;
/*
 * Open the Kerberos database dump file.  Takes care of locking it
 * and making sure that the .ok file is more recent that the database
 * dump file itself.
 *
 * Returns the file descriptor of the database dump file.  Also fills
 * in the size of the database file.
 */
int
open_database(context, data_fn, size)
    krb5_context context;
    char *data_fn;
    int *size;
{
    int             fd;
    int             err;
    struct stat     stbuf, stbuf_ok;
    char            *data_ok_fn;
    static char ok[] = ".dump_ok";

    dbpathname = strdup(data_fn);
    if (!dbpathname) {
        com_err(progname, ENOMEM, _("allocating database file name '%s'"),
                data_fn);
        exit(1);
    }
    if ((fd = open(dbpathname, O_RDONLY)) < 0) {
        com_err(progname, errno, _("while trying to open %s"),
                dbpathname);
        exit(1);
    }

    err = krb5_lock_file(context, fd,
                         KRB5_LOCKMODE_SHARED|KRB5_LOCKMODE_DONTBLOCK);
    if (err == EAGAIN || err == EWOULDBLOCK || errno == EACCES) {
        com_err(progname, 0, _("database locked"));
        exit(1);
    } else if (err) {
        com_err(progname, err, _("while trying to lock '%s'"), dbpathname);
        exit(1);
    }
    if (fstat(fd, &stbuf)) {
        com_err(progname, errno, _("while trying to stat %s"), data_fn);
        exit(1);
    }
    if (asprintf(&data_ok_fn, "%s%s", data_fn, ok) < 0) {
        com_err(progname, ENOMEM, _("while trying to malloc data_ok_fn"));
        exit(1);
    }
    if (stat(data_ok_fn, &stbuf_ok)) {
        com_err(progname, errno, _("while trying to stat %s"), data_ok_fn);
        free(data_ok_fn);
        exit(1);
    }
    if (stbuf.st_mtime > stbuf_ok.st_mtime) {
        com_err(progname, 0, _("'%s' more recent than '%s'."),
                data_fn, data_ok_fn);
        exit(1);
    }
    free(data_ok_fn);
    *size = stbuf.st_size;
    return(fd);
}

void
close_database(context, fd)
    krb5_context context;
    int fd;
{
    int err;
    err = krb5_lock_file(context, fd, KRB5_LOCKMODE_UNLOCK);
    if (err)
        com_err(progname, err, _("while unlocking database '%s'"), dbpathname);
    free(dbpathname);
    (void)close(fd);
    return;
}

/*
 * Now we send over the database.  We use the following protocol:
 * Send over a KRB_SAFE message with the size.  Then we send over the
 * database in blocks of KPROP_BLKSIZE, encrypted using KRB_PRIV.
 * Then we expect to see a KRB_SAFE message with the size sent back.
 *
 * At any point in the protocol, we may send a KRB_ERROR message; this
 * will abort the entire operation.
 */
void
xmit_database(context, auth_context, my_creds, fd, database_fd,
              in_database_size)
    krb5_context context;
    krb5_auth_context auth_context;
    krb5_creds *my_creds;
    int fd;
    int database_fd;
    int in_database_size;
{
    krb5_int32      sent_size, n;
    krb5_data       inbuf, outbuf;
    char            buf[KPROP_BUFSIZ];
    krb5_error_code retval;
    krb5_error      *error;
    /* These must be 4 bytes */
    krb5_ui_4       database_size = in_database_size;
    krb5_ui_4       send_size;

    /*
     * Send over the size
     */
    send_size = htonl(database_size);
    inbuf.data = (char *) &send_size;
    inbuf.length = sizeof(send_size); /* must be 4, really */
    /* KPROP_CKSUMTYPE */
    retval = krb5_mk_safe(context, auth_context, &inbuf,
                          &outbuf, NULL);
    if (retval) {
        com_err(progname, retval, _("while encoding database size"));
        send_error(context, my_creds, fd, _("while encoding database size"),
                   retval);
        exit(1);
    }

    retval = krb5_write_message(context, (void *) &fd, &outbuf);
    if (retval) {
        krb5_free_data_contents(context, &outbuf);
        com_err(progname, retval, _("while sending database size"));
        exit(1);
    }
    krb5_free_data_contents(context, &outbuf);
    /*
     * Initialize the initial vector.
     */
    retval = krb5_auth_con_initivector(context, auth_context);
    if (retval) {
        send_error(context, my_creds, fd,
                   "failed while initializing i_vector", retval);
        com_err(progname, retval, _("while allocating i_vector"));
        exit(1);
    }

    /*
     * Send over the file, block by block....
     */
    inbuf.data = buf;
    sent_size = 0;
    while ((n = read(database_fd, buf, sizeof(buf)))) {
        inbuf.length = n;
        retval = krb5_mk_priv(context, auth_context, &inbuf,
                              &outbuf, NULL);
        if (retval) {
            snprintf(buf, sizeof(buf),
                     "while encoding database block starting at %d",
                     sent_size);
            com_err(progname, retval, "%s", buf);
            send_error(context, my_creds, fd, buf, retval);
            exit(1);
        }

        retval = krb5_write_message(context, (void *)&fd,&outbuf);
        if (retval) {
            krb5_free_data_contents(context, &outbuf);
            com_err(progname, retval,
                    _("while sending database block starting at %d"),
                    sent_size);
            exit(1);
        }
        krb5_free_data_contents(context, &outbuf);
        sent_size += n;
        if (debug)
            printf("%d bytes sent.\n", sent_size);
    }
    if (sent_size != database_size) {
        com_err(progname, 0, _("Premature EOF found for database file!"));
        send_error(context, my_creds, fd,"Premature EOF found for database file!",
                   KRB5KRB_ERR_GENERIC);
        exit(1);
    }

    /*
     * OK, we've sent the database; now let's wait for a success
     * indication from the remote end.
     */
    retval = krb5_read_message(context, (void *) &fd, &inbuf);
    if (retval) {
        com_err(progname, retval, _("while reading response from server"));
        exit(1);
    }
    /*
     * If we got an error response back from the server, display
     * the error message
     */
    if (krb5_is_krb_error(&inbuf)) {
        retval = krb5_rd_error(context, &inbuf, &error);
        if (retval) {
            com_err(progname, retval,
                    _("while decoding error response from server"));
            exit(1);
        }
        if (error->error == KRB_ERR_GENERIC) {
            if (error->text.data) {
                fprintf(stderr, _("Generic remote error: %s\n"),
                        error->text.data);
            }
        } else if (error->error) {
            com_err(progname,
                    (krb5_error_code) error->error +
                    ERROR_TABLE_BASE_krb5,
                    _("signalled from server"));
            if (error->text.data) {
                fprintf(stderr, _("Error text from server: %s\n"),
                        error->text.data);
            }
        }
        krb5_free_error(context, error);
        exit(1);
    }

    retval = krb5_rd_safe(context,auth_context,&inbuf,&outbuf,NULL);
    if (retval) {
        com_err(progname, retval,
                "while decoding final size packet from server");
        exit(1);
    }

    memcpy(&send_size, outbuf.data, sizeof(send_size));
    send_size = ntohl(send_size);
    if (send_size != database_size) {
        com_err(progname, 0,
                _("Kpropd sent database size %d, expecting %d"),
                send_size, database_size);
        exit(1);
    }
    free(outbuf.data);
    /* inbuf.data points to local storage */
}

void
send_error(context, my_creds, fd, err_text, err_code)
    krb5_context context;
    krb5_creds *my_creds;
    int fd;
    char        *err_text;
    krb5_error_code     err_code;
{
    krb5_error      error;
    const char      *text;
    krb5_data       outbuf;

    memset(&error, 0, sizeof(error));
    krb5_us_timeofday(context, &error.ctime, &error.cusec);
    error.server = my_creds->server;
    error.client = my_principal;
    error.error = err_code - ERROR_TABLE_BASE_krb5;
    if (error.error > 127)
        error.error = KRB_ERR_GENERIC;
    if (err_text)
        text = err_text;
    else
        text = error_message(err_code);
    error.text.length = strlen(text) + 1;
    error.text.data = strdup(text);
    if (error.text.data) {
        if (!krb5_mk_error(context, &error, &outbuf)) {
            (void) krb5_write_message(context, (void *)&fd,&outbuf);
            krb5_free_data_contents(context, &outbuf);
        }
        free(error.text.data);
    }
}

void update_last_prop_file(hostname, file_name)
    char *hostname;
    char *file_name;
{
    /* handle slave locking/failure stuff */
    char *file_last_prop;
    int fd;
    static char last_prop[]=".last_prop";

    if (asprintf(&file_last_prop, "%s.%s%s", file_name, hostname,
                 last_prop) < 0) {
        com_err(progname, ENOMEM,
                _("while allocating filename for update_last_prop_file"));
        return;
    }
    if ((fd = THREEPARAMOPEN(file_last_prop, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
        com_err(progname, errno, _("while creating 'last_prop' file, '%s'"),
                file_last_prop);
        free(file_last_prop);
        return;
    }
    write(fd, "", 1);
    free(file_last_prop);
    close(fd);
    return;
}
