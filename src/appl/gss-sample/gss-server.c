/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Copyright (C) 2004,2005 by the Massachusetts Institute of Technology.
 * All rights reserved.
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

#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#include <winsock.h>
#else
#include "port-sockets.h"
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <ctype.h>

#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
#include "gss-misc.h"

#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#define FLAG_EXPORT 1
#define FLAG_S4U    2
#define FLAG_ANON   4

static OM_uint32
enumerateAttributes(OM_uint32 *minor, gss_name_t name, int noisy);

static OM_uint32
kerberosProtocolTransition(OM_uint32 *minor,
                           gss_name_t authenticatedInitiator,
                           int flags);

static void
usage()
{
    fprintf(stderr, "Usage: gss-server [-port port] [-verbose] [-once]");
#ifdef _WIN32
    fprintf(stderr, " [-threads num]");
#endif
    fprintf(stderr, "\n");
    fprintf(stderr,
            "       [-inetd] [-export] [-logfile file] [-keytab keytab]\n"
            "       service_name\n");
    exit(1);
}

static FILE *logfile;

int     verbose = 0;

/*
 * Function: server_acquire_creds
 *
 * Purpose: imports a service name and acquires credentials for it
 *
 * Arguments:
 *
 *      service_name    (r) the ASCII service name
 *      server_creds    (w) the GSS-API service credentials
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * The service name is imported with gss_import_name, and service
 * credentials are acquired with gss_acquire_cred.  If either opertion
 * fails, an error message is displayed and -1 is returned; otherwise,
 * 0 is returned.
 */

static int
server_acquire_creds(char *service_name, gss_cred_id_t *server_creds)
{
    gss_buffer_desc name_buf;
    gss_name_t server_name;
    OM_uint32 maj_stat, min_stat;

    name_buf.value = service_name;
    name_buf.length = strlen(name_buf.value) + 1;
    maj_stat = gss_import_name(&min_stat, &name_buf,
                               (gss_OID) gss_nt_service_name, &server_name);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("importing name", maj_stat, min_stat);
        return -1;
    }

    maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
                                GSS_C_NO_OID_SET, GSS_C_ACCEPT,
                                server_creds, NULL, NULL);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("acquiring credentials", maj_stat, min_stat);
        return -1;
    }

    (void) gss_release_name(&min_stat, &server_name);

    return 0;
}

/*
 * Function: server_establish_context
 *
 * Purpose: establishses a GSS-API context as a specified service with
 * an incoming client, and returns the context handle and associated
 * client name
 *
 * Arguments:
 *
 *      s               (r) an established TCP connection to the client
 *      service_creds   (r) server credentials, from gss_acquire_cred
 *      context         (w) the established GSS-API context
 *      client_name     (w) the client's ASCII name
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * Any valid client request is accepted.  If a context is established,
 * its handle is returned in context and the client name is returned
 * in client_name and 0 is returned.  If unsuccessful, an error
 * message is displayed and -1 is returned.
 */
static int
server_establish_context(int s, gss_cred_id_t server_creds, int flags,
                         gss_ctx_id_t *context, gss_buffer_t client_name,
                         OM_uint32 *ret_flags)
{
    gss_buffer_desc send_tok, recv_tok;
    gss_name_t client;
    gss_OID doid;
    OM_uint32 maj_stat, min_stat, acc_sec_min_stat;
    gss_buffer_desc oid_name;
    int     token_flags;

    if (recv_token(s, &token_flags, &recv_tok) < 0)
        return -1;

    if (recv_tok.value) {
        free(recv_tok.value);
        recv_tok.value = NULL;
    }

    if (!(token_flags & TOKEN_NOOP)) {
        if (logfile)
            fprintf(logfile, "Expected NOOP token, got %d token instead\n",
                    token_flags);
        return -1;
    }

    *context = GSS_C_NO_CONTEXT;

    if (token_flags & TOKEN_CONTEXT_NEXT) {
        do {
            if (recv_token(s, &token_flags, &recv_tok) < 0)
                return -1;

            if (verbose && logfile) {
                fprintf(logfile, "Received token (size=%d): \n",
                        (int) recv_tok.length);
                print_token(&recv_tok);
            }

            maj_stat = gss_accept_sec_context(&acc_sec_min_stat, context,
                                              server_creds, &recv_tok,
                                              GSS_C_NO_CHANNEL_BINDINGS,
                                              &client, &doid, &send_tok,
                                              ret_flags,
                                              NULL,  /* time_rec */
                                              NULL); /* del_cred_handle */

            if (recv_tok.value) {
                free(recv_tok.value);
                recv_tok.value = NULL;
            }

            if (send_tok.length != 0) {
                if (verbose && logfile) {
                    fprintf(logfile,
                            "Sending accept_sec_context token (size=%d):\n",
                            (int) send_tok.length);
                    print_token(&send_tok);
                }
                if (send_token(s, TOKEN_CONTEXT, &send_tok) < 0) {
                    if (logfile)
                        fprintf(logfile, "failure sending token\n");
                    return -1;
                }

                (void) gss_release_buffer(&min_stat, &send_tok);
            }
            if (maj_stat != GSS_S_COMPLETE
                && maj_stat != GSS_S_CONTINUE_NEEDED) {
                display_status("accepting context", maj_stat,
                               acc_sec_min_stat);
                if (*context != GSS_C_NO_CONTEXT)
                    gss_delete_sec_context(&min_stat, context,
                                           GSS_C_NO_BUFFER);
                return -1;
            }

            if (verbose && logfile) {
                if (maj_stat == GSS_S_CONTINUE_NEEDED)
                    fprintf(logfile, "continue needed...\n");
                else
                    fprintf(logfile, "\n");
                fflush(logfile);
            }
        } while (maj_stat == GSS_S_CONTINUE_NEEDED);

        /* display the flags */
        display_ctx_flags(*ret_flags);

        if (verbose && logfile) {
            maj_stat = gss_oid_to_str(&min_stat, doid, &oid_name);
            if (maj_stat != GSS_S_COMPLETE) {
                display_status("converting oid->string", maj_stat, min_stat);
                return -1;
            }
            fprintf(logfile, "Accepted connection using mechanism OID %.*s.\n",
                    (int) oid_name.length, (char *) oid_name.value);
            (void) gss_release_buffer(&min_stat, &oid_name);
        }

        maj_stat = gss_display_name(&min_stat, client, client_name, &doid);
        if (maj_stat != GSS_S_COMPLETE) {
            display_status("displaying name", maj_stat, min_stat);
            return -1;
        }
        enumerateAttributes(&min_stat, client, TRUE);
        if (flags & FLAG_S4U)
            kerberosProtocolTransition(&min_stat, client, flags);
        maj_stat = gss_release_name(&min_stat, &client);
        if (maj_stat != GSS_S_COMPLETE) {
            display_status("releasing name", maj_stat, min_stat);
            return -1;
        }
    } else {
        client_name->length = *ret_flags = 0;

        if (logfile)
            printf("Accepted unauthenticated connection.\n");
    }

    return 0;
}

/*
 * Function: create_socket
 *
 * Purpose: Opens a listening TCP socket.
 *
 * Arguments:
 *
 *      port            (r) the port number on which to listen
 *
 * Returns: the listening socket file descriptor, or -1 on failure
 *
 * Effects:
 *
 * A listening socket on the specified port and created and returned.
 * On error, an error message is displayed and -1 is returned.
 */
static int
create_socket(u_short port)
{
    struct sockaddr_in saddr;
    int     s;
    int     on = 1;

    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = INADDR_ANY;

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("creating socket");
        return -1;
    }
    /* Let the socket be reused right away */
    (void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));
    if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
        perror("binding socket");
        (void) close(s);
        return -1;
    }
    if (listen(s, 5) < 0) {
        perror("listening on socket");
        (void) close(s);
        return -1;
    }
    return s;
}

static float
timeval_subtract(struct timeval *tv1, struct timeval *tv2)
{
    return ((tv1->tv_sec - tv2->tv_sec) +
            ((float) (tv1->tv_usec - tv2->tv_usec)) / 1000000);
}

/*
 * Yes, yes, this isn't the best place for doing this test.
 * DO NOT REMOVE THIS UNTIL A BETTER TEST HAS BEEN WRITTEN, THOUGH.
 *                                      -TYT
 */
static int
test_import_export_context(gss_ctx_id_t *context)
{
    OM_uint32 min_stat, maj_stat;
    gss_buffer_desc context_token, copied_token;
    struct timeval tm1, tm2;

    /*
     * Attempt to save and then restore the context.
     */
    gettimeofday(&tm1, (struct timezone *) 0);
    maj_stat = gss_export_sec_context(&min_stat, context, &context_token);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("exporting context", maj_stat, min_stat);
        return 1;
    }
    gettimeofday(&tm2, (struct timezone *) 0);
    if (verbose && logfile)
        fprintf(logfile, "Exported context: %d bytes, %7.4f seconds\n",
                (int) context_token.length, timeval_subtract(&tm2, &tm1));
    copied_token.length = context_token.length;
    copied_token.value = malloc(context_token.length);
    if (copied_token.value == 0) {
        if (logfile)
            fprintf(logfile,
                    "Couldn't allocate memory to copy context token.\n");
        return 1;
    }
    memcpy(copied_token.value, context_token.value, copied_token.length);
    maj_stat = gss_import_sec_context(&min_stat, &copied_token, context);
    if (maj_stat != GSS_S_COMPLETE) {
        display_status("importing context", maj_stat, min_stat);
        return 1;
    }
    free(copied_token.value);
    gettimeofday(&tm1, (struct timezone *) 0);
    if (verbose && logfile)
        fprintf(logfile, "Importing context: %7.4f seconds\n",
                timeval_subtract(&tm1, &tm2));
    (void) gss_release_buffer(&min_stat, &context_token);
    return 0;
}

/*
 * Function: sign_server
 *
 * Purpose: Performs the "sign" service.
 *
 * Arguments:
 *
 *      s               (r) a TCP socket on which a connection has been
 *                      accept()ed
 *      service_name    (r) the ASCII name of the GSS-API service to
 *                      establish a context as
 *      export          (r) whether to test context exporting
 *
 * Returns: -1 on error
 *
 * Effects:
 *
 * sign_server establishes a context, and performs a single sign request.
 *
 * A sign request is a single GSS-API sealed token.  The token is
 * unsealed and a signature block, produced with gss_sign, is returned
 * to the sender.  The context is the destroyed and the connection
 * closed.
 *
 * If any error occurs, -1 is returned.
 */
static int
sign_server(int s, gss_cred_id_t server_creds, int flags)
{
    gss_buffer_desc client_name, xmit_buf, msg_buf;
    gss_ctx_id_t context;
    OM_uint32 maj_stat, min_stat;
    int     i, conf_state;
    OM_uint32 ret_flags;
    char   *cp;
    int     token_flags;

    /* Establish a context with the client */
    if (server_establish_context(s, server_creds, flags, &context,
                                 &client_name, &ret_flags) < 0)
        return (-1);

    if (context == GSS_C_NO_CONTEXT) {
        printf("Accepted unauthenticated connection.\n");
    } else {
        printf("Accepted connection: \"%.*s\"\n",
               (int) client_name.length, (char *) client_name.value);
        (void) gss_release_buffer(&min_stat, &client_name);

        if (flags & FLAG_EXPORT) {
            for (i = 0; i < 3; i++)
                if (test_import_export_context(&context))
                    return -1;
        }
    }

    do {
        /* Receive the message token */
        if (recv_token(s, &token_flags, &xmit_buf) < 0)
            return (-1);

        if (token_flags & TOKEN_NOOP) {
            if (logfile)
                fprintf(logfile, "NOOP token\n");
            if (xmit_buf.value) {
                free(xmit_buf.value);
                xmit_buf.value = 0;
            }
            break;
        }

        if (verbose && logfile) {
            fprintf(logfile, "Message token (flags=%d):\n", token_flags);
            print_token(&xmit_buf);
        }

        if ((context == GSS_C_NO_CONTEXT) &&
            (token_flags & (TOKEN_WRAPPED | TOKEN_ENCRYPTED | TOKEN_SEND_MIC)))
        {
            if (logfile)
                fprintf(logfile,
                        "Unauthenticated client requested authenticated services!\n");
            if (xmit_buf.value) {
                free(xmit_buf.value);
                xmit_buf.value = 0;
            }
            return (-1);
        }

        if (token_flags & TOKEN_WRAPPED) {
            maj_stat = gss_unwrap(&min_stat, context, &xmit_buf, &msg_buf,
                                  &conf_state, (gss_qop_t *) NULL);
            if (maj_stat != GSS_S_COMPLETE) {
                display_status("unsealing message", maj_stat, min_stat);
                if (xmit_buf.value) {
                    free(xmit_buf.value);
                    xmit_buf.value = 0;
                }
                return (-1);
            } else if (!conf_state && (token_flags & TOKEN_ENCRYPTED)) {
                fprintf(stderr, "Warning!  Message not encrypted.\n");
            }

            if (xmit_buf.value) {
                free(xmit_buf.value);
                xmit_buf.value = 0;
            }
        } else {
            msg_buf = xmit_buf;
        }

        if (logfile) {
            fprintf(logfile, "Received message: ");
            cp = msg_buf.value;
            if ((isprint((int) cp[0]) || isspace((int) cp[0])) &&
                (isprint((int) cp[1]) || isspace((int) cp[1]))) {
                fprintf(logfile, "\"%.*s\"\n", (int) msg_buf.length,
                        (char *) msg_buf.value);
            } else {
                fprintf(logfile, "\n");
                print_token(&msg_buf);
            }
        }

        if (token_flags & TOKEN_SEND_MIC) {
            /* Produce a signature block for the message */
            maj_stat = gss_get_mic(&min_stat, context, GSS_C_QOP_DEFAULT,
                                   &msg_buf, &xmit_buf);
            if (maj_stat != GSS_S_COMPLETE) {
                display_status("signing message", maj_stat, min_stat);
                return (-1);
            }

            if (msg_buf.value) {
                free(msg_buf.value);
                msg_buf.value = 0;
            }

            /* Send the signature block to the client */
            if (send_token(s, TOKEN_MIC, &xmit_buf) < 0)
                return (-1);

            if (xmit_buf.value) {
                free(xmit_buf.value);
                xmit_buf.value = 0;
            }
        } else {
            if (msg_buf.value) {
                free(msg_buf.value);
                msg_buf.value = 0;
            }
            if (send_token(s, TOKEN_NOOP, empty_token) < 0)
                return (-1);
        }
    } while (1 /* loop will break if NOOP received */ );

    if (context != GSS_C_NO_CONTEXT) {
        /* Delete context */
        maj_stat = gss_delete_sec_context(&min_stat, &context, NULL);
        if (maj_stat != GSS_S_COMPLETE) {
            display_status("deleting context", maj_stat, min_stat);
            return (-1);
        }
    }

    if (logfile)
        fflush(logfile);

    return (0);
}

static int max_threads = 1;

#ifdef _WIN32
static  thread_count = 0;
static HANDLE hMutex = NULL;
static HANDLE hEvent = NULL;

void
InitHandles(void)
{
    hMutex = CreateMutex(NULL, FALSE, NULL);
    hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
}

void
CleanupHandles(void)
{
    CloseHandle(hMutex);
    CloseHandle(hEvent);
}

BOOL
WaitAndIncrementThreadCounter(void)
{
    for (;;) {
        if (WaitForSingleObject(hMutex, INFINITE) == WAIT_OBJECT_0) {
            if (thread_count < max_threads) {
                thread_count++;
                ReleaseMutex(hMutex);
                return TRUE;
            } else {
                ReleaseMutex(hMutex);

                if (WaitForSingleObject(hEvent, INFINITE) == WAIT_OBJECT_0) {
                    continue;
                } else {
                    return FALSE;
                }
            }
        } else {
            return FALSE;
        }
    }
}

BOOL
DecrementAndSignalThreadCounter(void)
{
    if (WaitForSingleObject(hMutex, INFINITE) == WAIT_OBJECT_0) {
        if (thread_count == max_threads)
            ResetEvent(hEvent);
        thread_count--;
        ReleaseMutex(hMutex);
        return TRUE;
    } else {
        return FALSE;
    }
}
#endif

struct _work_plan
{
    int     s;
    gss_cred_id_t server_creds;
    int     flags;
};

static void
worker_bee(void *param)
{
    struct _work_plan *work = (struct _work_plan *) param;

    /* this return value is not checked, because there's
     * not really anything to do if it fails
     */
    sign_server(work->s, work->server_creds, work->flags);
    closesocket(work->s);
    free(work);

#ifdef _WIN32
    if (max_threads > 1)
        DecrementAndSignalThreadCounter();
#endif
}

int
main(int argc, char **argv)
{
    char   *service_name;
    gss_cred_id_t server_creds;
    OM_uint32 min_stat;
    u_short port = 4444;
    int     once = 0;
    int     do_inetd = 0;
    int     flags = 0;

    logfile = stdout;
    display_file = stdout;
    argc--;
    argv++;
    while (argc) {
        if (strcmp(*argv, "-port") == 0) {
            argc--;
            argv++;
            if (!argc)
                usage();
            port = atoi(*argv);
        }
#ifdef _WIN32
        else if (strcmp(*argv, "-threads") == 0) {
            argc--;
            argv++;
            if (!argc)
                usage();
            max_threads = atoi(*argv);
        }
#endif
        else if (strcmp(*argv, "-verbose") == 0) {
            verbose = 1;
        } else if (strcmp(*argv, "-once") == 0) {
            once = 1;
        } else if (strcmp(*argv, "-inetd") == 0) {
            do_inetd = 1;
        } else if (strcmp(*argv, "-export") == 0) {
            flags |= FLAG_EXPORT;
        } else if (strcmp(*argv, "-s4u") == 0) {
            flags |= FLAG_S4U;
        } else if (strcmp(*argv, "-anon") == 0) {
            flags |= FLAG_ANON;
        } else if (strcmp(*argv, "-logfile") == 0) {
            argc--;
            argv++;
            if (!argc)
                usage();
            /* Gross hack, but it makes it unnecessary to add an
             * extra argument to disable logging, and makes the code
             * more efficient because it doesn't actually write data
             * to /dev/null. */
            if (!strcmp(*argv, "/dev/null")) {
                logfile = display_file = NULL;
            } else {
                logfile = fopen(*argv, "a");
                display_file = logfile;
                if (!logfile) {
                    perror(*argv);
                    exit(1);
                }
            }
        } else if (strcmp(*argv, "-keytab") == 0) {
            argc--;
            argv++;
            if (!argc)
                usage();
            if (krb5_gss_register_acceptor_identity(*argv)) {
                fprintf(stderr, "failed to register keytab\n");
                exit(1);
            }
        } else
            break;
        argc--;
        argv++;
    }
    if (argc != 1)
        usage();

    if ((*argv)[0] == '-')
        usage();

#ifdef _WIN32
    if (max_threads < 1) {
        fprintf(stderr, "warning: there must be at least one thread\n");
        max_threads = 1;
    }

    if (max_threads > 1 && do_inetd)
        fprintf(stderr,
                "warning: one thread may be used in conjunction with inetd\n");

    InitHandles();
#endif

    service_name = *argv;

    if (server_acquire_creds(service_name, &server_creds) < 0)
        return -1;

    if (do_inetd) {
        close(1);
        close(2);

        sign_server(0, server_creds, flags);
        close(0);
    } else {
        int     stmp;

        if ((stmp = create_socket(port)) >= 0) {
            if (listen(stmp, max_threads == 1 ? 0 : max_threads) < 0)
                perror("listening on socket");
            fprintf(stderr, "starting...\n");

            do {
                struct _work_plan *work = malloc(sizeof(struct _work_plan));

                if (work == NULL) {
                    fprintf(stderr, "fatal error: out of memory");
                    break;
                }

                /* Accept a TCP connection */
                if ((work->s = accept(stmp, NULL, 0)) < 0) {
                    perror("accepting connection");
                    continue;
                }

                work->server_creds = server_creds;
                work->flags = flags;

                if (max_threads == 1) {
                    worker_bee((void *) work);
                }
#ifdef _WIN32
                else {
                    if (WaitAndIncrementThreadCounter()) {
                        uintptr_t handle =
                            _beginthread(worker_bee, 0, (void *) work);
                        if (handle == (uintptr_t) - 1) {
                            closesocket(work->s);
                            free(work);
                        }
                    } else {
                        fprintf(stderr,
                                "fatal error incrementing thread counter");
                        closesocket(work->s);
                        free(work);
                        break;
                    }
                }
#endif
            } while (!once);

            closesocket(stmp);
        }
    }

    (void) gss_release_cred(&min_stat, &server_creds);

#ifdef _WIN32
    CleanupHandles();
#endif

    return 0;
}

static void
dumpAttribute(OM_uint32 *minor,
              gss_name_t name,
              gss_buffer_t attribute,
              int noisy)
{
    OM_uint32 major, tmp;
    gss_buffer_desc value;
    gss_buffer_desc display_value;
    int authenticated = 0;
    int complete = 0;
    int more = -1;
    unsigned int i;

    while (more != 0) {
        value.value = NULL;
        display_value.value = NULL;

        major = gss_get_name_attribute(minor, name, attribute, &authenticated,
                                       &complete, &value, &display_value,
                                       &more);
        if (GSS_ERROR(major)) {
            display_status("gss_get_name_attribute", major, *minor);
            break;
        }

        fprintf(logfile, "Attribute %.*s %s %s\n\n%.*s\n",
               (int)attribute->length, (char *)attribute->value,
               authenticated ? "Authenticated" : "",
               complete ? "Complete" : "",
               (int)display_value.length, (char *)display_value.value);

        if (noisy) {
            for (i = 0; i < value.length; i++) {
                if ((i % 32) == 0)
                    fprintf(logfile, "\n");
                fprintf(logfile, "%02x", ((char *)value.value)[i] & 0xFF);
            }
            fprintf(logfile, "\n\n");
        }

        gss_release_buffer(&tmp, &value);
        gss_release_buffer(&tmp, &display_value);
    }
}

static OM_uint32
enumerateAttributes(OM_uint32 *minor,
                    gss_name_t name,
                    int noisy)
{
    OM_uint32 major, tmp;
    int name_is_MN;
    gss_OID mech = GSS_C_NO_OID;
    gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
    unsigned int i;

    major = gss_inquire_name(minor, name, &name_is_MN, &mech, &attrs);
    if (GSS_ERROR(major)) {
        display_status("gss_inquire_name", major, *minor);
        return major;
    }

    if (attrs != GSS_C_NO_BUFFER_SET) {
        for (i = 0; i < attrs->count; i++)
            dumpAttribute(minor, name, &attrs->elements[i], noisy);
    }

    gss_release_oid(&tmp, &mech);
    gss_release_buffer_set(&tmp, &attrs);

    return major;
}

static OM_uint32
displayCanonName(OM_uint32 *minor, gss_name_t name, char *tag)
{
    gss_name_t canon;
    OM_uint32 major, tmp_minor;
    gss_buffer_desc buf;

    major = gss_canonicalize_name(minor, name,
                                  (gss_OID)gss_mech_krb5, &canon);
    if (GSS_ERROR(major)) {
        display_status("gss_canonicalize_name", major, *minor);
        return major;
    }

    major = gss_display_name(minor, canon, &buf, NULL);
    if (GSS_ERROR(major)) {
        display_status("gss_display_name", major, *minor);
        gss_release_name(&tmp_minor, &canon);
        return major;
    }

    fprintf(logfile, "%s:\t%s\n", tag, (char *)buf.value);

    gss_release_buffer(&tmp_minor, &buf);
    gss_release_name(&tmp_minor, &canon);

    return GSS_S_COMPLETE;
}

static OM_uint32
displayOID(OM_uint32 *minor, gss_OID oid, char *tag)
{
    OM_uint32 major, tmp_minor;
    gss_buffer_desc buf;

    major = gss_oid_to_str(minor, oid, &buf);
    if (GSS_ERROR(major)) {
        display_status("gss_oid_to_str", major, *minor);
        return major;
    }

    fprintf(logfile, "%s:\t%s\n", tag, (char *)buf.value);

    gss_release_buffer(&tmp_minor, &buf);

    return GSS_S_COMPLETE;
}

static OM_uint32
initAcceptSecContext(OM_uint32 *minor,
                     gss_cred_id_t claimant_cred_handle,
                     gss_cred_id_t verifier_cred_handle,
                     gss_cred_id_t *deleg_cred_handle)
{
    OM_uint32 major, tmp_minor;
    gss_buffer_desc token, tmp;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;
    gss_name_t source_name = GSS_C_NO_NAME;
    gss_name_t target_name = GSS_C_NO_NAME;
    OM_uint32 time_rec;
    gss_OID mech = GSS_C_NO_OID;

    token.value = NULL;
    token.length = 0;

    tmp.value = NULL;
    tmp.length = 0;

    *deleg_cred_handle = GSS_C_NO_CREDENTIAL;

    major = gss_inquire_cred(minor, verifier_cred_handle,
                             &target_name, NULL, NULL, NULL);
    if (GSS_ERROR(major)) {
        display_status("gss_inquire_cred", major, *minor);
        return major;
    }

    displayCanonName(minor, target_name, "Target name");

    mech = (gss_OID)gss_mech_krb5;
    displayOID(minor, mech, "Target mech");

    major = gss_init_sec_context(minor,
                                 claimant_cred_handle,
                                 &initiator_context,
                                 target_name,
                                 mech,
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE,
                                 GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER,
                                 NULL,
                                 &token,
                                 NULL,
                                 &time_rec);

    if (target_name != GSS_C_NO_NAME)
        (void) gss_release_name(&tmp_minor, &target_name);

    if (GSS_ERROR(major)) {
        display_status("gss_init_sec_context", major, *minor);
        return major;
    }

    (void) gss_delete_sec_context(minor, &initiator_context, NULL);
    mech = GSS_C_NO_OID;

    major = gss_accept_sec_context(minor,
                                   &acceptor_context,
                                   verifier_cred_handle,
                                   &token,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   &source_name,
                                   &mech,
                                   &tmp,
                                   NULL,
                                   &time_rec,
                                   deleg_cred_handle);

    if (GSS_ERROR(major))
        display_status("gss_accept_sec_context", major, *minor);
    else {
        displayCanonName(minor, source_name, "Source name");
        displayOID(minor, mech, "Source mech");
        enumerateAttributes(minor, source_name, 1);
    }

    (void) gss_release_name(&tmp_minor, &source_name);
    (void) gss_delete_sec_context(&tmp_minor, &acceptor_context, NULL);
    (void) gss_release_buffer(&tmp_minor, &token);
    (void) gss_release_buffer(&tmp_minor, &tmp);
    (void) gss_release_oid(&tmp_minor, &mech);

    return major;
}

static OM_uint32
constrainedDelegate(OM_uint32 *minor,
                    gss_OID_set desired_mechs,
                    gss_name_t target,
                    gss_cred_id_t delegated_cred_handle,
                    gss_cred_id_t verifier_cred_handle)
{
    OM_uint32 major, tmp_minor;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_name_t cred_name = GSS_C_NO_NAME;
    OM_uint32 time_rec, lifetime;
    gss_cred_usage_t credUsage;
    gss_buffer_desc token;
    gss_OID_set mechs;

    fprintf(logfile, "Constrained delegation tests follow\n");
    fprintf(logfile, "-----------------------------------\n\n");

    if (gss_inquire_cred(minor, verifier_cred_handle, &cred_name,
                         &lifetime, &credUsage, NULL) == GSS_S_COMPLETE) {
        displayCanonName(minor, cred_name, "Proxy name");
        gss_release_name(&tmp_minor, &cred_name);
    }
    displayCanonName(minor, target, "Target name");
    if (gss_inquire_cred(minor, delegated_cred_handle, &cred_name,
                         &lifetime, &credUsage, &mechs) == GSS_S_COMPLETE) {
        displayCanonName(minor, cred_name, "Delegated name");
        displayOID(minor, &mechs->elements[0], "Delegated mech");
        gss_release_name(&tmp_minor, &cred_name);
    }

    fprintf(logfile, "\n");

    major = gss_init_sec_context(minor,
                                 delegated_cred_handle,
                                 &initiator_context,
                                 target,
                                 mechs ? &mechs->elements[0] :
                                 (gss_OID)gss_mech_krb5,
                                 GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE,
                                 GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER,
                                 NULL,
                                 &token,
                                 NULL,
                                 &time_rec);
    if (GSS_ERROR(major))
        display_status("gss_init_sec_context", major, *minor);

    (void) gss_release_buffer(&tmp_minor, &token);
    (void) gss_delete_sec_context(&tmp_minor, &initiator_context, NULL);
    (void) gss_release_oid_set(&tmp_minor, &mechs);

    return major;
}

static OM_uint32
kerberosProtocolTransition(OM_uint32 *minor,
                           gss_name_t authenticatedInitiator,
                           int flags)
{
    OM_uint32 major, tmpMinor;
    gss_cred_id_t impersonator_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t user_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t delegated_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_name_t anonName = GSS_C_NO_NAME;
    gss_name_t user = GSS_C_NO_NAME;
    gss_name_t target = GSS_C_NO_NAME;
    gss_OID_set_desc mechs;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc assertion = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc assertionAttr = GSS_C_EMPTY_BUFFER;
    int authenticated = 0, complete;

    mechs.elements = (gss_OID)gss_mech_krb5;
    mechs.count = 1;

    /* get default cred */
    major = gss_acquire_cred(minor,
                             GSS_C_NO_NAME,
                             GSS_C_INDEFINITE,
                             &mechs,
                             GSS_C_BOTH,
                             &impersonator_cred_handle,
                             &actual_mechs,
                             NULL);
    if (GSS_ERROR(major)) {
        display_status("gss_acquire_cred", major, *minor);
        goto out;
    }

    (void) gss_release_oid_set(minor, &actual_mechs);

    fprintf(logfile, "Protocol transition tests follow\n");
    fprintf(logfile, "-----------------------------------\n\n");

    assertionAttr.value = "urn:ietf:params:gss-eap:saml-aaa-assertion";
    assertionAttr.length = strlen((char *)assertionAttr.value);

    if (flags & FLAG_ANON) {
        int more = -1;
        gss_buffer_desc anonNameBuf;
        gss_buffer_desc tmp = GSS_C_EMPTY_BUFFER;

        (void) gss_get_name_attribute(minor, authenticatedInitiator,
                                      &assertionAttr, &authenticated, &complete,
                                      &assertion, &tmp, &more);
        gss_release_buffer(&tmpMinor, &tmp);

        anonNameBuf.value = KRB5_WELLKNOWN_NAMESTR "/" KRB5_ANONYMOUS_PRINCSTR "@" KRB5_ANONYMOUS_REALMSTR;
        anonNameBuf.length = strlen((char *)anonNameBuf.value);

        major = gss_import_name(minor, &anonNameBuf,
                                GSS_C_NT_USER_NAME, &anonName);
        if (GSS_ERROR(major)) {
            display_status("gss_import_name", major, *minor);
            goto out;
        }
    }

    major = gss_canonicalize_name(minor,
                                  (flags & FLAG_ANON) ? anonName : authenticatedInitiator,
                                  (gss_OID)gss_mech_krb5, &user);
    if (GSS_ERROR(major)) {
        display_status("gss_canonicalize_name", major, *minor);
        goto out;
    }

    if ((flags & FLAG_ANON) && authenticated && assertion.length != 0) {
        major = gss_set_name_attribute(minor, user, complete,
                                       &assertionAttr, &assertion);
        if (GSS_ERROR(major)) {
            display_status("gss_set_name_attribute", major, *minor);
            goto out;
        }
    }

    /* get S4U2Self cred */
    major = gss_acquire_cred_impersonate_name(minor,
                                              impersonator_cred_handle,
                                              user,
                                              GSS_C_INDEFINITE,
                                              &mechs,
                                              GSS_C_INITIATE,
                                              &user_cred_handle,
                                              &actual_mechs,
                                              NULL);
    if (GSS_ERROR(major)) {
        display_status("gss_acquire_cred_impersonate_name", major, *minor);
        goto out;
    }

    major = initAcceptSecContext(minor,
                                 user_cred_handle,
                                 impersonator_cred_handle,
                                 &delegated_cred_handle);
    if (GSS_ERROR(major))
        goto out;

    fprintf(logfile, "\n");

    if (target != GSS_C_NO_NAME &&
        delegated_cred_handle != GSS_C_NO_CREDENTIAL) {
        major = constrainedDelegate(minor, &mechs, target,
                                    delegated_cred_handle,
                                    impersonator_cred_handle);
    } else if (target != GSS_C_NO_NAME) {
        fprintf(stderr, "Warning: no delegated credentials handle returned\n\n");
        fprintf(stderr, "Verify:\n\n");
        fprintf(stderr, " - The TGT for the impersonating service is forwardable\n");
        fprintf(stderr, " - The T2A4D flag set on the impersonating service's UAC\n");
        fprintf(stderr, " - The user is not marked sensitive and cannot be delegated\n");
        fprintf(stderr, "\n");
    }

out:
    (void) gss_release_name(&tmpMinor, &user);
    (void) gss_release_name(&tmpMinor, &target);
    (void) gss_release_name(&tmpMinor, &anonName);
    (void) gss_release_cred(&tmpMinor, &delegated_cred_handle);
    (void) gss_release_cred(&tmpMinor, &impersonator_cred_handle);
    (void) gss_release_cred(&tmpMinor, &user_cred_handle);
    (void) gss_release_oid_set(&tmpMinor, &actual_mechs);
    (void) gss_release_buffer(&tmpMinor, &assertion);

    return GSS_ERROR(major) ? 1 : 0;
}
